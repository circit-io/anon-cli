//! Font encoding resolution for visible-text redaction.
//!
//! lopdf 0.36's `Dictionary::get_font_encoding` has three failure modes that
//! leak or quarantine real documents:
//! - dictionary `/Encoding` with a `/ToUnicode` CMap its parser rejects ->
//!   hard error ("failed parsing ToUnicode CMap") -> quarantine;
//! - unknown `/Encoding` name -> `SimpleEncoding`, which errors at decode time;
//! - dictionary `/Encoding` without usable `/ToUnicode` -> silent fallback to
//!   StandardEncoding, which garbles decoded text so identifiers never match
//!   (zero redactions / residual identifiers).
//!
//! This module resolves every font into an owned map instead, so redaction
//! either decodes correctly or fails closed into quarantine. The verifier is
//! never involved.
//!
//! Fallback policy: a present-but-unparseable `/ToUnicode` falls back to the
//! `/Encoding` resolution (mirroring what text extractors do); a present
//! `/ToUnicode` with no usable `/Encoding` at all is an error. Either way,
//! if the resolved decoding ends up applying zero redactions to a
//! text-bearing document, the caller quarantines — divergence is never
//! silent.

use lopdf::{Dictionary, Document, Object};

pub struct UnicodeCMap {
    // (code_len, range_lo, range_hi, target)
    ranges: Vec<(u8, u32, u32, RangeTarget)>,
}

#[derive(Debug)]
pub(crate) enum RangeTarget {
    /// decoded unit = code.wrapping_add(offset) as u16
    Offset(u32),
    /// UTF-16BE units; the last unit increments with the code in the range
    Hex(Vec<u16>),
    /// one UTF-16BE unit sequence per code in the range
    Array(Vec<Vec<u16>>),
}

impl Default for UnicodeCMap {
    fn default() -> Self {
        Self::new()
    }
}

impl UnicodeCMap {
    pub fn new() -> Self {
        UnicodeCMap { ranges: Vec::new() }
    }

    pub(crate) fn put_char(&mut self, code: u32, code_len: u8, dst: Vec<u16>) {
        let target = if dst.len() == 1 {
            RangeTarget::Offset(u32::wrapping_sub(dst[0] as u32, code))
        } else {
            RangeTarget::Hex(dst)
        };
        self.put(code, code, code_len, target);
    }

    pub(crate) fn put(&mut self, lo: u32, hi: u32, code_len: u8, target: RangeTarget) {
        // cap width so decode-side `(code - lo) as u16` truncation and the
        // encode-side full-width arithmetic in code_for_char cannot diverge
        if code_len == 0 || code_len > 4 || hi < lo || hi - lo > 0xFFFF {
            return;
        }
        self.ranges.push((code_len, lo, hi, target));
    }

    pub fn get(&self, code: u32, code_len: u8) -> Option<Vec<u16>> {
        self.ranges
            .iter()
            .find(|(l, lo, hi, _)| *l == code_len && *lo <= code && code <= *hi)
            .map(|(_, lo, _, t)| match t {
                RangeTarget::Offset(off) => vec![code.wrapping_add(*off) as u16],
                RangeTarget::Hex(h) => {
                    let mut v = h.clone();
                    if let Some(last) = v.last_mut() {
                        *last = last.wrapping_add((code - lo) as u16);
                    }
                    v
                }
                RangeTarget::Array(a) => a
                    .get((code - lo) as usize)
                    .cloned()
                    .unwrap_or_else(|| vec![0xFFFD]),
            })
    }

    /// Decode raw string bytes to text, mirroring lopdf's greedy
    /// shortest-code-first matching over 1..=4 byte codes.
    pub fn decode(&self, bytes: &[u8]) -> String {
        let mut units: Vec<u16> = Vec::new();
        let mut code = 0u32;
        let mut len = 0u8;
        for &b in bytes {
            if len == 4 {
                units.push(0xFFFD);
                code = 0;
                len = 0;
            }
            len += 1;
            code = code * 256 + b as u32;
            if let Some(v) = self.get(code, len) {
                units.extend(v);
                code = 0;
                len = 0;
            }
        }
        if len > 0 {
            units.extend(self.get(code, len).unwrap_or_else(|| vec![0xFFFD]));
        }
        String::from_utf16_lossy(&units)
    }

    /// Reverse lookup: encode one char to its source-code bytes, if the map
    /// can represent it.
    pub fn code_for_char(&self, ch: char) -> Option<Vec<u8>> {
        let mut buf = [0u16; 2];
        let units: Vec<u16> = ch.encode_utf16(&mut buf).to_vec();
        let target = units[0] as u32;
        for (len, lo, hi, t) in &self.ranges {
            let code = match t {
                RangeTarget::Offset(off) => {
                    if units.len() != 1 {
                        continue;
                    }
                    let c = u32::wrapping_sub(target, *off);
                    if *lo <= c && c <= *hi {
                        c
                    } else {
                        continue;
                    }
                }
                RangeTarget::Hex(h) => {
                    if h.len() == 1 && units.len() == 1 {
                        let c = *lo as i64 + (target as i64 - h[0] as i64);
                        if c >= *lo as i64 && c <= *hi as i64 {
                            c as u32
                        } else {
                            continue;
                        }
                    } else if h == &units {
                        *lo
                    } else {
                        continue;
                    }
                }
                RangeTarget::Array(a) => match a.iter().position(|u| *u == units) {
                    Some(idx) => {
                        let c = *lo + idx as u32;
                        if c > *hi {
                            continue;
                        }
                        c
                    }
                    None => continue,
                },
            };
            return Some(code.to_be_bytes()[(4 - *len as usize)..].to_vec());
        }
        None
    }
}

/// Resolve a font dictionary to an owned decode/encode map.
///
/// A `/ToUnicode` CMap is authoritative whenever present; `/Encoding`
/// dictionaries are resolved via BaseEncoding + Differences; anything
/// unresolvable is an error so the caller quarantines (fail-closed).
pub fn resolve_font_encoding(doc: &Document, font: &Dictionary) -> Result<UnicodeCMap, lopdf::Error> {
    if let Ok(obj) = font.get_deref(b"ToUnicode", doc) {
        if let Ok(stream) = obj.as_stream() {
            if let Ok(content) = stream.get_plain_content() {
                if let Ok(cmap) = parse_tounicode_cmap(&content) {
                    return Ok(cmap);
                }
            }
        }
    }
    match font.get_deref(b"Encoding", doc) {
        Ok(Object::Dictionary(enc)) => encoding_from_encoding_dict(enc),
        Ok(Object::Name(name)) => encoding_from_name(name),
        Ok(_) => Err(lopdf::Error::Syntax("unsupported /Encoding entry".into())),
        Err(_) => {
            if font.get_deref(b"ToUnicode", doc).is_ok() {
                return Err(lopdf::Error::Syntax(
                    "ToUnicode CMap present but unparseable; refusing silent fallback".into(),
                ));
            }
            // Simple fonts without /Encoding default to StandardEncoding (PDF spec 9.6.4).
            Ok(cmap_from_table(&STANDARD_ENCODING))
        }
    }
}

fn encoding_from_name(name: &[u8]) -> Result<UnicodeCMap, lopdf::Error> {
    match name {
        b"StandardEncoding" => Ok(cmap_from_table(&STANDARD_ENCODING)),
        b"MacRomanEncoding" => Ok(cmap_from_table(&MAC_ROMAN_ENCODING)),
        b"MacExpertEncoding" => Ok(cmap_from_table(&MAC_EXPERT_ENCODING)),
        b"WinAnsiEncoding" => Ok(cmap_from_table(&WIN_ANSI_ENCODING)),
        b"PDFDocEncoding" => Ok(cmap_from_table(&PDF_DOC_ENCODING)),
        b"UniGB-UCS2-H" | b"UniGB-UTF16-H" => {
            let mut m = UnicodeCMap::new();
            m.put(0, 0xFFFF, 2, RangeTarget::Offset(0));
            Ok(m)
        }
        b"Identity-H" | b"Identity-V" => Err(lopdf::Error::Syntax(
            "Identity encoding without a parseable ToUnicode CMap".into(),
        )),
        other => Err(lopdf::Error::Syntax(format!(
            "unsupported /Encoding name /{}",
            String::from_utf8_lossy(other)
        ))),
    }
}

fn encoding_from_encoding_dict(dict: &Dictionary) -> Result<UnicodeCMap, lopdf::Error> {
    let base = dict.get(b"BaseEncoding").and_then(Object::as_name).map_err(|_| {
        lopdf::Error::Syntax(
            "dictionary /Encoding without BaseEncoding and without a usable ToUnicode CMap".into(),
        )
    })?;
    let table = base_encoding_table(base).ok_or_else(|| {
        lopdf::Error::Syntax(format!(
            "unsupported BaseEncoding /{}",
            String::from_utf8_lossy(base)
        ))
    })?;
    let mut cmap = cmap_from_table(table);
    if let Ok(Object::Array(items)) = dict.get(b"Differences") {
        let mut code: u32 = 0;
        for item in items {
            match item {
                Object::Integer(n) => code = (*n).clamp(0, 255) as u32,
                Object::Name(glyph) => {
                    let u = glyph_name_to_unicode(glyph).ok_or_else(|| {
                        lopdf::Error::Syntax(format!(
                            "unknown glyph name /{} in /Differences",
                            String::from_utf8_lossy(glyph)
                        ))
                    })?;
                    cmap.put_char(code, 1, vec![u]);
                    code = code.saturating_add(1);
                }
                _ => {}
            }
        }
    }
    Ok(cmap)
}

fn cmap_from_table(table: &'static [Option<u16>; 256]) -> UnicodeCMap {
    let mut cmap = UnicodeCMap::new();
    for (code, entry) in table.iter().enumerate() {
        if let Some(u) = entry {
            cmap.put_char(code as u32, 1, vec![*u]);
        }
    }
    cmap
}

fn base_encoding_table(name: &[u8]) -> Option<&'static [Option<u16>; 256]> {
    match name {
        b"StandardEncoding" => Some(&STANDARD_ENCODING),
        b"MacRomanEncoding" => Some(&MAC_ROMAN_ENCODING),
        b"MacExpertEncoding" => Some(&MAC_EXPERT_ENCODING),
        b"WinAnsiEncoding" => Some(&WIN_ANSI_ENCODING),
        b"PDFDocEncoding" => Some(&PDF_DOC_ENCODING),
        _ => None,
    }
}

/// Minimal Adobe glyph list subset for /Differences entries: single-char
/// names, digit/letter words, common punctuation, and uniXXXX / uXXXX forms.
fn glyph_name_to_unicode(name: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(name).ok()?;
    if s.chars().count() == 1 {
        return s.chars().next().map(|c| c as u16);
    }
    let lower = s.to_ascii_lowercase();
    let ch: u32 = match lower.as_str() {
        "space" => 0x20,
        "exclam" => 0x21,
        "quotedbl" => 0x22,
        "numbersign" => 0x23,
        "dollar" => 0x24,
        "percent" => 0x25,
        "ampersand" => 0x26,
        "quotesingle" => 0x27,
        "parenleft" => 0x28,
        "parenright" => 0x29,
        "asterisk" => 0x2A,
        "plus" => 0x2B,
        "comma" => 0x2C,
        "hyphen" | "minus" => 0x2D,
        "period" => 0x2E,
        "slash" => 0x2F,
        "zero" => 0x30,
        "one" => 0x31,
        "two" => 0x32,
        "three" => 0x33,
        "four" => 0x34,
        "five" => 0x35,
        "six" => 0x36,
        "seven" => 0x37,
        "eight" => 0x38,
        "nine" => 0x39,
        "colon" => 0x3A,
        "semicolon" => 0x3B,
        "less" => 0x3C,
        "equal" => 0x3D,
        "greater" => 0x3E,
        "question" => 0x3F,
        "at" => 0x40,
        "bracketleft" => 0x5B,
        "backslash" => 0x5C,
        "bracketright" => 0x5D,
        "asciicircum" => 0x5E,
        "underscore" => 0x5F,
        "grave" => 0x60,
        "braceleft" => 0x7B,
        "bar" => 0x7C,
        "braceright" => 0x7D,
        "asciitilde" => 0x7E,
        "periodcentered" => 0x00B7,
        "endash" => 0x2013,
        "emdash" => 0x2014,
        "bullet" => 0x2022,
        _ => {
            if let Some(hex) = lower.strip_prefix("uni") {
                return u16::from_str_radix(hex, 16).ok().filter(|_| hex.len() == 4);
            }
            if let Some(hex) = lower.strip_prefix('u') {
                if hex.len() == 4 {
                    return u16::from_str_radix(hex, 16).ok();
                }
                if hex.len() == 6 {
                    return u32::from_str_radix(hex, 16)
                        .ok()
                        .and_then(|v| u16::try_from(v).ok());
                }
            }
            return None;
        }
    };
    Some(ch as u16)
}

enum Tok {
    Hex(Vec<u8>),
    Open,
    Close,
    Word(String),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c.is_ascii_whitespace() || matches!(c, b')' | b'/' | b'{' | b'}' | b'>') {
            i += 1;
            continue;
        }
        match c {
            b'(' => {
                // literal string: consume to the matching ')' (nested,
                // backslash-escaped) and emit no tokens, so a crafted CMap
                // cannot inject mappings via text inside (...)
                let mut depth = 1usize;
                i += 1;
                while i < b.len() && depth > 0 {
                    match b[i] {
                        b'\\' => {
                            i += 2;
                            continue;
                        }
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'<' => {
                let mut hex = Vec::new();
                i += 1;
                while i < b.len() && b[i] != b'>' {
                    if !b[i].is_ascii_whitespace() {
                        hex.push(b[i]);
                    }
                    i += 1;
                }
                if i >= b.len() {
                    break;
                }
                i += 1;
                out.push(Tok::Hex(hex));
            }
            b'[' => {
                out.push(Tok::Open);
                i += 1;
            }
            b']' => {
                out.push(Tok::Close);
                i += 1;
            }
            _ => {
                let start = i;
                while i < b.len()
                    && !b[i].is_ascii_whitespace()
                    && !matches!(b[i], b'<' | b'>' | b'[' | b']' | b'%' | b'(' | b')' | b'/' | b'{' | b'}')
                {
                    i += 1;
                }
                if i == start {
                    i += 1;
                    continue;
                }
                out.push(Tok::Word(s[start..i].to_string()));
            }
        }
    }
    out
}

fn hex_to_code(hex: &[u8]) -> Result<(u32, u8), String> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 8 {
        return Err(format!("bad hex string <{}>", String::from_utf8_lossy(hex)));
    }
    let mut code = 0u32;
    for &h in hex {
        let v = (h as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex digit in <{}>", String::from_utf8_lossy(hex)))?;
        code = code * 16 + v;
    }
    Ok((code, (hex.len() / 2) as u8))
}

fn hex_to_u16s(hex: &[u8]) -> Result<Vec<u16>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string <{}>", String::from_utf8_lossy(hex)));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for p in hex.chunks(2) {
        let s = std::str::from_utf8(p).map_err(|e| e.to_string())?;
        bytes.push(u8::from_str_radix(s, 16).map_err(|e| e.to_string())?);
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(format!(
            "odd byte count in UTF-16BE hex string <{}>",
            String::from_utf8_lossy(hex)
        ));
    }
    Ok(bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect())
}

/// Tolerant ToUnicode CMap parser: scans for beginbfchar/beginbfrange blocks
/// and ignores everything else (codespacerange, def lines, comments).
pub fn parse_tounicode_cmap(content: &[u8]) -> Result<UnicodeCMap, String> {
    let text = String::from_utf8_lossy(content);
    let toks = tokenize(&text);
    let mut cmap = UnicodeCMap::new();
    let mut mappings = 0usize;
    let mut i = 0usize;
    while i < toks.len() {
        match &toks[i] {
            Tok::Word(w) if w == "beginbfchar" => {
                i += 1;
                loop {
                    match toks.get(i) {
                        Some(Tok::Word(w)) if w == "endbfchar" => {
                            i += 1;
                            break;
                        }
                        Some(Tok::Hex(src)) => {
                            let (code, len) = hex_to_code(src)?;
                            i += 1;
                            match toks.get(i) {
                                Some(Tok::Hex(dst)) => {
                                    let units = hex_to_u16s(dst)?;
                                    cmap.put_char(code, len, units);
                                    mappings += 1;
                                    i += 1;
                                }
                                _ => return Err("bfchar: expected destination hex string".into()),
                            }
                        }
                        _ => return Err("bfchar: expected source hex string".into()),
                    }
                }
            }
            Tok::Word(w) if w == "beginbfrange" => {
                i += 1;
                loop {
                    match toks.get(i) {
                        Some(Tok::Word(w)) if w == "endbfrange" => {
                            i += 1;
                            break;
                        }
                        Some(Tok::Hex(lo_h)) => {
                            let (lo, len) = hex_to_code(lo_h)?;
                            i += 1;
                            let (hi, hi_len) = match toks.get(i) {
                                Some(Tok::Hex(h)) => {
                                    let r = hex_to_code(h)?;
                                    i += 1;
                                    r
                                }
                                _ => return Err("bfrange: expected range end".into()),
                            };
                            if hi_len != len || hi < lo {
                                return Err("bfrange: invalid range".into());
                            }
                            let dst = match toks.get(i) {
                                Some(Tok::Hex(h)) => {
                                    let units = hex_to_u16s(h)?;
                                    i += 1;
                                    if units.len() == 1 {
                                        RangeTarget::Offset(u32::wrapping_sub(units[0] as u32, lo))
                                    } else {
                                        RangeTarget::Hex(units)
                                    }
                                }
                                Some(Tok::Open) => {
                                    i += 1;
                                    let mut arr = Vec::new();
                                    loop {
                                        match toks.get(i) {
                                            Some(Tok::Hex(h)) => {
                                                arr.push(hex_to_u16s(h)?);
                                                i += 1;
                                            }
                                            Some(Tok::Close) => {
                                                i += 1;
                                                break;
                                            }
                                            _ => return Err("bfrange: bad array destination".into()),
                                        }
                                    }
                                    RangeTarget::Array(arr)
                                }
                                _ => return Err("bfrange: expected destination".into()),
                            };
                            cmap.put(lo, hi, len, dst);
                            mappings += 1;
                        }
                        _ => return Err("bfrange: expected range start".into()),
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    if mappings == 0 {
        return Err("ToUnicode CMap contains no bfchar/bfrange mappings".into());
    }
    Ok(cmap)
}

// Base character-set tables (PDF spec / Adobe encodings), generated from the
// public PDF specification data: code -> Unicode code point.
pub static STANDARD_ENCODING: [Option<u16>; 256] = [

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    Some(0x0020), Some(0x0021), Some(0x0022), Some(0x0023), Some(0x0024), Some(0x0025), Some(0x0026), Some(0x2019),

    Some(0x0028), Some(0x0029), Some(0x002a), Some(0x002b), Some(0x002c), Some(0x002d), Some(0x002e), Some(0x002f),

    Some(0x0030), Some(0x0031), Some(0x0032), Some(0x0033), Some(0x0034), Some(0x0035), Some(0x0036), Some(0x0037),

    Some(0x0038), Some(0x0039), Some(0x003a), Some(0x003b), Some(0x003c), Some(0x003d), Some(0x003e), Some(0x003f),

    Some(0x0040), Some(0x0041), Some(0x0042), Some(0x0043), Some(0x0044), Some(0x0045), Some(0x0046), Some(0x0047),

    Some(0x0048), Some(0x0049), Some(0x004a), Some(0x004b), Some(0x004c), Some(0x004d), Some(0x004e), Some(0x004f),

    Some(0x0050), Some(0x0051), Some(0x0052), Some(0x0053), Some(0x0054), Some(0x0055), Some(0x0056), Some(0x0057),

    Some(0x0058), Some(0x0059), Some(0x005a), Some(0x005b), Some(0x005c), Some(0x005d), Some(0x005e), Some(0x005f),

    Some(0x2018), Some(0x0061), Some(0x0062), Some(0x0063), Some(0x0064), Some(0x0065), Some(0x0066), Some(0x0067),

    Some(0x0068), Some(0x0069), Some(0x006a), Some(0x006b), Some(0x006c), Some(0x006d), Some(0x006e), Some(0x006f),

    Some(0x0070), Some(0x0071), Some(0x0072), Some(0x0073), Some(0x0074), Some(0x0075), Some(0x0076), Some(0x0077),

    Some(0x0078), Some(0x0079), Some(0x007a), Some(0x007b), Some(0x007c), Some(0x007d), Some(0x007e), None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, Some(0x00a1), Some(0x00a2), Some(0x00a3), Some(0x2044), Some(0x00a5), Some(0x0192), Some(0x00a7),

    Some(0x00a4), Some(0x0027), Some(0x201c), Some(0x00ab), Some(0x2039), Some(0x203a), Some(0xfb01), Some(0xfb02),

    None, Some(0x2013), Some(0x2020), Some(0x2021), Some(0x00b7), None, Some(0x00b6), Some(0x2022),

    Some(0x201a), Some(0x201e), Some(0x201d), Some(0x00bb), Some(0x2026), Some(0x2030), None, Some(0x00bf),

    None, Some(0x0060), Some(0x00b4), Some(0x02c6), Some(0x02dc), Some(0x00af), Some(0x02d8), Some(0x02d9),

    Some(0x00a8), None, Some(0x02da), Some(0x00b8), None, Some(0x02dd), Some(0x02db), Some(0x02c7),

    Some(0x2014), None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, Some(0x00c6), None, Some(0x00aa), None, None, None, None,

    Some(0x0141), Some(0x00d8), Some(0x0152), Some(0x00ba), None, None, None, None,

    None, Some(0x00e6), None, None, None, Some(0x0131), None, None,

    Some(0x0142), Some(0x00f8), Some(0x0153), Some(0x00df), None, None, None, None,

];

pub static WIN_ANSI_ENCODING: [Option<u16>; 256] = [

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    Some(0x0020), Some(0x0021), Some(0x0022), Some(0x0023), Some(0x0024), Some(0x0025), Some(0x0026), Some(0x0027),

    Some(0x0028), Some(0x0029), Some(0x002a), Some(0x002b), Some(0x002c), Some(0x002d), Some(0x002e), Some(0x002f),

    Some(0x0030), Some(0x0031), Some(0x0032), Some(0x0033), Some(0x0034), Some(0x0035), Some(0x0036), Some(0x0037),

    Some(0x0038), Some(0x0039), Some(0x003a), Some(0x003b), Some(0x003c), Some(0x003d), Some(0x003e), Some(0x003f),

    Some(0x0040), Some(0x0041), Some(0x0042), Some(0x0043), Some(0x0044), Some(0x0045), Some(0x0046), Some(0x0047),

    Some(0x0048), Some(0x0049), Some(0x004a), Some(0x004b), Some(0x004c), Some(0x004d), Some(0x004e), Some(0x004f),

    Some(0x0050), Some(0x0051), Some(0x0052), Some(0x0053), Some(0x0054), Some(0x0055), Some(0x0056), Some(0x0057),

    Some(0x0058), Some(0x0059), Some(0x005a), Some(0x005b), Some(0x005c), Some(0x005d), Some(0x005e), Some(0x005f),

    Some(0x0060), Some(0x0061), Some(0x0062), Some(0x0063), Some(0x0064), Some(0x0065), Some(0x0066), Some(0x0067),

    Some(0x0068), Some(0x0069), Some(0x006a), Some(0x006b), Some(0x006c), Some(0x006d), Some(0x006e), Some(0x006f),

    Some(0x0070), Some(0x0071), Some(0x0072), Some(0x0073), Some(0x0074), Some(0x0075), Some(0x0076), Some(0x0077),

    Some(0x0078), Some(0x0079), Some(0x007a), Some(0x007b), Some(0x007c), Some(0x007d), Some(0x007e), Some(0x2022),

    Some(0x20ac), Some(0x2022), Some(0x201a), Some(0x0192), Some(0x201e), Some(0x2026), Some(0x2020), Some(0x2021),

    Some(0x02c6), Some(0x2030), Some(0x0160), Some(0x2039), Some(0x0152), Some(0x2022), Some(0x017d), Some(0x2022),

    Some(0x2022), Some(0x2018), Some(0x2019), Some(0x201c), Some(0x201d), Some(0x2022), Some(0x2013), Some(0x2014),

    Some(0x02dc), Some(0x2122), Some(0x0161), Some(0x203a), Some(0x0153), Some(0x2022), Some(0x017e), Some(0x0178),

    Some(0x0020), Some(0x00a1), Some(0x00a2), Some(0x00a3), Some(0x00a4), Some(0x00a5), Some(0x00a6), Some(0x00a7),

    Some(0x00a8), Some(0x00a9), Some(0x00aa), Some(0x00ab), Some(0x00ac), Some(0x002d), Some(0x00ae), Some(0x00af),

    Some(0x00b0), Some(0x00b1), Some(0x00b2), Some(0x00b3), Some(0x00b4), Some(0x00b5), Some(0x00b6), Some(0x00b7),

    Some(0x00b8), Some(0x00b9), Some(0x00ba), Some(0x00bb), Some(0x00bc), Some(0x00bd), Some(0x00be), Some(0x00bf),

    Some(0x00c0), Some(0x00c1), Some(0x00c2), Some(0x00c3), Some(0x00c4), Some(0x00c5), Some(0x00c6), Some(0x00c7),

    Some(0x00c8), Some(0x00c9), Some(0x00ca), Some(0x00cb), Some(0x00cc), Some(0x00cd), Some(0x00ce), Some(0x00cf),

    Some(0x00d0), Some(0x00d1), Some(0x00d2), Some(0x00d3), Some(0x00d4), Some(0x00d5), Some(0x00d6), Some(0x00d7),

    Some(0x00d8), Some(0x00d9), Some(0x00da), Some(0x00db), Some(0x00dc), Some(0x00dd), Some(0x00de), Some(0x00df),

    Some(0x00e0), Some(0x00e1), Some(0x00e2), Some(0x00e3), Some(0x00e4), Some(0x00e5), Some(0x00e6), Some(0x00e7),

    Some(0x00e8), Some(0x00e9), Some(0x00ea), Some(0x00eb), Some(0x00ec), Some(0x00ed), Some(0x00ee), Some(0x00ef),

    Some(0x00f0), Some(0x00f1), Some(0x00f2), Some(0x00f3), Some(0x00f4), Some(0x00f5), Some(0x00f6), Some(0x00f7),

    Some(0x00f8), Some(0x00f9), Some(0x00fa), Some(0x00fb), Some(0x00fc), Some(0x00fd), Some(0x00fe), Some(0x00ff),

];

pub static MAC_ROMAN_ENCODING: [Option<u16>; 256] = [

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    Some(0x0020), Some(0x0021), Some(0x0022), Some(0x0023), Some(0x0024), Some(0x0025), Some(0x0026), Some(0x0027),

    Some(0x0028), Some(0x0029), Some(0x002a), Some(0x002b), Some(0x002c), Some(0x002d), Some(0x002e), Some(0x002f),

    Some(0x0030), Some(0x0031), Some(0x0032), Some(0x0033), Some(0x0034), Some(0x0035), Some(0x0036), Some(0x0037),

    Some(0x0038), Some(0x0039), Some(0x003a), Some(0x003b), Some(0x003c), Some(0x003d), Some(0x003e), Some(0x003f),

    Some(0x0040), Some(0x0041), Some(0x0042), Some(0x0043), Some(0x0044), Some(0x0045), Some(0x0046), Some(0x0047),

    Some(0x0048), Some(0x0049), Some(0x004a), Some(0x004b), Some(0x004c), Some(0x004d), Some(0x004e), Some(0x004f),

    Some(0x0050), Some(0x0051), Some(0x0052), Some(0x0053), Some(0x0054), Some(0x0055), Some(0x0056), Some(0x0057),

    Some(0x0058), Some(0x0059), Some(0x005a), Some(0x005b), Some(0x005c), Some(0x005d), Some(0x005e), Some(0x005f),

    Some(0x0060), Some(0x0061), Some(0x0062), Some(0x0063), Some(0x0064), Some(0x0065), Some(0x0066), Some(0x0067),

    Some(0x0068), Some(0x0069), Some(0x006a), Some(0x006b), Some(0x006c), Some(0x006d), Some(0x006e), Some(0x006f),

    Some(0x0070), Some(0x0071), Some(0x0072), Some(0x0073), Some(0x0074), Some(0x0075), Some(0x0076), Some(0x0077),

    Some(0x0078), Some(0x0079), Some(0x007a), Some(0x007b), Some(0x007c), Some(0x007d), Some(0x007e), None,

    Some(0x00c4), Some(0x00c5), Some(0x00c7), Some(0x00c9), Some(0x00d1), Some(0x00d6), Some(0x00dc), Some(0x00e1),

    Some(0x00e0), Some(0x00e2), Some(0x00e4), Some(0x00e3), Some(0x00e5), Some(0x00e7), Some(0x00e9), Some(0x00e8),

    Some(0x00ea), Some(0x00eb), Some(0x00ed), Some(0x00ec), Some(0x00ee), Some(0x00ef), Some(0x00f1), Some(0x00f3),

    Some(0x00f2), Some(0x00f4), Some(0x00f6), Some(0x00f5), Some(0x00fa), Some(0x00f9), Some(0x00fb), Some(0x00fc),

    Some(0x2020), Some(0x00b0), Some(0x00a2), Some(0x00a3), Some(0x00a7), Some(0x2022), Some(0x00b6), Some(0x00df),

    Some(0x00ae), Some(0x00a9), Some(0x2122), Some(0x00b4), Some(0x00a8), Some(0x2260), Some(0x00c6), Some(0x00d8),

    Some(0x221e), Some(0x00b1), Some(0x2264), Some(0x2265), Some(0x00a5), Some(0x00b5), Some(0x2202), Some(0x2211),

    Some(0x220f), Some(0x03c0), Some(0x222b), Some(0x00aa), Some(0x00ba), Some(0x2126), Some(0x00e6), Some(0x00f8),

    Some(0x00bf), Some(0x00a1), Some(0x00ac), Some(0x221a), Some(0x0192), Some(0x2248), Some(0x2206), Some(0x00ab),

    Some(0x00bb), Some(0x2026), Some(0x0020), Some(0x00c0), Some(0x00c3), Some(0x00d5), Some(0x0152), Some(0x0153),

    Some(0x2013), Some(0x2014), Some(0x201c), Some(0x201d), Some(0x2018), Some(0x2019), Some(0x00f7), Some(0x25ca),

    Some(0x00ff), Some(0x0178), Some(0x2044), Some(0x00a4), Some(0x2039), Some(0x203a), Some(0xfb01), Some(0xfb02),

    Some(0x2021), Some(0x00b7), Some(0x201a), Some(0x201e), Some(0x2030), Some(0x00c2), Some(0x00ca), Some(0x00c1),

    Some(0x00cb), Some(0x00c8), Some(0x00cd), Some(0x00ce), Some(0x00cf), Some(0x00cc), Some(0x00d3), Some(0x00d4),

    Some(0xf8ff), Some(0x00d2), Some(0x00da), Some(0x00db), Some(0x00d9), Some(0x0131), Some(0x02c6), Some(0x02dc),

    Some(0x00af), Some(0x02d8), Some(0x02d9), Some(0x02da), Some(0x00b8), Some(0x02dd), Some(0x02db), Some(0x02c7),

];

pub static MAC_EXPERT_ENCODING: [Option<u16>; 256] = [

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    Some(0x0020), Some(0xf721), Some(0xf6f8), Some(0xf7a2), Some(0xf724), Some(0xf6e4), Some(0xf726), Some(0xf7b4),

    Some(0x207d), Some(0x207e), Some(0x2025), Some(0x2024), Some(0x002c), Some(0x002d), Some(0x002e), Some(0x2044),

    Some(0xf730), Some(0xf731), Some(0xf732), Some(0xf733), Some(0xf734), Some(0xf735), Some(0xf736), Some(0xf737),

    Some(0xf738), Some(0xf739), Some(0x003a), Some(0x003b), None, Some(0xf6de), None, Some(0xf73f),

    None, None, None, None, Some(0xf7f0), None, None, Some(0x00bc),

    Some(0x00bd), Some(0x00be), Some(0x215b), Some(0x215c), Some(0x215d), Some(0x215e), Some(0x2153), Some(0x2154),

    None, None, None, None, None, None, Some(0xfb00), Some(0xfb01),

    Some(0xfb02), Some(0xfb03), Some(0xfb04), Some(0x208d), None, Some(0x208e), Some(0xf6f6), Some(0xf6e5),

    Some(0xf760), Some(0xf761), Some(0xf762), Some(0xf763), Some(0xf764), Some(0xf765), Some(0xf766), Some(0xf767),

    Some(0xf768), Some(0xf769), Some(0xf76a), Some(0xf76b), Some(0xf76c), Some(0xf76d), Some(0xf76e), Some(0xf76f),

    Some(0xf770), Some(0xf771), Some(0xf772), Some(0xf773), Some(0xf774), Some(0xf775), Some(0xf776), Some(0xf777),

    Some(0xf778), Some(0xf779), Some(0xf77a), Some(0x20a1), Some(0xf6dc), Some(0xf6dd), Some(0xf6fe), None,

    None, Some(0xf6e9), Some(0xf6e0), None, None, None, None, Some(0xf7e1),

    Some(0xf7e0), Some(0xf7e2), Some(0xf7e4), Some(0xf7e3), Some(0xf7e5), Some(0xf7e7), Some(0xf7e9), Some(0xf7e8),

    Some(0xf7ea), Some(0xf7eb), Some(0xf7ed), Some(0xf7ec), Some(0xf7ee), Some(0xf7ef), Some(0xf7f1), Some(0xf7f3),

    Some(0xf7f2), Some(0xf7f4), Some(0xf7f6), Some(0xf7f5), Some(0xf7fa), Some(0xf7f9), Some(0xf7fb), Some(0xf7fc),

    None, Some(0x2078), Some(0x2084), Some(0x2083), Some(0x2086), Some(0x2088), Some(0x2087), Some(0xf6fd),

    None, Some(0xf6df), Some(0x2082), None, Some(0xf7a8), None, Some(0xf6f5), Some(0xf6f0),

    Some(0x2085), None, Some(0xf6e1), Some(0xf6e7), Some(0xf7fd), None, Some(0xf6e3), None,

    None, Some(0xf7fe), None, Some(0x2089), Some(0x2080), Some(0xf6ff), Some(0xf7e6), Some(0xf7f8),

    Some(0xf7bf), Some(0x2081), Some(0xf6f9), None, None, None, None, None,

    None, Some(0xf7b8), None, None, None, None, None, Some(0xf6fa),

    Some(0x2012), Some(0xf6e6), None, None, None, None, Some(0xf7a1), None,

    Some(0xf7ff), None, Some(0x00b9), Some(0x00b2), Some(0x00b3), Some(0x2074), Some(0x2075), Some(0x2076),

    Some(0x2077), Some(0x2079), Some(0x2070), None, Some(0xf6ec), Some(0xf6f1), Some(0xf6f3), None,

    None, Some(0xf6ed), Some(0xf6f2), Some(0xf6eb), None, None, None, None,

    None, Some(0xf6ee), Some(0xf6fb), Some(0xf6f4), Some(0xf7af), Some(0xf6ea), Some(0x207f), Some(0xf6ef),

    Some(0xf6e2), Some(0xf6e8), Some(0xf6f7), Some(0xf6fc), None, None, None, None,

];

pub static PDF_DOC_ENCODING: [Option<u16>; 256] = [

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    None, None, None, None, None, None, None, None,

    Some(0x02d8), Some(0x02c7), Some(0x02c6), Some(0x02d9), Some(0x02dd), Some(0x02db), Some(0x02da), Some(0x02dc),

    Some(0x0020), Some(0x0021), Some(0x0022), Some(0x0023), Some(0x0024), Some(0x0025), Some(0x0026), Some(0x0027),

    Some(0x0028), Some(0x0029), Some(0x002a), Some(0x002b), Some(0x002c), Some(0x002d), Some(0x002e), Some(0x002f),

    Some(0x0030), Some(0x0031), Some(0x0032), Some(0x0033), Some(0x0034), Some(0x0035), Some(0x0036), Some(0x0037),

    Some(0x0038), Some(0x0039), Some(0x003a), Some(0x003b), Some(0x003c), Some(0x003d), Some(0x003e), Some(0x003f),

    Some(0x0040), Some(0x0041), Some(0x0042), Some(0x0043), Some(0x0044), Some(0x0045), Some(0x0046), Some(0x0047),

    Some(0x0048), Some(0x0049), Some(0x004a), Some(0x004b), Some(0x004c), Some(0x004d), Some(0x004e), Some(0x004f),

    Some(0x0050), Some(0x0051), Some(0x0052), Some(0x0053), Some(0x0054), Some(0x0055), Some(0x0056), Some(0x0057),

    Some(0x0058), Some(0x0059), Some(0x005a), Some(0x005b), Some(0x005c), Some(0x005d), Some(0x005e), Some(0x005f),

    Some(0x0060), Some(0x0061), Some(0x0062), Some(0x0063), Some(0x0064), Some(0x0065), Some(0x0066), Some(0x0067),

    Some(0x0068), Some(0x0069), Some(0x006a), Some(0x006b), Some(0x006c), Some(0x006d), Some(0x006e), Some(0x006f),

    Some(0x0070), Some(0x0071), Some(0x0072), Some(0x0073), Some(0x0074), Some(0x0075), Some(0x0076), Some(0x0077),

    Some(0x0078), Some(0x0079), Some(0x007a), Some(0x007b), Some(0x007c), Some(0x007d), Some(0x007e), None,

    Some(0x2022), Some(0x2020), Some(0x2021), Some(0x2026), Some(0x2014), Some(0x2013), Some(0x0192), Some(0x2044),

    Some(0x2039), Some(0x203a), Some(0x2212), Some(0x2030), Some(0x201e), Some(0x201c), Some(0x201d), Some(0x2018),

    Some(0x2019), Some(0x201a), Some(0x2122), Some(0xfb01), Some(0xfb02), Some(0x0141), Some(0x0152), Some(0x0160),

    Some(0x0178), Some(0x017d), Some(0x0131), Some(0x0142), Some(0x0153), Some(0x0161), Some(0x017e), None,

    Some(0x20ac), Some(0x00a1), Some(0x00a2), Some(0x00a3), Some(0x00a4), Some(0x00a5), Some(0x00a6), Some(0x00a7),

    Some(0x00a8), Some(0x00a9), Some(0x00aa), Some(0x00ab), Some(0x00ac), None, Some(0x00ae), Some(0x00af),

    Some(0x00b0), Some(0x00b1), Some(0x00b2), Some(0x00b3), Some(0x00b4), Some(0x00b5), Some(0x00b6), Some(0x00b7),

    Some(0x00b8), Some(0x00b9), Some(0x00ba), Some(0x00bb), Some(0x00bc), Some(0x00bd), Some(0x00be), Some(0x00bf),

    Some(0x00c0), Some(0x00c1), Some(0x00c2), Some(0x00c3), Some(0x00c4), Some(0x00c5), Some(0x00c6), Some(0x00c7),

    Some(0x00c8), Some(0x00c9), Some(0x00ca), Some(0x00cb), Some(0x00cc), Some(0x00cd), Some(0x00ce), Some(0x00cf),

    Some(0x00d0), Some(0x00d1), Some(0x00d2), Some(0x00d3), Some(0x00d4), Some(0x00d5), Some(0x00d6), Some(0x00d7),

    Some(0x00d8), Some(0x00d9), Some(0x00da), Some(0x00db), Some(0x00dc), Some(0x00dd), Some(0x00de), Some(0x00df),

    Some(0x00e0), Some(0x00e1), Some(0x00e2), Some(0x00e3), Some(0x00e4), Some(0x00e5), Some(0x00e6), Some(0x00e7),

    Some(0x00e8), Some(0x00e9), Some(0x00ea), Some(0x00eb), Some(0x00ec), Some(0x00ed), Some(0x00ee), Some(0x00ef),

    Some(0x00f0), Some(0x00f1), Some(0x00f2), Some(0x00f3), Some(0x00f4), Some(0x00f5), Some(0x00f6), Some(0x00f7),

    Some(0x00f8), Some(0x00f9), Some(0x00fa), Some(0x00fb), Some(0x00fc), Some(0x00fd), Some(0x00fe), Some(0x00ff),

];

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CMAP: &[u8] = b"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
3 beginbfchar
<0001> <0041>
<0002> <0042>
<0003> <0043>
endbfchar
1 beginbfrange
<0020> <0021> [<0058> <0059>]
endbfrange
endcmap
end
end
";

    #[test]
    fn parse_and_decode_roundtrip() {
        let cmap = parse_tounicode_cmap(TEST_CMAP).expect("parse");
        assert_eq!(cmap.decode(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x03]), "ABC");
        assert_eq!(cmap.decode(&[0x00, 0x20, 0x00, 0x21]), "XY");
        assert_eq!(cmap.code_for_char('A'), Some(vec![0x00, 0x01]));
        assert_eq!(cmap.code_for_char('X'), Some(vec![0x00, 0x20]));
        assert!(cmap.code_for_char('Z').is_none());
    }

    #[test]
    fn literal_strings_in_cmap_cannot_inject_mappings() {
        let cmap_src = b"begincmap
/CMapName /Test def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
% (beginbfchar <0001> <005A> endbfchar) inside a literal string must not count
1 beginbfchar
<0001> <0041>
endbfchar
endcmap
";
        let cmap = parse_tounicode_cmap(cmap_src).expect("parse");
        assert_eq!(cmap.decode(&[0x00, 0x01]), "A", "injected mapping must not shadow the real one");
    }

    #[test]
    fn overwide_hex_and_ranges_are_rejected() {
        assert!(parse_tounicode_cmap(b"1 beginbfchar\n<0123456789AB> <0041>\nendbfchar\n").is_err());
        let mut cmap = UnicodeCMap::new();
        cmap.put(0, 0x1_0000, 2, RangeTarget::Offset(0));
        assert!(cmap.get(0x8000, 2).is_none(), "over-wide range must be dropped");
    }
}
