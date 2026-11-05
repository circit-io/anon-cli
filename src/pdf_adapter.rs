use crate::crypto::CohortKey;
use crate::error::AdapterError;
use crate::policy::Policy;
use lopdf::{Document, Object};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfReport {
    pub pages_processed: usize,
    pub objects_removed: usize,
    pub metadata_scrubbed: bool,
    pub redactions_applied: usize,
    pub quarantined: bool,
    pub quarantine_reason: Option<String>,
}

const CATALOG_KEYS_TO_STRIP: &[&str] = &[
    "Names",
    "OpenAction",
    "AA",
    "AcroForm",
    "XFA",
    "Metadata",
    "AF",
    "Perms",
    "PieceInfo",
    "SpiderInfo",
    "Outlines",
    "StructTreeRoot",
];

const PAGE_KEYS_TO_STRIP: &[&str] = &["Annots", "AA", "Metadata", "PieceInfo", "Thumb"];

const OBJECT_KEYS_TO_STRIP: &[&[u8]] = &[
    b"Metadata",
    b"PieceInfo",
    b"AA",
    b"OpenAction",
    b"JS",
    b"JavaScript",
    b"A",
];

const MULTIMEDIA_SUBTYPES: [&[u8]; 5] = [b"Screen", b"Movie", b"Sound", b"RichMedia", b"3D"];

pub fn sanitize_pdf(
    input: &Path,
    output: &Path,
    policy: &Policy,
) -> Result<PdfReport, AdapterError> {
    sanitize_pdf_with_redactions(input, output, policy, None, &[])
}

pub fn sanitize_pdf_with_redactions(
    input: &Path,
    output: &Path,
    policy: &Policy,
    key: Option<&CohortKey>,
    redactions: &[(String, String)],
) -> Result<PdfReport, AdapterError> {
    match Document::load(input) {
        Ok(mut doc) => {
            if doc.is_encrypted() {
                return Ok(quarantined("encrypted pdf"));
            }
            Ok(sanitize_loaded(&mut doc, output, policy, key, redactions))
        }
        Err(e) => {
            let reason = e.to_string();
            if reason.to_lowercase().contains("encrypt") {
                Ok(quarantined("encrypted pdf: decryption not supported"))
            } else {
                Ok(quarantined(&format!("malformed pdf: {reason}")))
            }
        }
    }
}

fn quarantined(reason: &str) -> PdfReport {
    PdfReport {
        pages_processed: 0,
        objects_removed: 0,
        metadata_scrubbed: false,
        redactions_applied: 0,
        quarantined: true,
        quarantine_reason: Some(reason.to_string()),
    }
}

fn sanitize_loaded(
    doc: &mut Document,
    output: &Path,
    _policy: &Policy,
    key: Option<&CohortKey>,
    redactions: &[(String, String)],
) -> PdfReport {
    let objects_before = doc.objects.len();
    let pages_processed = doc.page_iter().count();

    if let Ok(catalog) = doc.catalog_mut() {
        for key_name in CATALOG_KEYS_TO_STRIP {
            catalog.remove(key_name.as_bytes());
        }
    }

    let page_ids: Vec<lopdf::ObjectId> = doc.page_iter().collect();
    for page_id in page_ids {
        if let Ok(page) = doc.get_dictionary_mut(page_id) {
            for key_name in PAGE_KEYS_TO_STRIP {
                page.remove(key_name.as_bytes());
            }
        }
    }

    let mut metadata_scrubbed = doc.trailer.remove(b"Info").is_some();
    for obj in doc.objects.values_mut() {
        let dict_opt = match obj {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&mut s.dict),
            _ => None,
        };
        if let Some(d) = dict_opt {
            for key_name in OBJECT_KEYS_TO_STRIP {
                if d.remove(key_name).is_some() && *key_name == b"Metadata" {
                    metadata_scrubbed = true;
                }
            }
        }
    }

    delete_typed_objects(doc, b"Filespec");
    delete_typed_objects(doc, b"Metadata");
    delete_multimedia_and_actions(doc);
    doc.prune_objects();
    let objects_removed = objects_before.saturating_sub(doc.objects.len());

    let mut redactions_applied = 0;
    if !redactions.is_empty() {
        match apply_redactions(doc, key, redactions) {
            Ok(n) => redactions_applied = n,
            Err(e) => return quarantined(&format!("visible-text redaction failed: {e}")),
        }
    }

    match doc.save(output) {
        Ok(_) => PdfReport {
            pages_processed,
            objects_removed,
            metadata_scrubbed,
            redactions_applied,
            quarantined: false,
            quarantine_reason: None,
        },
        Err(e) => quarantined(&format!("save failed: {e}")),
    }
}

fn apply_redactions(
    doc: &mut Document,
    key: Option<&CohortKey>,
    redactions: &[(String, String)],
) -> Result<usize, lopdf::Error> {
    let page_ids: Vec<lopdf::ObjectId> = doc.page_iter().collect();
    let mut applied = 0;
    let mut cache: std::collections::HashMap<(Vec<u8>, char), Option<Vec<u8>>> =
        std::collections::HashMap::new();
    for (raw, entity_type) in redactions {
        let replacement = match key {
            Some(k) => k.pseudonymize_for(raw, entity_type),
            None => "REDACTED".to_string(),
        };
        for &page_id in &page_ids {
            let encodings: std::collections::BTreeMap<Vec<u8>, lopdf::Encoding> = doc
                .get_page_fonts(page_id)?
                .into_iter()
                .map(|(name, font)| font.get_font_encoding(doc).map(|it| (name, it)))
                .collect::<Result<_, lopdf::Error>>()?;
            let mut content = doc.get_and_decode_page_content(page_id)?;
            let mut current_font: Option<Vec<u8>> = None;
            let mut font_size: Object = Object::Integer(12);
            let mut page_hits = 0usize;
            let ops = &mut content.operations;
            let mut i = 0;
            while i < ops.len() {
                if ops[i].operator.as_str() == "Tf" {
                    current_font = ops[i]
                        .operands
                        .first()
                        .and_then(|o| o.as_name().ok())
                        .map(|n| n.to_vec());
                    if let Some(size) = ops[i].operands.get(1) {
                        font_size = size.clone();
                    }
                    i += 1;
                    continue;
                }
                if !matches!(ops[i].operator.as_str(), "Tj" | "TJ") {
                    i += 1;
                    continue;
                }
                let font_key = current_font.clone().unwrap_or_default();
                if !encodings.contains_key(&font_key) {
                    i += 1;
                    continue;
                }

                let start = i;
                while i < ops.len() && matches!(ops[i].operator.as_str(), "Tj" | "TJ") {
                    i += 1;
                }
                let group: Vec<lopdf::content::Operation> = ops[start..i].to_vec();
                let (new_group, hits_n) = replace_in_group(
                    group,
                    &encodings,
                    &font_key,
                    font_size.clone(),
                    raw,
                    &replacement,
                    &mut cache,
                )?;
                ops.splice(start..i, new_group);
                i = start + hits_n.1;
                page_hits += hits_n.0;
            }
            if page_hits > 0 {
                doc.change_page_content(page_id, content.encode()?)?;
                applied += page_hits;
            }
        }
    }
    Ok(applied)
}

fn choose_replacement_font(
    replacement: &str,
    encodings: &std::collections::BTreeMap<Vec<u8>, lopdf::Encoding>,
    cache: &mut std::collections::HashMap<(Vec<u8>, char), Option<Vec<u8>>>,
) -> Option<Vec<u8>> {
    for (name, enc) in encodings {
        if replacement
            .chars()
            .all(|ch| encodable_in(enc, name, ch, cache))
        {
            return Some(name.clone());
        }
    }
    None
}

fn encodable_in(
    encoding: &lopdf::Encoding,
    font_key: &[u8],
    ch: char,
    cache: &mut std::collections::HashMap<(Vec<u8>, char), Option<Vec<u8>>>,
) -> bool {
    match encoding {
        lopdf::Encoding::UnicodeMapEncoding(cmap) => {
            let key = (font_key.to_vec(), ch);
            if let Some(hit) = cache.get(&key) {
                return hit.is_some();
            }
            let mut found = None;
            let target = ch as u32;
            if target <= 0xFFFF {
                if target <= 0xFF {
                    if let Some(vals) = cmap.get(target, 1) {
                        if vals.len() == 1 && vals[0] as u32 == target {
                            found = Some(vec![target as u8]);
                        }
                    }
                }
                if found.is_none() {
                    if let Some(vals) = cmap.get(target, 2) {
                        if vals.len() == 1 && vals[0] as u32 == target {
                            found = Some(target.to_be_bytes()[1..].to_vec());
                        }
                    }
                }
                if found.is_none() {
                    'outer: for len in [1u8, 2] {
                        let max: u32 = if len == 1 { 0x100 } else { 0x10000 };
                        for code_val in (0..max).rev() {
                            if let Some(vals) = cmap.get(code_val, len) {
                                if vals.len() == 1 && vals[0] as u32 == target {
                                    found =
                                        Some(code_val.to_be_bytes()[2 - len as usize..].to_vec());
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
            }
            cache.insert(key, found.clone());
            found.is_some()
        }
        _ => true,
    }
}

fn safe_encode(
    encoding: &lopdf::Encoding,
    font_key: &[u8],
    text: &str,
    cache: &mut std::collections::HashMap<(Vec<u8>, char), Option<Vec<u8>>>,
) -> Result<Vec<u8>, lopdf::Error> {
    if text
        .chars()
        .all(|ch| encodable_in(encoding, font_key, ch, cache))
    {
        return match encoding {
            lopdf::Encoding::UnicodeMapEncoding(_) => {
                let mut out = Vec::new();
                for ch in text.chars() {
                    let key = (font_key.to_vec(), ch);
                    let code = cache.get(&key).cloned().flatten().ok_or_else(|| {
                        lopdf::Error::Syntax(format!("character {ch:?} not encodable"))
                    })?;
                    out.extend(code);
                }
                Ok(out)
            }
            _ => Ok(Document::encode_text(encoding, text)),
        };
    }
    Err(lopdf::Error::Syntax(format!(
        "text {text:?} not encodable in font"
    )))
}

#[allow(clippy::too_many_arguments)]
fn replace_in_group(
    ops: Vec<lopdf::content::Operation>,
    encodings: &std::collections::BTreeMap<Vec<u8>, lopdf::Encoding>,
    font_key: &[u8],
    font_size: Object,
    raw: &str,
    replacement: &str,
    cache: &mut std::collections::HashMap<(Vec<u8>, char), Option<Vec<u8>>>,
) -> Result<(Vec<lopdf::content::Operation>, (usize, usize)), lopdf::Error> {
    let mut ops = ops;
    let mut hits = 0;
    loop {
        let encoding = encodings
            .get(font_key)
            .ok_or_else(|| lopdf::Error::Syntax("group font missing".into()))?;

        let mut spans: Vec<(usize, usize, usize, usize, String)> = Vec::new();
        let mut joined = String::new();
        for (op_idx, op) in ops.iter().enumerate() {
            for (operand_idx, operand) in op.operands.iter().enumerate() {
                let count = match operand {
                    Object::String(_, _) => 1,
                    Object::Array(items) => items.iter().filter(|o| o.as_str().is_ok()).count(),
                    _ => continue,
                };
                for k in 0..count {
                    let decoded = decode_operand_piece(operand, k, encoding)?;
                    let start = joined.len();
                    joined.push_str(&decoded);
                    spans.push((op_idx, operand_idx, k, start, decoded));
                }
            }
        }
        let mut compact_map: Vec<usize> = Vec::with_capacity(joined.len());
        {
            let mut byte_idx = 0usize;
            for ch in joined.chars() {
                compact_map.push(byte_idx);
                byte_idx += ch.len_utf8();
            }
        }
        let compact: String = joined.chars().filter(|c| !c.is_whitespace()).collect();
        let raw_compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();

        let (pos, match_end) = if let Some(p) = joined.find(raw) {
            (p, p + raw.len())
        } else if let Some(p) = compact.find(&raw_compact) {
            let start = compact_map[p];
            let last_char_byte = compact_map[p + raw_compact.len() - 1];
            let end = last_char_byte + joined[last_char_byte..].chars().next().unwrap().len_utf8();
            (start, end)
        } else {
            break;
        };

        let alt_font = if replacement
            .chars()
            .all(|ch| encodable_in(encoding, font_key, ch, cache))
        {
            None
        } else {
            Some(
                choose_replacement_font(replacement, encodings, cache).ok_or_else(|| {
                    lopdf::Error::Syntax(
                        "no page font can encode replacement text; visible-text-redaction-required"
                            .into(),
                    )
                })?,
            )
        };

        let first_overlap_idx = spans
            .iter()
            .position(|s| {
                let ps = s.3;
                let pe = ps + s.4.len();
                pe > pos && ps < match_end
            })
            .unwrap_or(usize::MAX);

        let bucket_maps: Vec<Vec<Vec<Vec<Object>>>> = ops.iter().map(operand_buckets).collect();
        let mut removed_nums: Vec<Object> = Vec::new();
        for span in &spans {
            let piece_start = span.3;
            let piece_end = piece_start + span.4.len();
            if piece_end <= pos || piece_start >= match_end {
                continue;
            }
            if let Some(bucket) = bucket_maps
                .get(span.0)
                .and_then(|b| b.get(span.1))
                .and_then(|b| b.get(span.2))
            {
                removed_nums.extend(bucket.iter().cloned());
            }
        }

        let mut out_ops: Vec<lopdf::content::Operation> = Vec::with_capacity(ops.len() + 4);
        let mut in_repl_run = false;
        let mut global_span_idx = 0usize;
        for (op_idx, op) in ops.into_iter().enumerate() {
            let op_spans: Vec<&(usize, usize, usize, usize, String)> =
                spans.iter().filter(|s| s.0 == op_idx).collect();
            if op_spans.is_empty() {
                out_ops.push(op);
                continue;
            }
            let operand_idx = op_spans[0].1;
            let nums_after = &bucket_maps[op_idx][operand_idx];
            let mut segments: Vec<(String, bool, Vec<Object>)> = Vec::new();
            for span in &op_spans {
                let span_ordinal = global_span_idx;
                global_span_idx += 1;
                let piece_start = span.3;
                let piece_end = piece_start + span.4.len();
                let nums: Vec<Object> = nums_after.get(span.2).cloned().unwrap_or_default();
                if piece_end <= pos || piece_start >= match_end {
                    segments.push((span.4.clone(), false, nums));
                } else {
                    if piece_start < pos {
                        segments.push((span.4[..pos - piece_start].to_string(), false, nums));
                    }
                    if span_ordinal == first_overlap_idx {
                        segments.push((replacement.to_string(), true, removed_nums.clone()));
                    }
                    if piece_end > match_end {
                        segments.push((
                            span.4[match_end - piece_start..].to_string(),
                            false,
                            Vec::new(),
                        ));
                    }
                }
            }

            let mut emitted_repl = false;
            for (text, is_repl, nums) in segments {
                if is_repl && !in_repl_run {
                    if let Some(alt) = &alt_font {
                        out_ops.push(lopdf::content::Operation::new(
                            "Tf",
                            vec![Object::Name(alt.clone()), font_size.clone()],
                        ));
                    }
                    in_repl_run = true;
                } else if !is_repl && in_repl_run {
                    if alt_font.is_some() {
                        out_ops.push(lopdf::content::Operation::new(
                            "Tf",
                            vec![Object::Name(font_key.to_vec()), font_size.clone()],
                        ));
                    }
                    in_repl_run = false;
                }
                let (enc, fkey) = if is_repl {
                    match &alt_font {
                        Some(alt) => (encodings.get(alt).unwrap(), alt.as_slice()),
                        None => (encoding, font_key),
                    }
                } else {
                    (encoding, font_key)
                };
                let encoded = safe_encode(enc, fkey, &text, cache)?;
                let mut new_op = op.clone();
                new_op.operands[operand_idx] = if new_op.operator.as_str() == "TJ" {
                    let mut arr = vec![Object::String(encoded, lopdf::StringFormat::Literal)];
                    arr.extend(nums.iter().cloned());
                    Object::Array(arr)
                } else {
                    Object::String(encoded, lopdf::StringFormat::Literal)
                };
                out_ops.push(new_op);
                emitted_repl = emitted_repl || is_repl;
            }
            let _ = emitted_repl;
            if in_repl_run {
                if alt_font.is_some() {
                    out_ops.push(lopdf::content::Operation::new(
                        "Tf",
                        vec![Object::Name(font_key.to_vec()), font_size.clone()],
                    ));
                }
                in_repl_run = false;
            }
        }
        ops = out_ops;
        hits += 1;
        if hits > 256 {
            return Err(lopdf::Error::Syntax("redaction loop limit exceeded".into()));
        }
    }
    let len = ops.len();
    Ok((ops, (hits, len)))
}

fn operand_buckets(op: &lopdf::content::Operation) -> Vec<Vec<Vec<Object>>> {
    op.operands
        .iter()
        .map(|operand| match operand {
            Object::Array(items) => {
                let mut buckets: Vec<Vec<Object>> = Vec::new();
                let mut last_string = 0usize;
                for item in items {
                    if item.as_str().is_ok() {
                        buckets.push(Vec::new());
                        last_string = buckets.len() - 1;
                    } else if !matches!(item, Object::String(_, _)) {
                        if buckets.is_empty() {
                            buckets.push(Vec::new());
                        }
                        buckets[last_string].push(item.clone());
                    }
                }
                buckets
            }
            _ => Vec::new(),
        })
        .collect()
}

fn decode_operand_piece(
    operand: &Object,
    k: usize,
    encoding: &lopdf::Encoding,
) -> Result<String, lopdf::Error> {
    let bytes = match operand {
        Object::String(bytes, _) => bytes,
        Object::Array(items) => items
            .iter()
            .filter_map(|o| o.as_str().ok())
            .nth(k)
            .ok_or_else(|| lopdf::Error::Syntax("string piece out of range".into()))?,
        _ => return Err(lopdf::Error::Syntax("operand not a string".into())),
    };
    Document::decode_text(encoding, bytes)
}

fn delete_typed_objects(doc: &mut Document, type_name: &[u8]) {
    let ids: Vec<lopdf::ObjectId> = doc
        .objects
        .iter()
        .filter(|(_, obj)| {
            let dict = match obj {
                Object::Dictionary(d) => Some(d),
                Object::Stream(s) => Some(&s.dict),
                _ => None,
            };
            dict.and_then(|d| d.get(b"Type").ok())
                .and_then(|t| t.as_name().ok())
                .map(|n| n == type_name)
                .unwrap_or(false)
        })
        .map(|(id, _)| *id)
        .collect();
    for id in ids {
        doc.objects.remove(&id);
    }
}

fn delete_multimedia_and_actions(doc: &mut Document) {
    let ids: Vec<lopdf::ObjectId> = doc
        .objects
        .iter()
        .filter(|(_, obj)| {
            let dict = match obj {
                Object::Dictionary(d) => Some(d),
                Object::Stream(s) => Some(&s.dict),
                _ => None,
            };
            dict.map(|d| {
                let subtype_hit = d
                    .get(b"Subtype")
                    .and_then(|s| s.as_name())
                    .map(|n| MULTIMEDIA_SUBTYPES.contains(&n))
                    .unwrap_or(false);
                let action_hit = d.get(b"S").and_then(|s| s.as_name()).map(|n| {
                    matches!(
                        n,
                        b"JavaScript" | b"URI" | b"Launch" | b"SubmitForm" | b"ImportData"
                    )
                });
                let uri_launch_hit =
                    d.get(b"URI").is_ok() || d.get(b"F").is_ok() && d.get(b"Win").is_ok();
                subtype_hit || action_hit.unwrap_or(false) || uri_launch_hit
            })
            .unwrap_or(false)
        })
        .map(|(id, _)| *id)
        .collect();
    for id in ids {
        doc.objects.remove(&id);
    }
}
