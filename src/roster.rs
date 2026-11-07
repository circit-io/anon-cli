//! PII roster intake validation and narrowed identifier extraction.
//!
//! Upstream roster extraction historically used broad regexes such as
//! `SORTCODE_RE = (\d{2}-\d{2}-\d{2})` and a similarly broad `ACCOUNT_RE`,
//! which matched dates and amounts and produced false-positive roster
//! entries (over-redaction, spurious quarantines). The matchers here are the
//! narrowed replacements: strict shape checks plus boundary rules that reject
//! date/amount/phone-shaped strings. `validate_entry` is enforced at the
//! `--redact` intake boundary in `main.rs`, fail-closed.

/// Strict UK sort code: `NN-NN-NN` with the first pair in 01..=99.
pub fn is_sort_code(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 8 || b[2] != b'-' || b[5] != b'-' {
        return false;
    }
    let d = |i: usize| -> Option<u32> {
        if b[i].is_ascii_digit() {
            Some((b[i] - b'0') as u32)
        } else {
            None
        }
    };
    match (d(0), d(1), d(3), d(4), d(6), d(7)) {
        (Some(a), Some(b0), Some(c), Some(d0), Some(e), Some(f)) => {
            let first = a * 10 + b0;
            let _ = (c, d0, e, f);
            (1..=99).contains(&first)
        }
        _ => false,
    }
}

/// Strict UK account number: 8 digits, optionally grouped 4-4 with `-` or
/// space. Anything longer (card numbers), or containing other separators, is
/// rejected.
pub fn is_account_number(s: &str) -> bool {
    let b = s.as_bytes();
    match b.len() {
        8 => b.iter().all(|c| c.is_ascii_digit()),
        9 => {
            (b[4] == b'-' || b[4] == b' ')
                && b[..4].iter().all(|c| c.is_ascii_digit())
                && b[5..].iter().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// True when the byte just before `start` ties the candidate into a longer
/// numeric run (date, amount, card number): digit, `-`, or a decimal/comma
/// separator that itself follows a digit.
fn left_tied(text: &[u8], start: usize) -> bool {
    if start == 0 {
        return false;
    }
    let p = text[start - 1];
    if p.is_ascii_digit() || p == b'-' {
        return true;
    }
    if (p == b'.' || p == b',') && start >= 2 && text[start - 2].is_ascii_digit() {
        return true;
    }
    false
}

/// Mirror of `left_tied` for the byte just after `end`.
fn right_tied(text: &[u8], end: usize) -> bool {
    if end >= text.len() {
        return false;
    }
    let n = text[end];
    if n.is_ascii_digit() || n == b'-' {
        return true;
    }
    if (n == b'.' || n == b',') && end + 1 < text.len() && text[end + 1].is_ascii_digit() {
        return true;
    }
    false
}

/// Scan free text for sort-code candidates with the narrowed pattern:
/// `\d{2}-\d{2}-\d{2}` on clean boundaries, first pair 01..=99, not embedded
/// in a date/amount/longer digit run.
pub fn find_sort_codes(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= b.len() {
        let cand = &b[i..i + 8];
        if cand[2] == b'-'
            && cand[5] == b'-'
            && cand
                .iter()
                .enumerate()
                .all(|(k, c)| k == 2 || k == 5 || c.is_ascii_digit())
        {
            let first = (cand[0] - b'0') as u32 * 10 + (cand[1] - b'0') as u32;
            if (1..=99).contains(&first)
                && !left_tied(b, i)
                && !right_tied(b, i + 8)
                && is_sort_code(&text[i..i + 8])
            {
                out.push(text[i..i + 8].to_string());
                i += 8;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Scan free text for account-number candidates with the narrowed pattern:
/// 8 digits, or `\d{4}[- ]\d{4}`, on clean boundaries (rejects substrings of
/// dates, decimals, amounts, and 16-digit card numbers).
pub fn find_account_numbers(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        // grouped form NNNN-NNNN / NNNN NNNN must be tried before the plain
        // digit run, otherwise the run branch consumes its first 4 digits
        if i + 9 <= b.len()
            && b[i..i + 4].iter().all(|c| c.is_ascii_digit())
            && (b[i + 4] == b'-' || b[i + 4] == b' ')
            && b[i + 5..i + 9].iter().all(|c| c.is_ascii_digit())
            && !left_tied(b, i)
            && !right_tied(b, i + 9)
        {
            out.push(text[i..i + 9].to_string());
            i += 9;
            continue;
        }
        if b[i].is_ascii_digit() {
            // run of digits
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let run = i - start;
            if run == 8 && !left_tied(b, start) && !right_tied(b, i) {
                out.push(text[start..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RosterEntity {
    SortCode,
    AccountNumber,
}

pub fn parse_entity_filter(s: &str) -> Result<Option<RosterEntity>, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(None),
        "sort_code" => Ok(Some(RosterEntity::SortCode)),
        "account_number" => Ok(Some(RosterEntity::AccountNumber)),
        other => Err(format!(
            "unknown entity filter {other:?}; expected all|sort_code|account_number"
        )),
    }
}

/// Extract roster candidates (`raw`, `entity_type`) from free text using the
/// narrowed matchers, deduplicated in first-seen order. Upstream extractors
/// should use this (via `anon-cli roster extract`) instead of broad regexes
/// so dates/amounts/cards never enter the roster.
pub fn extract_from_text(text: &str, filter: Option<RosterEntity>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |v: String, et: &str| {
        if !out.iter().any(|(e, t)| e == &v && t == et) {
            out.push((v, et.to_string()));
        }
    };
    if filter != Some(RosterEntity::AccountNumber) {
        for sc in find_sort_codes(text) {
            push(sc, "sort_code");
        }
    }
    if filter != Some(RosterEntity::SortCode) {
        for an in find_account_numbers(text) {
            push(an, "account_number");
        }
    }
    out
}

/// Fail-closed intake check for a `--redact "raw:entity_type"` spec.
/// Entries tagged `sort_code` / `account_number` must match the narrowed
/// shapes; a mismatch means the upstream extractor emitted a date/amount
/// false positive, so we refuse rather than sweep garbage across documents.
pub fn validate_entry(raw: &str, entity_type: &str) -> Result<(), String> {
    // normalize so casing/whitespace variants ("Sort_Code", "sort_code ")
    // cannot bypass the fail-closed shape check
    let entity_type = entity_type.trim().to_ascii_lowercase();
    match entity_type.as_str() {
        "sort_code" if !is_sort_code(raw) => Err(format!(
            "roster entry {raw:?} tagged sort_code does not match the narrowed sort-code shape NN-NN-NN (first pair 01-99); refusing date/amount false positive"
        )),
        "account_number" if !is_account_number(raw) => Err(format!(
            "roster entry {raw:?} tagged account_number does not match the narrowed account-number shape (8 digits or NNNN-NNNN); refusing date/amount/card false positive"
        )),
        _ => Ok(()),
    }
}
