use crate::crypto::CohortKey;
use crate::error::AdapterError;
use crate::policy::Policy;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_NESTING_DEPTH: usize = 5;
const MAX_ENTRIES: usize = 1024;
const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbcReport {
    pub files_processed: usize,
    pub files_quarantined: usize,
    pub quarantine_reasons: Vec<(String, String)>,
}

enum Kind {
    Pdf,
    Zip,
    Csv,
    Jsonl,
    Office,
    Unknown,
}

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(prefix: &str) -> Result<Self, AdapterError> {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{seq}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir(&path)?;
        }
        Ok(ScratchDir(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn detect(name: &str, bytes: &[u8]) -> Kind {
    if bytes.starts_with(b"%PDF") {
        return Kind::Pdf;
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        if let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) {
            for i in 0..archive.len() {
                if let Ok(entry) = archive.by_index(i) {
                    if entry.name() == "[Content_Types].xml" {
                        return Kind::Office;
                    }
                }
            }
        }
        return Kind::Zip;
    }
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace()).copied();
    if first == Some(b'{') {
        return Kind::Jsonl;
    }
    if first.is_some() && !matches!(first, Some(b'[') | Some(b'<') | Some(b'\x00')) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            let first_line = text.lines().next().unwrap_or("");
            if first_line.contains(',')
                && first_line.chars().all(|c| {
                    c.is_alphanumeric() || matches!(c, ',' | '.' | '-' | '_' | ' ' | '\t' | '"')
                })
            {
                return Kind::Csv;
            }
        }
    }
    let _ = name;
    Kind::Unknown
}

fn read_bounded<R: Read>(entry: &mut R) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    entry
        .take((MAX_ENTRY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_ENTRY_BYTES {
        return Err("entry exceeds maximum size limit".to_string());
    }
    Ok(bytes)
}

pub fn process_archive(
    input: &Path,
    output_dir: &Path,
    policy: &Policy,
    key: &CohortKey,
) -> Result<PbcReport, AdapterError> {
    std::fs::create_dir_all(output_dir)?;

    let file = std::fs::File::open(input)?;
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => {
            return Ok(PbcReport {
                files_processed: 0,
                files_quarantined: 1,
                quarantine_reasons: vec![(
                    input.display().to_string(),
                    "corrupt zip archive".to_string(),
                )],
            });
        }
    };

    if archive.len() > MAX_ENTRIES {
        return Ok(PbcReport {
            files_processed: 0,
            files_quarantined: 1,
            quarantine_reasons: vec![(
                input.display().to_string(),
                "archive exceeds maximum entry count".to_string(),
            )],
        });
    }

    let mut report = PbcReport {
        files_processed: 0,
        files_quarantined: 0,
        quarantine_reasons: Vec::new(),
    };

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let bytes = match read_bounded(&mut entry) {
            Ok(b) => b,
            Err(reason) => {
                report.files_quarantined += 1;
                report.quarantine_reasons.push((name, reason));
                continue;
            }
        };

        match process_member(&name, bytes, output_dir, policy, key, 0) {
            Ok(n) => report.files_processed += n,
            Err(reason) => {
                report.files_quarantined += 1;
                report.quarantine_reasons.push((name, reason));
            }
        }
    }

    Ok(report)
}

fn process_member(
    name: &str,
    bytes: Vec<u8>,
    output_dir: &Path,
    policy: &Policy,
    key: &CohortKey,
    depth: usize,
) -> Result<usize, String> {
    if depth > MAX_NESTING_DEPTH {
        return Err("nested archive exceeds maximum recursion depth".to_string());
    }

    let kind = detect(name, &bytes);
    if matches!(kind, Kind::Zip) {
        return process_nested_zip(bytes, output_dir, policy, key, depth + 1);
    }
    if matches!(kind, Kind::Unknown) {
        return Err(format!("unknown file type: {name}"));
    }
    if matches!(kind, Kind::Office) {
        return Err(format!("office open-xml format not supported: {name}"));
    }

    let out_name = file_name(name);
    let dst = output_dir.join(&out_name);
    if dst.exists() {
        return Err(format!("duplicate output filename collision: {out_name}"));
    }

    let scratch = ScratchDir::new("anon-pbc-member").map_err(|e| e.to_string())?;
    let src = scratch.path().join("in");
    let tmp_out = scratch.path().join("out");
    std::fs::write(&src, &bytes).map_err(|e| e.to_string())?;

    match kind {
        Kind::Pdf => {
            let r = crate::pdf_adapter::sanitize_pdf(&src, &tmp_out, policy)
                .map_err(|e| e.to_string())?;
            if r.quarantined {
                return Err(r
                    .quarantine_reason
                    .unwrap_or_else(|| "pdf quarantined".into()));
            }
        }
        Kind::Csv => {
            crate::sql_adapter::transform_csv(&src, &tmp_out, policy, key)
                .map_err(|e| e.to_string())?;
        }
        Kind::Jsonl => {
            crate::sql_adapter::transform_jsonl(&src, &tmp_out, policy, key)
                .map_err(|e| e.to_string())?;
        }
        Kind::Zip | Kind::Unknown | Kind::Office => unreachable!(),
    }

    std::fs::rename(&tmp_out, &dst).map_err(|e| e.to_string())?;
    Ok(1)
}

fn process_nested_zip(
    bytes: Vec<u8>,
    output_dir: &Path,
    policy: &Policy,
    key: &CohortKey,
    depth: usize,
) -> Result<usize, String> {
    if depth > MAX_NESTING_DEPTH {
        return Err("nested archive exceeds maximum recursion depth".to_string());
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    if archive.len() > MAX_ENTRIES {
        return Err("nested archive exceeds maximum entry count".to_string());
    }

    let scratch = ScratchDir::new("anon-pbc-nested").map_err(|e| e.to_string())?;
    let mut processed = 0;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let member_bytes = read_bounded(&mut entry)?;
        processed += process_member(&name, member_bytes, scratch.path(), policy, key, depth)?;
    }

    let mut staged_entries = Vec::new();
    for entry in std::fs::read_dir(scratch.path()).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let target = output_dir.join(entry.file_name());
        if target.exists() {
            return Err(format!(
                "duplicate output filename collision: {}",
                entry.file_name().to_string_lossy()
            ));
        }
        staged_entries.push((entry.path(), target));
    }

    for (from, to) in staged_entries {
        std::fs::rename(from, to).map_err(|e| e.to_string())?;
    }

    Ok(processed)
}

fn file_name(path: &str) -> String {
    PathBuf::from(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".to_string())
}
