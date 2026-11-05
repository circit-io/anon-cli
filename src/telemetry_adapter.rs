use crate::crypto::{canonicalize, CohortKey};
use crate::error::AdapterError;
use crate::policy::{Granularity, Policy, Transform};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryAllowlist {
    pub allowed_attributes: HashSet<String>,
    pub pseudonymize_attributes: HashSet<String>,
    pub entity_types: HashMap<String, String>,
    pub coarsen_attributes: HashMap<String, Granularity>,
}

impl TelemetryAllowlist {
    pub fn from_policy(policy: &Policy) -> Self {
        let mut allowed = HashSet::new();
        let mut pseudonymize = HashSet::new();
        let mut entity_types = HashMap::new();
        let mut coarsen_attributes = HashMap::new();
        for (name, field) in &policy.fields {
            match &field.transform {
                Transform::Preserve { .. } => {
                    allowed.insert(name.clone());
                }
                Transform::Pseudonymize { entity_type } => {
                    allowed.insert(name.clone());
                    pseudonymize.insert(name.clone());
                    entity_types.insert(name.clone(), entity_type.clone());
                }
                Transform::Coarsen { granularity } => {
                    allowed.insert(name.clone());
                    coarsen_attributes.insert(name.clone(), *granularity);
                }
                Transform::Suppress => {}
            }
        }
        TelemetryAllowlist {
            allowed_attributes: allowed,
            pseudonymize_attributes: pseudonymize,
            entity_types,
            coarsen_attributes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub records_processed: usize,
    pub attributes_removed: usize,
    pub attributes_pseudonymized: usize,
}

pub fn filter_telemetry(
    input: &Path,
    output: &Path,
    allowlist: &TelemetryAllowlist,
    key: &CohortKey,
) -> Result<TelemetryReport, AdapterError> {
    let content = std::fs::read_to_string(input)?;
    let mut out = std::fs::File::create(output)?;

    let mut report = TelemetryReport {
        records_processed: 0,
        attributes_removed: 0,
        attributes_pseudonymized: 0,
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(line)?;
        let obj = match record {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(AdapterError::Message(
                    "telemetry records must be objects".into(),
                ))
            }
        };

        let mut filtered = serde_json::Map::new();
        for (attr, value) in obj {
            let lower = attr.to_lowercase();
            if lower.starts_with("baggage") {
                report.attributes_removed += 1;
                continue;
            }
            if !allowlist.allowed_attributes.contains(&attr) {
                report.attributes_removed += 1;
                continue;
            }
            if let Some(entity_type) = allowlist.entity_types.get(&attr) {
                let raw = scalar_to_string(&value);
                filtered.insert(
                    attr.clone(),
                    serde_json::Value::String(
                        key.pseudonymize_for(&canonicalize(&raw), entity_type),
                    ),
                );
                report.attributes_pseudonymized += 1;
            } else if let Some(granularity) = allowlist.coarsen_attributes.get(&attr) {
                let raw = scalar_to_string(&value);
                match coarsen_date(&raw, *granularity) {
                    Some(coarsened) => {
                        filtered.insert(attr, serde_json::Value::String(coarsened));
                    }
                    None => {
                        report.attributes_removed += 1;
                    }
                }
            } else {
                filtered.insert(attr, value);
            }
        }

        serde_json::to_writer(&mut out, &serde_json::Value::Object(filtered))?;
        out.write_all(b"\n")?;
        report.records_processed += 1;
    }

    Ok(report)
}

fn scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn coarsen_date(raw: &str, granularity: Granularity) -> Option<String> {
    let parts: Vec<&str> = raw.split('-').collect();
    let (year, month, day) = match parts.as_slice() {
        [y, m, d] => (*y, *m, *d),
        [y, m] if granularity == Granularity::Month => (*y, *m, ""),
        [y] if granularity == Granularity::Year => (*y, "", ""),
        _ => return None,
    };
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let valid_month = month.len() == 2 && month.chars().all(|c| c.is_ascii_digit());
    match granularity {
        Granularity::Day => {
            if valid_month && day.len() == 2 && day.chars().all(|c| c.is_ascii_digit()) {
                Some(format!("{year}-{month}-{day}"))
            } else {
                None
            }
        }
        Granularity::Month => {
            if valid_month {
                Some(format!("{year}-{month}"))
            } else {
                None
            }
        }
        Granularity::Year => Some(year.to_string()),
    }
}
