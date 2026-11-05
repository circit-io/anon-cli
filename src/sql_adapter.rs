use crate::crypto::{canonicalize, CohortKey};
use crate::error::AdapterError;
use crate::policy::{Classification, Granularity, Policy, Transform};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformReport {
    pub rows_processed: usize,
    pub fields_withheld: Vec<String>,
    pub fields_transformed: usize,
    pub quarantined_rows: usize,
}

pub fn transform_csv(
    input: &Path,
    output: &Path,
    policy: &Policy,
    key: &CohortKey,
) -> Result<TransformReport, AdapterError> {
    validate_policy(policy)?;

    let mut reader = csv::Reader::from_path(input)?;
    let headers = reader.headers()?.clone();

    let (kept, withheld) = partition_fields(&headers, policy);

    let mut writer = csv::Writer::from_path(output)?;
    writer.write_record(
        kept.iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
    )?;

    let mut report = TransformReport {
        rows_processed: 0,
        fields_withheld: withheld,
        fields_transformed: kept
            .iter()
            .filter(|(_, t)| *t != ColumnAction::Copy)
            .count(),
        quarantined_rows: 0,
    };

    for record in reader.records() {
        let record = record?;
        let row: HashMap<String, serde_json::Value> = headers
            .iter()
            .zip(record.iter())
            .map(|(h, v)| (h.to_string(), serde_json::Value::String(v.to_string())))
            .collect();

        match transform_row(&row, &kept, policy, key) {
            Some(values) => {
                let strings: Vec<String> = values.iter().map(csv_stringify).collect();
                writer.write_record(&strings)?;
                report.rows_processed += 1;
            }
            None => report.quarantined_rows += 1,
        }
    }
    writer.flush()?;
    Ok(report)
}

pub fn transform_jsonl(
    input: &Path,
    output: &Path,
    policy: &Policy,
    key: &CohortKey,
) -> Result<TransformReport, AdapterError> {
    validate_policy(policy)?;

    let content = std::fs::read_to_string(input)?;
    let mut out = std::fs::File::create(output)?;

    let mut all_fields: Vec<String> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line)?;
        if let serde_json::Value::Object(map) = &row {
            for k in map.keys() {
                if !all_fields.contains(k) {
                    all_fields.push(k.clone());
                }
            }
        }
    }

    let kept = partition_field_names(&all_fields, policy);
    let withheld: Vec<String> = all_fields
        .iter()
        .filter(|f| !kept.iter().any(|(k, _)| k == *f))
        .cloned()
        .collect();

    let mut report = TransformReport {
        rows_processed: 0,
        fields_withheld: withheld,
        fields_transformed: kept
            .iter()
            .filter(|(_, t)| *t != ColumnAction::Copy)
            .count(),
        quarantined_rows: 0,
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line)?;
        let obj: HashMap<String, serde_json::Value> = match row {
            serde_json::Value::Object(map) => map.into_iter().collect(),
            _ => return Err(AdapterError::Message("JSONL rows must be objects".into())),
        };

        match transform_row(&obj, &kept, policy, key) {
            Some(values) => {
                let record: serde_json::Map<String, serde_json::Value> = kept
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .zip(values)
                    .map(|(name, value)| (name.to_string(), value))
                    .collect();
                serde_json::to_writer(&mut out, &serde_json::Value::Object(record))?;
                out.write_all(b"\n")?;
                report.rows_processed += 1;
            }
            None => report.quarantined_rows += 1,
        }
    }
    Ok(report)
}

fn csv_stringify(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ColumnAction {
    Pseudonymize(String),
    CoarsenDay,
    CoarsenMonth,
    CoarsenYear,
    Copy,
}

fn validate_policy(policy: &Policy) -> Result<(), AdapterError> {
    if policy.fields.is_empty() {
        return Err(AdapterError::Policy(
            crate::policy::PolicyError::MissingField("fields".into()),
        ));
    }
    Ok(())
}

fn action_for(field: &str, policy: &Policy) -> Option<ColumnAction> {
    let fp = policy.classify(field)?;
    match &fp.transform {
        Transform::Pseudonymize { entity_type } => {
            Some(ColumnAction::Pseudonymize(entity_type.clone()))
        }
        Transform::Coarsen { granularity } => Some(match granularity {
            Granularity::Day => ColumnAction::CoarsenDay,
            Granularity::Month => ColumnAction::CoarsenMonth,
            Granularity::Year => ColumnAction::CoarsenYear,
        }),
        Transform::Preserve { .. } => Some(ColumnAction::Copy),
        Transform::Suppress => None,
    }
}

fn partition_fields(
    headers: &csv::StringRecord,
    policy: &Policy,
) -> (Vec<(String, ColumnAction)>, Vec<String>) {
    let names: Vec<String> = headers.iter().map(str::to_string).collect();
    let kept = partition_field_names(&names, policy);
    let withheld = names
        .iter()
        .filter(|f| !kept.iter().any(|(k, _)| k == *f))
        .cloned()
        .collect();
    (kept, withheld)
}

fn partition_field_names(names: &[String], policy: &Policy) -> Vec<(String, ColumnAction)> {
    names
        .iter()
        .filter_map(|name| action_for(name, policy).map(|action| (name.clone(), action)))
        .collect()
}

fn transform_row(
    row: &HashMap<String, serde_json::Value>,
    kept: &[(String, ColumnAction)],
    policy: &Policy,
    key: &CohortKey,
) -> Option<Vec<serde_json::Value>> {
    let mut out = Vec::with_capacity(kept.len());
    for (name, action) in kept {
        let value = row.get(name).cloned().unwrap_or(serde_json::Value::Null);
        let transformed = match action {
            ColumnAction::Pseudonymize(entity_type) => {
                let raw = json_scalar_to_string(&value);
                if raw.is_empty() {
                    return None;
                }
                serde_json::Value::String(key.pseudonymize_for(&canonicalize(&raw), entity_type))
            }
            ColumnAction::CoarsenDay => coarsen_value(&value, Granularity::Day)?,
            ColumnAction::CoarsenMonth => coarsen_value(&value, Granularity::Month)?,
            ColumnAction::CoarsenYear => coarsen_value(&value, Granularity::Year)?,
            ColumnAction::Copy => {
                let fp = policy.classify(name)?;
                match &fp.transform {
                    Transform::Preserve { precision } => {
                        preserve_value(value, *precision, fp.classification)?
                    }
                    _ => value,
                }
            }
        };
        out.push(transformed);
    }
    Some(out)
}

fn json_scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn preserve_value(
    value: serde_json::Value,
    precision: Option<u32>,
    classification: Classification,
) -> Option<serde_json::Value> {
    if value.is_null() {
        return Some(value);
    }
    if classification != Classification::FinancialInvariant {
        return Some(value);
    }
    let raw = json_scalar_to_string(&value);
    let decimal: Decimal = raw.parse().ok()?;
    match precision {
        Some(p) => {
            let rounded = decimal.round_dp(p);
            let repr = rounded.to_string();
            let number: serde_json::Number = repr.parse().ok()?;
            Some(serde_json::Value::Number(number))
        }
        None => Some(value),
    }
}

fn coarsen_value(value: &serde_json::Value, granularity: Granularity) -> Option<serde_json::Value> {
    if value.is_null() {
        return None;
    }
    let raw = json_scalar_to_string(value);
    coarsen(&raw, granularity).map(serde_json::Value::String)
}

fn coarsen(date: &str, granularity: Granularity) -> Option<String> {
    let parts: Vec<&str> = date.split('-').collect();
    let (year, month, day) = match parts.as_slice() {
        [y, m, d] => (*y, *m, *d),
        [y, m] if granularity == Granularity::Month => (*y, *m, ""),
        [y] if granularity == Granularity::Year => (*y, "", ""),
        _ => return None,
    };
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match granularity {
        Granularity::Day => {
            if month.len() == 2
                && day.len() == 2
                && month.chars().all(|c| c.is_ascii_digit())
                && day.chars().all(|c| c.is_ascii_digit())
            {
                Some(format!("{year}-{month}-{day}"))
            } else {
                None
            }
        }
        Granularity::Month => {
            if month.len() == 2 && month.chars().all(|c| c.is_ascii_digit()) {
                Some(format!("{year}-{month}"))
            } else {
                None
            }
        }
        Granularity::Year => Some(year.to_string()),
    }
}
