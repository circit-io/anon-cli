use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("missing required policy field: {0}")]
    MissingField(String),
    #[error("unknown classification: {0}")]
    UnknownClassification(String),
    #[error("unknown transform: {0}")]
    UnknownTransform(String),
    #[error("invalid granularity: {0}")]
    InvalidGranularity(String),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    DirectIdentifier,
    QuasiIdentifier,
    FinancialInvariant,
    FreeText,
    NonSensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    Day,
    Month,
    Year,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "transform", rename_all = "snake_case")]
pub enum Transform {
    Pseudonymize { entity_type: String },
    Coarsen { granularity: Granularity },
    Suppress,
    Preserve { precision: Option<u32> },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FieldPolicy {
    pub classification: Classification,
    #[serde(flatten)]
    pub transform: Transform,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub version: String,
    pub tenant: String,
    pub purpose: String,
    pub fields: HashMap<String, FieldPolicy>,
}

#[derive(Debug, Deserialize)]
struct RawFieldPolicy {
    classification: String,
    #[serde(flatten)]
    transform: serde_yaml::Value,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    version: Option<String>,
    tenant: Option<String>,
    purpose: Option<String>,
    fields: Option<HashMap<String, RawFieldPolicy>>,
}

fn parse_classification(raw: &str) -> Result<Classification, PolicyError> {
    match raw {
        "direct_identifier" => Ok(Classification::DirectIdentifier),
        "quasi_identifier" => Ok(Classification::QuasiIdentifier),
        "financial_invariant" => Ok(Classification::FinancialInvariant),
        "free_text" => Ok(Classification::FreeText),
        "non_sensitive" => Ok(Classification::NonSensitive),
        other => Err(PolicyError::UnknownClassification(other.to_string())),
    }
}

fn parse_transform(raw: &RawFieldPolicy) -> Result<Transform, PolicyError> {
    let name = raw
        .transform
        .get("transform")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PolicyError::MissingField("transform".to_string()))?;

    let get_str = |key: &str| -> Result<String, PolicyError> {
        raw.transform
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| PolicyError::MissingField(key.to_string()))
    };

    match name {
        "pseudonymize" => Ok(Transform::Pseudonymize {
            entity_type: get_str("entity_type")?,
        }),
        "coarsen" => {
            let granularity = get_str("granularity")?;
            let granularity = match granularity.as_str() {
                "day" => Granularity::Day,
                "month" => Granularity::Month,
                "year" => Granularity::Year,
                other => return Err(PolicyError::InvalidGranularity(other.to_string())),
            };
            Ok(Transform::Coarsen { granularity })
        }
        "suppress" => Ok(Transform::Suppress),
        "preserve" => {
            let precision = raw
                .transform
                .get("precision")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32);
            Ok(Transform::Preserve { precision })
        }
        other => Err(PolicyError::UnknownTransform(other.to_string())),
    }
}

impl Policy {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let raw: RawPolicy = serde_yaml::from_str(yaml)?;

        let version = raw
            .version
            .ok_or_else(|| PolicyError::MissingField("version".to_string()))?;
        let tenant = raw
            .tenant
            .ok_or_else(|| PolicyError::MissingField("tenant".to_string()))?;
        let purpose = raw
            .purpose
            .ok_or_else(|| PolicyError::MissingField("purpose".to_string()))?;
        let raw_fields = raw
            .fields
            .ok_or_else(|| PolicyError::MissingField("fields".to_string()))?;

        let mut fields = HashMap::new();
        for (name, raw_field) in raw_fields {
            let classification = parse_classification(&raw_field.classification)?;
            let transform = parse_transform(&raw_field)?;
            fields.insert(
                name,
                FieldPolicy {
                    classification,
                    transform,
                },
            );
        }

        Ok(Policy {
            version,
            tenant,
            purpose,
            fields,
        })
    }

    pub fn classify(&self, field: &str) -> Option<&FieldPolicy> {
        self.fields.get(field)
    }

    pub fn is_withheld(&self, field: &str) -> bool {
        self.classify(field).is_none()
    }
}
