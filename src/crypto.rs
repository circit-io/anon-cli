use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key file: {0}")]
    InvalidKeyFile(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct CohortKey {
    key: [u8; 32],
    tenant: String,
    purpose: String,
    entity_type: String,
    policy_version: String,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    key_hex: String,
    tenant: String,
    purpose: String,
    entity_type: String,
    policy_version: String,
}

pub fn canonicalize(input: &str) -> String {
    let nfkc: String = input.nfkc().collect();
    nfkc.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

impl CohortKey {
    pub fn generate(tenant: &str, purpose: &str, entity_type: &str, policy_version: &str) -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        CohortKey {
            key,
            tenant: tenant.to_string(),
            purpose: purpose.to_string(),
            entity_type: entity_type.to_string(),
            policy_version: policy_version.to_string(),
        }
    }

    pub fn from_raw(
        key: [u8; 32],
        tenant: &str,
        purpose: &str,
        entity_type: &str,
        policy_version: &str,
    ) -> Self {
        CohortKey {
            key,
            tenant: tenant.to_string(),
            purpose: purpose.to_string(),
            entity_type: entity_type.to_string(),
            policy_version: policy_version.to_string(),
        }
    }

    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn domain_separator(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.tenant, self.purpose, self.entity_type, self.policy_version
        )
    }

    pub fn pseudonymize(&self, canonical_identity: &str) -> String {
        self.pseudonymize_for(canonical_identity, &self.entity_type)
    }

    pub fn pseudonymize_for(&self, canonical_identity: &str, entity_type: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        let canonical = canonicalize(canonical_identity);
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.tenant.len(),
            self.tenant,
            self.purpose.len(),
            self.purpose,
            entity_type.len(),
            entity_type,
            self.policy_version.len(),
            self.policy_version,
            canonical.len(),
            canonical
        );
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn validate_policy(&self, policy: &crate::policy::Policy) -> Result<(), CryptoError> {
        if self.tenant != policy.tenant
            || self.purpose != policy.purpose
            || self.policy_version != policy.version
        {
            return Err(CryptoError::InvalidKeyFile(format!(
                "key domain ({}:{}:{}) does not match policy ({}:{}:{})",
                self.tenant,
                self.purpose,
                self.policy_version,
                policy.tenant,
                policy.purpose,
                policy.version
            )));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.key))
    }

    pub fn to_key_file_json(&self) -> Result<String, CryptoError> {
        let file = KeyFile {
            key_hex: hex::encode(self.key),
            tenant: self.tenant.clone(),
            purpose: self.purpose.clone(),
            entity_type: self.entity_type.clone(),
            policy_version: self.policy_version.clone(),
        };
        Ok(serde_json::to_string_pretty(&file)?)
    }

    pub fn from_key_file_json(json: &str) -> Result<Self, CryptoError> {
        let file: KeyFile = serde_json::from_str(json)?;
        let key_bytes = hex::decode(&file.key_hex)
            .map_err(|e| CryptoError::InvalidKeyFile(format!("bad key_hex: {e}")))?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyFile("key must be 32 bytes".to_string()))?;
        Ok(CohortKey::from_raw(
            key,
            &file.tenant,
            &file.purpose,
            &file.entity_type,
            &file.policy_version,
        ))
    }
}
