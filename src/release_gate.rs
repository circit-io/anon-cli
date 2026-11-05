use crate::sql_adapter::TransformReport;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub policy_version: String,
    pub key_fingerprint: String,
    pub timestamp: String,
    pub reports: Vec<TransformReport>,
    pub validation_results: ValidationResults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    pub synthetic_fixture_pass: bool,
    pub accounting_consistency_pass: bool,
    pub no_withheld_field_leak: bool,
}

impl ValidationResults {
    pub fn all_pass(&self) -> bool {
        self.synthetic_fixture_pass
            && self.accounting_consistency_pass
            && self.no_withheld_field_leak
    }

    fn failed_names(&self) -> Vec<&'static str> {
        let mut failed = Vec::new();
        if !self.synthetic_fixture_pass {
            failed.push("synthetic_fixture");
        }
        if !self.accounting_consistency_pass {
            failed.push("accounting_consistency");
        }
        if !self.no_withheld_field_leak {
            failed.push("no_withheld_field_leak");
        }
        failed
    }
}

pub struct ReleaseGate {
    staging_dir: PathBuf,
    quarantine_dir: PathBuf,
    release_dir: PathBuf,
}

pub enum ReleaseOutcome {
    Released(PathBuf),
    Quarantined(String),
}

impl ReleaseGate {
    pub fn new(
        staging_dir: impl AsRef<Path>,
        quarantine_dir: impl AsRef<Path>,
        release_dir: impl AsRef<Path>,
    ) -> Self {
        ReleaseGate {
            staging_dir: staging_dir.as_ref().to_path_buf(),
            quarantine_dir: quarantine_dir.as_ref().to_path_buf(),
            release_dir: release_dir.as_ref().to_path_buf(),
        }
    }

    pub fn attempt_release(&self, manifest: ReleaseManifest) -> Result<ReleaseOutcome, GateError> {
        if !manifest.validation_results.all_pass() {
            let failed = manifest.validation_results.failed_names().join(", ");
            self.quarantine_all()?;
            return Ok(ReleaseOutcome::Quarantined(format!(
                "validation failed: {failed}"
            )));
        }

        std::fs::create_dir_all(&self.release_dir)?;
        if self.staging_dir.exists() {
            for entry in std::fs::read_dir(&self.staging_dir)? {
                let entry = entry?;
                let target = self.release_dir.join(entry.file_name());
                std::fs::rename(entry.path(), target)?;
            }
        }
        let path = self.release_dir.join("release-manifest.json");
        std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
        Ok(ReleaseOutcome::Released(path))
    }

    fn quarantine_all(&self) -> Result<(), GateError> {
        std::fs::create_dir_all(&self.quarantine_dir)?;
        if !self.staging_dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.staging_dir)? {
            let entry = entry?;
            let target = self.quarantine_dir.join(entry.file_name());
            std::fs::rename(entry.path(), target)?;
        }
        Ok(())
    }
}
