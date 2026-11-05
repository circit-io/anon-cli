use anon_cli::crypto::CohortKey;
use anon_cli::pbc_adapter::process_archive;
use anon_cli::policy::Policy;
use anon_cli::release_gate::{ReleaseGate, ReleaseManifest, ReleaseOutcome, ValidationResults};
use anon_cli::sql_adapter::{transform_csv, transform_jsonl, TransformReport};
use anon_cli::telemetry_adapter::{filter_telemetry, TelemetryAllowlist};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "anon-cli", about = "Anonymization pipeline CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Transform SQL snapshot (CSV/JSONL)
    Sql {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        policy: PathBuf,
        /// Persistent key file; if absent, a fresh key is generated
        #[arg(short, long)]
        key_file: Option<PathBuf>,
        /// Write the JSON adapter report here (stage as *-report.json for release)
        #[arg(long)]
        report_file: Option<PathBuf>,
    },
    /// Sanitize PDF document
    Pdf {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        policy: PathBuf,
        #[arg(short, long)]
        key_file: Option<PathBuf>,
        /// Replace visible text: "raw text:entity_type" (repeatable)
        #[arg(short, long)]
        redact: Vec<String>,
        /// Write the JSON adapter report here (stage as *-report.json for release)
        #[arg(long)]
        report_file: Option<PathBuf>,
    },
    /// Process PBC archive
    Pbc {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        policy: PathBuf,
        #[arg(short, long)]
        key_file: Option<PathBuf>,
        /// Write the JSON adapter report here (stage as *-report.json for release)
        #[arg(long)]
        report_file: Option<PathBuf>,
    },
    /// Filter telemetry export
    Telemetry {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        policy: PathBuf,
        #[arg(short, long)]
        key_file: Option<PathBuf>,
        /// Write the JSON adapter report here (stage as *-report.json for release)
        #[arg(long)]
        report_file: Option<PathBuf>,
    },
    /// Generate fresh cohort key
    Keygen {
        #[arg(short, long)]
        tenant: String,
        #[arg(short, long)]
        purpose: String,
        #[arg(short, long)]
        entity_type: String,
        #[arg(short = 'v', long)]
        policy_version: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Run release gate validation
    Release {
        #[arg(short, long)]
        staging: PathBuf,
        #[arg(short, long)]
        release_dir: PathBuf,
        #[arg(short, long)]
        quarantine_dir: PathBuf,
        #[arg(short, long)]
        policy_version: String,
        #[arg(short, long)]
        key_fingerprint: String,
        #[arg(long, default_value_t = false)]
        synthetic_fixture_pass: bool,
        #[arg(long, default_value_t = false)]
        accounting_consistency_pass: bool,
        #[arg(long, default_value_t = false)]
        no_withheld_field_leak: bool,
    },
}

fn load_policy(path: &PathBuf) -> Result<Policy> {
    let yaml = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;
    Policy::from_yaml(&yaml).context("parsing policy")
}

fn load_or_generate_key(key_file: &Option<PathBuf>, policy: &Policy) -> Result<CohortKey> {
    match key_file {
        Some(path) => {
            let json = std::fs::read_to_string(path)
                .with_context(|| format!("reading key file {}", path.display()))?;
            let key = CohortKey::from_key_file_json(&json).context("parsing key file")?;
            key.validate_policy(policy)
                .context("validating key file against policy")?;
            Ok(key)
        }
        None => Ok(CohortKey::generate(
            &policy.tenant,
            &policy.purpose,
            "default",
            &policy.version,
        )),
    }
}

fn print_report<T: serde::Serialize>(report: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn write_report_file<T: serde::Serialize>(path: &Option<PathBuf>, report: &T) -> Result<()> {
    if let Some(path) = path {
        std::fs::write(path, serde_json::to_string_pretty(report)?)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sql {
            input,
            output,
            policy,
            key_file,
            report_file,
        } => {
            let policy = load_policy(&policy)?;
            let key = load_or_generate_key(&key_file, &policy)?;
            let report: TransformReport = if input.extension().is_some_and(|e| e == "jsonl") {
                transform_jsonl(&input, &output, &policy, &key)?
            } else {
                transform_csv(&input, &output, &policy, &key)?
            };
            print_report(&report)?;
            write_report_file(&report_file, &report)?;
        }
        Commands::Pdf {
            input,
            output,
            policy,
            key_file,
            redact,
            report_file,
        } => {
            let policy = load_policy(&policy)?;
            let key = load_or_generate_key(&key_file, &policy)?;
            let redactions = parse_redactions(&redact)?;
            let report = anon_cli::pdf_adapter::sanitize_pdf_with_redactions(
                &input,
                &output,
                &policy,
                Some(&key),
                &redactions,
            )?;
            print_report(&report)?;
            write_report_file(&report_file, &report)?;
        }
        Commands::Pbc {
            input,
            output,
            policy,
            key_file,
            report_file,
        } => {
            let policy = load_policy(&policy)?;
            let key = load_or_generate_key(&key_file, &policy)?;
            let report = process_archive(&input, &output, &policy, &key)?;
            print_report(&report)?;
            write_report_file(&report_file, &report)?;
        }
        Commands::Telemetry {
            input,
            output,
            policy,
            key_file,
            report_file,
        } => {
            let policy = load_policy(&policy)?;
            let key = load_or_generate_key(&key_file, &policy)?;
            let allowlist = TelemetryAllowlist::from_policy(&policy);
            let report = filter_telemetry(&input, &output, &allowlist, &key)?;
            print_report(&report)?;
            write_report_file(&report_file, &report)?;
        }
        Commands::Keygen {
            tenant,
            purpose,
            entity_type,
            policy_version,
            output,
        } => {
            let key = CohortKey::generate(&tenant, &purpose, &entity_type, &policy_version);
            write_private_key_file(&output, &key.to_key_file_json()?)?;
            println!("key written to {}", output.display());
        }
        Commands::Release {
            staging,
            release_dir,
            quarantine_dir,
            policy_version,
            key_fingerprint,
            synthetic_fixture_pass,
            accounting_consistency_pass,
            no_withheld_field_leak,
        } => {
            let reports = load_staged_reports(&staging)?;
            let manifest = ReleaseManifest {
                policy_version,
                key_fingerprint,
                timestamp: chrono_now(),
                reports,
                validation_results: ValidationResults {
                    synthetic_fixture_pass,
                    accounting_consistency_pass,
                    no_withheld_field_leak,
                },
            };
            let gate = ReleaseGate::new(&staging, &quarantine_dir, &release_dir);
            match gate.attempt_release(manifest)? {
                ReleaseOutcome::Released(path) => println!("released: {}", path.display()),
                ReleaseOutcome::Quarantined(reason) => {
                    println!("quarantined: {reason}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

fn write_private_key_file(path: &PathBuf, contents: &str) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok() {
        anyhow::bail!(
            "refusing to overwrite existing key path: {}",
            path.display()
        );
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating key file {}", path.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn load_staged_reports(staging: &PathBuf) -> Result<Vec<TransformReport>> {
    let mut reports = Vec::new();
    let entries = std::fs::read_dir(staging)
        .with_context(|| format!("reading staging dir {}", staging.display()))?;
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json")
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with("-report.json"))
        {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading report {}", path.display()))?;
            reports.push(
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing report {}", path.display()))?,
            );
        }
    }
    if reports.is_empty() {
        anyhow::bail!(
            "no *-report.json adapter reports found in {}; run transforms with --report-file or stage reports before release",
            staging.display()
        );
    }
    Ok(reports)
}

fn parse_redactions(specs: &[String]) -> Result<Vec<(String, String)>> {
    specs
        .iter()
        .map(|s| {
            s.rsplit_once(':')
                .map(|(text, entity)| (text.to_string(), entity.to_string()))
                .with_context(|| {
                    format!("invalid --redact value {s:?}; expected \"text:entity_type\"")
                })
        })
        .collect()
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}
