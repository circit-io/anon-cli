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
#[command(name = "anon-cli", version, about = "Anonymization pipeline CLI")]
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
    /// Benchmark throughput at scale (generate N rows, transform, report rows/sec)
    Bench {
        #[arg(short, long)]
        policy: PathBuf,
        #[arg(short, long)]
        key_file: Option<PathBuf>,
        /// Number of rows to generate and process
        #[arg(short, long, default_value_t = 100_000)]
        rows: usize,
        /// Batch size for batched mode (0 = single batch)
        #[arg(short, long, default_value_t = 0)]
        batch_size: usize,
        /// Temp directory for generated files
        #[arg(long)]
        tmpdir: Option<PathBuf>,
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
        Commands::Bench {
            policy,
            key_file,
            rows,
            batch_size,
            tmpdir,
        } => {
            let policy = load_policy(&policy)?;
            let key = load_or_generate_key(&key_file, &policy)?;
            let tmpdir = tmpdir.unwrap_or_else(|| {
                std::env::temp_dir().join(format!("anon-cli-bench-{}", std::process::id()))
            });
            std::fs::create_dir_all(&tmpdir)?;

            if batch_size > 0 {
                let results =
                    anon_cli::bench::run_batched_bench(rows, batch_size, &policy, &key, &tmpdir)?;
                let total_processed: usize = results.iter().map(|r| r.rows_processed).sum();
                let total_secs: f64 = results.iter().map(|r| r.elapsed_secs).sum();
                let total_input: usize = results.iter().map(|r| r.input_bytes).sum();
                let aggregate_rps = if total_secs > 0.0 {
                    total_processed as f64 / total_secs
                } else {
                    0.0
                };
                let aggregate_mbps = if total_secs > 0.0 {
                    (total_input as f64 / 1_048_576.0) / total_secs
                } else {
                    0.0
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "mode": "batched",
                        "total_rows": rows,
                        "batch_size": batch_size,
                        "batches": results.len(),
                        "total_processed": total_processed,
                        "total_secs": total_secs,
                        "aggregate_rows_per_sec": aggregate_rps,
                        "aggregate_throughput_mbps": aggregate_mbps,
                        "batch_details": results,
                    }))?
                );
            } else {
                let result = anon_cli::bench::run_csv_bench(rows, &policy, &key, &tmpdir)?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            let _ = std::fs::remove_dir_all(&tmpdir);
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
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let (text, entity) = s
            .rsplit_once(':')
            .with_context(|| format!("invalid --redact value {s:?}; expected \"text:entity_type\""))?;
        anon_cli::roster::validate_entry(text, entity)
            .map_err(|e| anyhow::anyhow!("invalid --redact value {s:?}: {e}"))?;
        out.push((text.to_string(), entity.to_string()));
    }
    Ok(out)
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}
