use anon_cli::release_gate::{ReleaseGate, ReleaseManifest, ReleaseOutcome, ValidationResults};
use anon_cli::sql_adapter::TransformReport;
use std::path::PathBuf;

fn tmp(name: String) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn manifest(all_pass: bool) -> ReleaseManifest {
    ReleaseManifest {
        policy_version: "1.0".to_string(),
        key_fingerprint: "ab".repeat(32),
        timestamp: "2024-03-15T10:00:00Z".to_string(),
        reports: vec![TransformReport {
            rows_processed: 10,
            fields_withheld: vec!["internal_note".to_string()],
            fields_transformed: 3,
            quarantined_rows: 0,
        }],
        validation_results: ValidationResults {
            synthetic_fixture_pass: all_pass,
            accounting_consistency_pass: all_pass,
            no_withheld_field_leak: all_pass,
        },
    }
}

fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let staging = tmp(format!("{name}-staging"));
    let quarantine = tmp(format!("{name}-quarantine"));
    let release = tmp(format!("{name}-release"));
    std::fs::remove_dir_all(&staging).ok();
    std::fs::remove_dir_all(&quarantine).ok();
    std::fs::remove_dir_all(&release).ok();
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::create_dir_all(&quarantine).unwrap();
    std::fs::create_dir_all(&release).unwrap();
    (staging, quarantine, release)
}

#[test]
fn all_validations_pass_releases_manifest() {
    let (staging, quarantine, release) = setup("anon-gate-ok");
    std::fs::write(staging.join("output.csv"), "customer_id,amount\nxyz,1.00\n").unwrap();

    let gate = ReleaseGate::new(&staging, &quarantine, &release);
    let outcome = gate.attempt_release(manifest(true)).unwrap();

    let path = match outcome {
        ReleaseOutcome::Released(p) => p,
        ReleaseOutcome::Quarantined(r) => panic!("expected release, got quarantine: {r}"),
    };
    assert!(path.starts_with(&release));

    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved["policy_version"], "1.0");
    assert_eq!(saved["key_fingerprint"], "ab".repeat(32));
    assert_eq!(saved["validation_results"]["synthetic_fixture_pass"], true);
    assert_eq!(saved["reports"][0]["rows_processed"], 10);
    assert!(saved["timestamp"].is_string());
}

#[test]
fn validation_failure_quarantines_no_manifest() {
    let (staging, quarantine, release) = setup("anon-gate-fail");
    std::fs::write(staging.join("output.csv"), "data\n").unwrap();

    let gate = ReleaseGate::new(&staging, &quarantine, &release);
    let outcome = gate.attempt_release(manifest(false)).unwrap();

    match outcome {
        ReleaseOutcome::Quarantined(reason) => assert!(!reason.is_empty()),
        ReleaseOutcome::Released(p) => panic!("expected quarantine, got release: {}", p.display()),
    }

    assert!(
        release.read_dir().unwrap().next().is_none(),
        "release dir must stay empty"
    );

    let quarantined: Vec<_> = quarantine.read_dir().unwrap().collect();
    assert_eq!(quarantined.len(), 1, "staging content must be quarantined");
    assert!(quarantine.join("output.csv").exists());
}

#[test]
fn partial_failure_quarantines_entire_run() {
    let (staging, quarantine, release) = setup("anon-gate-partial");
    std::fs::write(staging.join("a.csv"), "x\n").unwrap();
    std::fs::write(staging.join("b.csv"), "y\n").unwrap();

    let mut m = manifest(true);
    m.validation_results.accounting_consistency_pass = false;

    let gate = ReleaseGate::new(&staging, &quarantine, &release);
    let outcome = gate.attempt_release(m).unwrap();
    assert!(
        matches!(outcome, ReleaseOutcome::Quarantined(_)),
        "fail-closed required"
    );

    assert!(quarantine.join("a.csv").exists());
    assert!(quarantine.join("b.csv").exists());
    assert!(release.read_dir().unwrap().next().is_none());
}

#[test]
fn manifest_never_contains_raw_key() {
    let (staging, quarantine, release) = setup("anon-gate-key");
    let gate = ReleaseGate::new(&staging, &quarantine, &release);
    let outcome = gate.attempt_release(manifest(true)).unwrap();
    let path = match outcome {
        ReleaseOutcome::Released(p) => p,
        _ => panic!("expected release"),
    };
    let text = std::fs::read_to_string(path).unwrap();
    assert!(!text.contains("key_hex"), "manifest must not embed the key");
    assert!(text.contains("key_fingerprint"));
}

#[test]
fn passing_release_publishes_staged_artifacts() {
    let (staging, quarantine, release) = setup("anon-gate-publish");
    std::fs::write(staging.join("output.csv"), "customer_id,amount\nxyz,1.00\n").unwrap();
    let gate = ReleaseGate::new(&staging, &quarantine, &release);
    let outcome = gate.attempt_release(manifest(true)).unwrap();
    assert!(matches!(outcome, ReleaseOutcome::Released(_)));
    assert!(
        release.join("output.csv").exists(),
        "staged artifact must be published to release_dir"
    );
}
