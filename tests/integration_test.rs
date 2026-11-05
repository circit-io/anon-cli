use anon_cli::crypto::CohortKey;
use anon_cli::pbc_adapter::process_archive;
use anon_cli::pdf_adapter::sanitize_pdf;
use anon_cli::policy::Policy;
use anon_cli::release_gate::{ReleaseGate, ReleaseManifest, ReleaseOutcome, ValidationResults};
use anon_cli::sql_adapter::transform_csv;
use anon_cli::telemetry_adapter::{filter_telemetry, TelemetryAllowlist};
use lopdf::{Dictionary, Document, Object};
use std::io::Write;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn minimal_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let page = doc.add_object(Object::Dictionary(Dictionary::new()));
    let pages = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Pages".to_vec())),
        (
            "Kids".to_string(),
            Object::Array(vec![Object::Reference(page)]),
        ),
        ("Count".to_string(), Object::Integer(1)),
    ]);
    let pages_id = doc.add_object(Object::Dictionary(pages));
    let catalog = Dictionary::from_iter(vec![
        ("Type".to_string(), Object::Name(b"Catalog".to_vec())),
        ("Pages".to_string(), Object::Reference(pages_id)),
    ]);
    let catalog_id = doc.add_object(Object::Dictionary(catalog));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    let path = tmp("anon-int-src.pdf");
    doc.save(&path).unwrap();
    std::fs::read(&path).unwrap()
}

#[test]
fn end_to_end_pipeline() {
    let policy =
        Policy::from_yaml(&std::fs::read_to_string(fixture("policy_valid.yaml")).unwrap()).unwrap();
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");

    let staging = tmp("anon-int-staging");
    std::fs::remove_dir_all(&staging).ok();
    std::fs::create_dir_all(&staging).unwrap();
    let csv_out = staging.join("transactions.csv");
    let report =
        transform_csv(&fixture("sample_transactions.csv"), &csv_out, &policy, &key).unwrap();
    assert_eq!(report.rows_processed, 3);
    let csv_text = std::fs::read_to_string(&csv_out).unwrap();
    assert!(!csv_text.contains("cust-1"));
    assert!(csv_text.contains("1500.25"));
    assert!(!csv_text.contains("description"));

    let pdf_in = tmp("anon-int-in.pdf");
    std::fs::write(&pdf_in, minimal_pdf()).unwrap();
    let pdf_out = staging.join("doc.pdf");
    let pdf_report = sanitize_pdf(&pdf_in, &pdf_out, &policy).unwrap();
    assert!(!pdf_report.quarantined);

    let zip_path = tmp("anon-int-pbc.zip");
    let zip_file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(zip_file);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
    zip.start_file("ledger.jsonl", options).unwrap();
    zip.write_all(b"{\"customer_id\":\"cust-5\",\"amount\":\"3.00\",\"currency\":\"EUR\"}\n")
        .unwrap();
    zip.start_file("binary.exe", options).unwrap();
    zip.write_all(b"\x7fELF unknown").unwrap();
    zip.finish().unwrap();
    let pbc_out = tmp("anon-int-pbc-out");
    std::fs::remove_dir_all(&pbc_out).ok();
    let pbc_report = process_archive(&zip_path, &pbc_out, &policy, &key).unwrap();
    assert_eq!(pbc_report.files_processed, 1);
    assert_eq!(pbc_report.files_quarantined, 1);

    let allowlist = TelemetryAllowlist::from_policy(&policy);
    let telem_out = staging.join("telemetry.jsonl");
    let telem_report = filter_telemetry(
        &fixture("sample_telemetry.jsonl"),
        &telem_out,
        &allowlist,
        &key,
    )
    .unwrap();
    assert_eq!(telem_report.records_processed, 2);

    let release_dir = tmp("anon-int-release");
    let quarantine_dir = tmp("anon-int-quarantine");
    std::fs::remove_dir_all(&release_dir).ok();
    std::fs::remove_dir_all(&quarantine_dir).ok();
    let gate = ReleaseGate::new(&staging, &quarantine_dir, &release_dir);
    let manifest = ReleaseManifest {
        policy_version: policy.version.clone(),
        key_fingerprint: key.fingerprint(),
        timestamp: "unix:0".to_string(),
        reports: vec![report],
        validation_results: ValidationResults {
            synthetic_fixture_pass: true,
            accounting_consistency_pass: true,
            no_withheld_field_leak: true,
        },
    };
    let outcome = gate.attempt_release(manifest).unwrap();
    let manifest_path = match outcome {
        ReleaseOutcome::Released(p) => p,
        ReleaseOutcome::Quarantined(r) => panic!("expected release, got: {r}"),
    };
    let saved = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(saved.contains("key_fingerprint"));
    assert!(!saved.contains("key_hex"));
}
