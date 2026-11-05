use anon_cli::crypto::CohortKey;
use anon_cli::pbc_adapter::process_archive;
use anon_cli::pdf_adapter::sanitize_pdf;
use anon_cli::policy::Policy;
use anon_cli::sql_adapter::{transform_csv, transform_jsonl};
use anon_cli::telemetry_adapter::{filter_telemetry, TelemetryAllowlist};
use rust_decimal::Decimal;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[test]
fn real_sec_edgar_and_form10k_differential_verification() {
    let base = PathBuf::from("/tmp/sec-fin-docs");
    if !base.join("sec_edgar_cash_snapshots.csv").exists() {
        return;
    }

    let policy_yaml = std::fs::read_to_string(base.join("sec_policy.yaml")).unwrap();
    let policy = Policy::from_yaml(&policy_yaml).unwrap();
    let key = CohortKey::generate(
        &policy.tenant,
        &policy.purpose,
        "company_cik",
        &policy.version,
    );

    let out_dir = std::env::temp_dir().join("anon-sec-rust-test");
    std::fs::remove_dir_all(&out_dir).ok();
    std::fs::create_dir_all(&out_dir).unwrap();

    let csv_in = base.join("sec_edgar_cash_snapshots.csv");
    let csv_out = out_dir.join("sec_edgar_cash_snapshots.csv");
    let csv_report = transform_csv(&csv_in, &csv_out, &policy, &key).unwrap();
    assert_eq!(csv_report.rows_processed, 500);
    assert_eq!(csv_report.quarantined_rows, 0);

    let mut orig_reader = csv::Reader::from_path(&csv_in).unwrap();
    let mut anon_reader = csv::Reader::from_path(&csv_out).unwrap();
    let orig_rows: Vec<HashMap<String, String>> = orig_reader
        .deserialize()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let anon_rows: Vec<HashMap<String, String>> = anon_reader
        .deserialize()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(orig_rows.len(), 500);
    assert_eq!(anon_rows.len(), 500);

    let raw_anon_csv = std::fs::read_to_string(&csv_out).unwrap();
    let mut cik_bijection: HashMap<String, String> = HashMap::new();
    let mut orig_sum = Decimal::ZERO;
    let mut anon_sum = Decimal::ZERO;

    for (o, a) in orig_rows.iter().zip(anon_rows.iter()) {
        assert!(!a.contains_key("preparer_note"));
        assert!(!a.contains_key("raw_edgar_path"));
        assert_eq!(a["cik"].len(), 64);
        assert_eq!(a["entity_name"].len(), 64);
        assert_eq!(a["accession_number"].len(), 64);
        assert_ne!(a["cik"], a["entity_name"]);
        assert!(!raw_anon_csv.contains(&o["entity_name"]));
        assert!(!raw_anon_csv.contains(&o["accession_number"]));

        if let Some(prev) = cik_bijection.get(&o["cik"]) {
            assert_eq!(prev, &a["cik"]);
        } else {
            cik_bijection.insert(o["cik"].clone(), a["cik"].clone());
        }

        let o_val: Decimal = o["cash_usd"].parse().unwrap();
        let a_val: Decimal = a["cash_usd"].parse().unwrap();
        assert_eq!(o_val, a_val);
        orig_sum += o_val;
        anon_sum += a_val;

        assert_eq!(a["period_end"], o["period_end"][..7]);
        assert_eq!(a["currency"], o["currency"]);
        assert_eq!(a["jurisdiction"], o["jurisdiction"]);
        assert_eq!(a["filing_frame"], o["filing_frame"]);
    }

    let unique_pseudos: HashSet<_> = cik_bijection.values().collect();
    assert_eq!(cik_bijection.len(), 250);
    assert_eq!(unique_pseudos.len(), 250);
    assert_eq!(orig_sum, anon_sum);
    assert_eq!(orig_sum.to_string(), "520621306888");

    let jsonl_out = out_dir.join("sec_edgar_cash_snapshots.jsonl");
    let jsonl_report = transform_jsonl(
        &base.join("sec_edgar_cash_snapshots.jsonl"),
        &jsonl_out,
        &policy,
        &key,
    )
    .unwrap();
    assert_eq!(jsonl_report.rows_processed, 500);

    let pdf_out = out_dir.join("sec_form10k.pdf");
    let pdf_report = sanitize_pdf(&base.join("sec_form10k.pdf"), &pdf_out, &policy).unwrap();
    assert!(!pdf_report.quarantined);
    assert_eq!(pdf_report.pages_processed, 19);
    assert!(pdf_report.metadata_scrubbed);

    let pbc_out = out_dir.join("pbc");
    let pbc_report =
        process_archive(&base.join("sec_pbc_package.zip"), &pbc_out, &policy, &key).unwrap();
    assert_eq!(pbc_report.files_processed, 3);
    assert_eq!(pbc_report.files_quarantined, 1);

    let telem_out = out_dir.join("sec_telem.jsonl");
    let telem_report = filter_telemetry(
        &base.join("sec_edgar_telemetry.jsonl"),
        &telem_out,
        &TelemetryAllowlist::from_policy(&policy),
        &key,
    )
    .unwrap();
    assert_eq!(telem_report.records_processed, 100);
    assert_eq!(telem_report.attributes_removed, 200);
    assert_eq!(telem_report.attributes_pseudonymized, 200);

    std::fs::remove_dir_all(&out_dir).ok();
}
