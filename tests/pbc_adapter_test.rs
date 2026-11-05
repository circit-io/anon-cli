use anon_cli::crypto::CohortKey;
use anon_cli::pbc_adapter::process_archive;
use anon_cli::policy::Policy;
use lopdf::{Dictionary, Document, Object};
use std::io::Write;
use std::path::PathBuf;

fn load_policy() -> Policy {
    let path = format!(
        "{}/tests/fixtures/policy_valid.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    Policy::from_yaml(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn load_key() -> CohortKey {
    CohortKey::generate("circit", "internal-analytics", "customer", "1.0")
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

fn minimal_pdf_bytes() -> Vec<u8> {
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
    let path = tmp("anon-pbc-src.pdf");
    doc.save(&path).unwrap();
    std::fs::read(&path).unwrap()
}

fn make_zip(path: &PathBuf, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
    for (name, data) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

#[test]
fn mixed_content_routed_to_sub_adapters() {
    let input = tmp("anon-pbc-mixed.zip");
    let jsonl = b"{\"customer_id\":\"cust-1\",\"amount\":\"10.50\",\"currency\":\"EUR\"}\n";
    make_zip(
        &input,
        &[
            ("statement.pdf", &minimal_pdf_bytes()),
            ("ledger.jsonl", jsonl),
            ("mystery.bin", b"\x00\x01\x02\x03 binary blob"),
        ],
    );

    let out = tmp("anon-pbc-mixed-out");
    std::fs::remove_dir_all(&out).ok();
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();

    assert_eq!(report.files_processed, 2);
    assert_eq!(report.files_quarantined, 1);
    assert_eq!(report.quarantine_reasons.len(), 1);
    assert_eq!(report.quarantine_reasons[0].0, "mystery.bin");

    let pdf_out = std::fs::read(out.join("statement.pdf")).unwrap();
    assert!(pdf_out.windows(4).any(|w| w == b"%PDF"));

    let jsonl_out = std::fs::read_to_string(out.join("ledger.jsonl")).unwrap();
    let row: serde_json::Value = serde_json::from_str(jsonl_out.lines().next().unwrap()).unwrap();
    assert_ne!(row["customer_id"], "cust-1");
    assert_eq!(row["amount"].as_f64().unwrap(), 10.5);

    assert!(!out.join("mystery.bin").exists());
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn nested_zip_extracted_and_processed() {
    let inner = tmp("anon-pbc-inner.zip");
    let jsonl = b"{\"customer_id\":\"cust-9\",\"amount\":\"1.00\",\"currency\":\"PLN\"}\n";
    make_zip(&inner, &[("data.jsonl", jsonl)]);
    let inner_bytes = std::fs::read(&inner).unwrap();

    let input = tmp("anon-pbc-outer.zip");
    make_zip(&input, &[("inner.zip", &inner_bytes)]);

    let out = tmp("anon-pbc-nested-out");
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();

    assert_eq!(report.files_processed, 1);
    let processed = std::fs::read_to_string(out.join("data.jsonl")).unwrap();
    let row: serde_json::Value = serde_json::from_str(processed.lines().next().unwrap()).unwrap();
    assert_ne!(row["customer_id"], "cust-9");

    std::fs::remove_file(&inner).ok();
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn empty_zip_produces_empty_output() {
    let input = tmp("anon-pbc-empty.zip");
    make_zip(&input, &[]);
    let out = tmp("anon-pbc-empty-out");
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.files_processed, 0);
    assert_eq!(report.files_quarantined, 0);
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn corrupt_zip_quarantined_not_error() {
    let input = tmp("anon-pbc-corrupt.zip");
    std::fs::write(&input, b"not a zip at all").unwrap();
    let out = tmp("anon-pbc-corrupt-out");
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.files_quarantined, 1);
    assert!(
        report.quarantine_reasons[0].1.contains("corrupt")
            || report.quarantine_reasons[0].1.contains("zip")
    );
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn csv_extension_routed_to_csv_transform() {
    let input = tmp("anon-pbc-csv.zip");
    let csv = "customer_id,amount,currency\ncust-3,42.00,EUR\n";
    make_zip(&input, &[("export.csv", csv.as_bytes())]);
    let out = tmp("anon-pbc-csv-out");
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.files_processed, 1);
    let content = std::fs::read_to_string(out.join("export.csv")).unwrap();
    assert!(content.contains("customer_id"));
    assert!(!content.contains("cust-3"));
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn nested_quarantined_pdf_counts_as_quarantined() {
    let mut doc = Document::with_version("1.7");
    let page = doc.add_object(Object::Dictionary(Dictionary::from_iter(vec![(
        "Type".to_string(),
        Object::Name(b"Page".to_vec()),
    )])));
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
    doc.trailer.set(
        "ID",
        Object::Array(vec![
            Object::String(b"id1".to_vec(), lopdf::StringFormat::Hexadecimal),
            Object::String(b"id2".to_vec(), lopdf::StringFormat::Hexadecimal),
        ]),
    );
    let state =
        lopdf::encryption::EncryptionState::try_from(lopdf::encryption::EncryptionVersion::V1 {
            document: &doc,
            owner_password: "o",
            user_password: "u",
            permissions: lopdf::encryption::Permissions::default(),
        })
        .unwrap();
    doc.encrypt(&state).unwrap();
    let enc_path = tmp("anon-pbc-enc-src.pdf");
    doc.save(&enc_path).unwrap();

    let inner = tmp("anon-pbc-nq-inner.zip");
    make_zip(
        &inner,
        &[("locked.pdf", &std::fs::read(&enc_path).unwrap())],
    );
    let outer = tmp("anon-pbc-nq-outer.zip");
    make_zip(&outer, &[("nested.zip", &std::fs::read(&inner).unwrap())]);

    let out = tmp("anon-pbc-nq-out");
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&outer, &out, &load_policy(), &load_key()).unwrap();
    assert_eq!(
        report.files_processed, 0,
        "quarantined PDF must not count as processed"
    );
    assert_eq!(report.files_quarantined, 1);

    std::fs::remove_file(&enc_path).ok();
    std::fs::remove_file(&inner).ok();
    std::fs::remove_file(&outer).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn nested_partial_failure_leaves_no_output() {
    let inner = tmp("anon-pbc-pf-inner.zip");
    let jsonl = b"{\"customer_id\":\"cust-7\",\"amount\":\"5.00\",\"currency\":\"EUR\"}\n";
    make_zip(
        &inner,
        &[
            ("good.jsonl", jsonl),
            ("mystery.bin", b"\x00\x01\x02 unknown"),
        ],
    );
    let outer = tmp("anon-pbc-pf-outer.zip");
    make_zip(&outer, &[("nested.zip", &std::fs::read(&inner).unwrap())]);

    let out = tmp("anon-pbc-pf-out");
    std::fs::remove_dir_all(&out).ok();
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&outer, &out, &load_policy(), &load_key()).unwrap();

    assert_eq!(
        report.files_processed, 0,
        "nested run failed; nothing counts as processed"
    );
    assert_eq!(report.files_quarantined, 1);
    assert!(
        out.read_dir().unwrap().next().is_none(),
        "no partial outputs allowed"
    );

    std::fs::remove_file(&inner).ok();
    std::fs::remove_file(&outer).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn duplicate_filenames_across_subdirs_quarantined_no_overwrite() {
    let input = tmp("anon-pbc-dup.zip");
    let csv1 = b"customer_id,amount,currency\ncust-1,11.11,EUR\n";
    let csv2 = b"customer_id,amount,currency\ncust-2,22.22,EUR\n";
    make_zip(&input, &[("a/export.csv", csv1), ("b/export.csv", csv2)]);
    let out = tmp("anon-pbc-dup-out");
    std::fs::remove_dir_all(&out).ok();
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.files_processed, 1);
    assert_eq!(report.files_quarantined, 1);
    let content = std::fs::read_to_string(out.join("export.csv")).unwrap();
    assert!(content.contains("11.11"));
    assert!(!content.contains("22.22"));
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}

#[test]
fn failed_csv_in_archive_leaves_no_partial_output() {
    let input = tmp("anon-pbc-badcsv.zip");
    let bad_csv = b"customer_id,amount,currency\ncust-1,10.00,EUR\nbroken,row,with,too,many,cols\n";
    make_zip(&input, &[("bad.csv", bad_csv)]);
    let out = tmp("anon-pbc-badcsv-out");
    std::fs::remove_dir_all(&out).ok();
    std::fs::create_dir_all(&out).unwrap();
    let report = process_archive(&input, &out, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.files_processed, 0);
    assert_eq!(report.files_quarantined, 1);
    assert!(
        !out.join("bad.csv").exists(),
        "partial output of failed CSV must not remain"
    );
    std::fs::remove_file(&input).ok();
    std::fs::remove_dir_all(&out).ok();
}
