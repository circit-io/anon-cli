use anon_cli::crypto::CohortKey;
use anon_cli::policy::Policy;
use anon_cli::sql_adapter::{transform_csv, transform_jsonl};
use std::collections::HashMap;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn load_policy() -> Policy {
    Policy::from_yaml(&std::fs::read_to_string(fixture("policy_valid.yaml")).unwrap()).unwrap()
}

fn load_key() -> CohortKey {
    CohortKey::generate("circit", "internal-analytics", "customer", "1.0")
}

fn read_csv(path: &PathBuf) -> Vec<HashMap<String, String>> {
    let mut reader = csv::Reader::from_path(path).unwrap();
    reader
        .deserialize::<HashMap<String, String>>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn csv_transform_pseudonymizes_preserves_and_suppresses() {
    let tmp = std::env::temp_dir().join("anon-cli-test-sql-csv.csv");
    let report = transform_csv(
        &fixture("sample_transactions.csv"),
        &tmp,
        &load_policy(),
        &load_key(),
    )
    .unwrap();

    assert_eq!(report.rows_processed, 3);
    assert!(report
        .fields_withheld
        .contains(&"internal_note".to_string()));

    let rows = read_csv(&tmp);
    assert_eq!(rows.len(), 3);

    let header = std::fs::read_to_string(&tmp).unwrap();
    assert!(!header.lines().next().unwrap().contains("internal_note"));
    assert!(!header.lines().next().unwrap().contains("description"));

    assert_ne!(rows[0]["customer_id"], "cust-1");
    assert_eq!(rows[0]["customer_id"].len(), 64);
    assert_ne!(rows[0]["account_number"], "acct-100");

    assert_eq!(rows[0]["amount"], "1500.25");
    assert_eq!(rows[0]["balance"], "20000.00");
    assert_eq!(rows[0]["currency"], "EUR");

    assert_eq!(rows[0]["date"], "2024-03");

    std::fs::remove_file(&tmp).ok();
}

#[test]
fn unclassified_column_is_withheld() {
    let tmp = std::env::temp_dir().join("anon-cli-test-sql-withheld.csv");
    transform_csv(
        &fixture("sample_transactions.csv"),
        &tmp,
        &load_policy(),
        &load_key(),
    )
    .unwrap();
    let header = std::fs::read_to_string(&tmp).unwrap();
    let first = header.lines().next().unwrap();
    let columns: Vec<&str> = first.split(',').collect();
    let expected = [
        "customer_id",
        "account_number",
        "amount",
        "date",
        "balance",
        "currency",
    ];
    for col in expected {
        assert!(columns.contains(&col), "missing expected column {col}");
    }
    assert_eq!(columns.len(), expected.len(), "unexpected columns present");
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn empty_policy_errors() {
    let policy = Policy {
        version: "1.0".into(),
        tenant: "circit".into(),
        purpose: "internal-analytics".into(),
        fields: HashMap::new(),
    };
    let tmp = std::env::temp_dir().join("anon-cli-test-sql-empty-policy.csv");
    let err = transform_csv(
        &fixture("sample_transactions.csv"),
        &tmp,
        &policy,
        &load_key(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("fields"),
        "expected fields error, got: {err}"
    );
}

#[test]
fn empty_csv_produces_empty_output() {
    let input = std::env::temp_dir().join("anon-cli-test-empty.csv");
    std::fs::write(&input, "customer_id,amount\n").unwrap();
    let tmp = std::env::temp_dir().join("anon-cli-test-empty-out.csv");
    let report = transform_csv(&input, &tmp, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.rows_processed, 0);
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn referential_integrity_same_input_same_pseudonym() {
    let tmp = std::env::temp_dir().join("anon-cli-test-sql-ref.csv");
    transform_csv(
        &fixture("sample_transactions.csv"),
        &tmp,
        &load_policy(),
        &load_key(),
    )
    .unwrap();
    let rows = read_csv(&tmp);
    assert_eq!(rows[0]["customer_id"], rows[1]["customer_id"]);
    assert_ne!(rows[0]["customer_id"], rows[2]["customer_id"]);
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn jsonl_transform_matches_semantics() {
    let tmp = std::env::temp_dir().join("anon-cli-test-sql.jsonl");
    let report = transform_jsonl(
        &fixture("sample_transactions.jsonl"),
        &tmp,
        &load_policy(),
        &load_key(),
    )
    .unwrap();
    assert_eq!(report.rows_processed, 2);

    let content = std::fs::read_to_string(&tmp).unwrap();
    let rows: Vec<serde_json::Value> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    assert_eq!(rows[0]["amount"].to_string(), "1500.25");
    assert_eq!(rows[0]["date"], "2024-03");
    assert!(rows[0].get("internal_note").is_none());
    assert!(rows[0].get("description").is_none());
    assert_ne!(rows[0]["customer_id"], "cust-1");
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn entity_type_domain_separation() {
    let input = std::env::temp_dir().join("anon-cli-test-entities.csv");
    std::fs::write(
        &input,
        "customer_id,account_number,amount,currency\nsame-raw,same-raw,10.00,EUR\n",
    )
    .unwrap();
    let tmp = std::env::temp_dir().join("anon-cli-test-entities-out.csv");
    transform_csv(&input, &tmp, &load_policy(), &load_key()).unwrap();
    let rows = read_csv(&tmp);
    assert_ne!(
        rows[0]["customer_id"], rows[0]["account_number"],
        "different entity types must produce different pseudonyms for same raw value"
    );
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn jsonl_numeric_scalars_not_quarantined() {
    let input = std::env::temp_dir().join("anon-cli-test-numeric.jsonl");
    std::fs::write(
        &input,
        "{\"customer_id\":\"cust-1\",\"amount\":1500.25,\"currency\":\"EUR\"}\n",
    )
    .unwrap();
    let tmp = std::env::temp_dir().join("anon-cli-test-numeric-out.jsonl");
    let report = transform_jsonl(&input, &tmp, &load_policy(), &load_key()).unwrap();
    assert_eq!(
        report.rows_processed, 1,
        "numeric amount row must not be quarantined"
    );
    assert_eq!(report.quarantined_rows, 0);
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&tmp)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[0]["amount"].to_string(), "1500.25");
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn jsonl_large_decimal_preserves_exact_precision() {
    let input = std::env::temp_dir().join("anon-cli-test-bigdec.jsonl");
    std::fs::write(
        &input,
        "{\"customer_id\":\"cust-1\",\"amount\":9007199254740993.01,\"currency\":\"EUR\"}\n",
    )
    .unwrap();
    let tmp = std::env::temp_dir().join("anon-cli-test-bigdec-out.jsonl");
    let report = transform_jsonl(&input, &tmp, &load_policy(), &load_key()).unwrap();
    assert_eq!(report.rows_processed, 1);
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&tmp)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[0]["amount"].to_string(), "9007199254740993.01");
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&tmp).ok();
}
