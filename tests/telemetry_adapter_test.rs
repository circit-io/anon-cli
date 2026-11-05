use anon_cli::crypto::CohortKey;
use anon_cli::telemetry_adapter::{filter_telemetry, TelemetryAllowlist};
use std::collections::HashSet;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn allowlist() -> TelemetryAllowlist {
    let mut allowed = HashSet::new();
    allowed.insert("timestamp".to_string());
    allowed.insert("service.name".to_string());
    allowed.insert("user.id".to_string());
    allowed.insert("http.status_code".to_string());

    let mut pseudonymize = HashSet::new();
    pseudonymize.insert("user.id".to_string());

    let mut entity_types = std::collections::HashMap::new();
    entity_types.insert("user.id".to_string(), "user".to_string());

    TelemetryAllowlist {
        allowed_attributes: allowed,
        pseudonymize_attributes: pseudonymize,
        entity_types,
        coarsen_attributes: Default::default(),
    }
}

fn read_rows(path: &PathBuf) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn only_allowlisted_attributes_survive() {
    let tmp = std::env::temp_dir().join("anon-telemetry-out.jsonl");
    let report = filter_telemetry(
        &fixture("sample_telemetry.jsonl"),
        &tmp,
        &allowlist(),
        &CohortKey::generate("circit", "internal-analytics", "customer", "1.0"),
    )
    .unwrap();

    assert_eq!(report.records_processed, 2);
    let rows = read_rows(&tmp);

    let attrs: HashSet<String> = rows[0].as_object().unwrap().keys().cloned().collect();
    assert!(attrs.contains("timestamp"));
    assert!(attrs.contains("service.name"));
    assert!(attrs.contains("user.id"));
    assert!(attrs.contains("http.status_code"));
    assert!(!attrs.contains("db.statement"));
    assert!(!attrs.contains("process.command_line"));
    assert_eq!(attrs.len(), 4);
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn baggage_removed_entirely() {
    let tmp = std::env::temp_dir().join("anon-telemetry-baggage.jsonl");
    filter_telemetry(
        &fixture("sample_telemetry.jsonl"),
        &tmp,
        &allowlist(),
        &CohortKey::generate("t", "p", "e", "1"),
    )
    .unwrap();
    let rows = read_rows(&tmp);
    for row in &rows {
        for key in row.as_object().unwrap().keys() {
            assert!(
                !key.to_lowercase().starts_with("baggage"),
                "baggage key leaked: {key}"
            );
        }
    }
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn empty_input_produces_empty_output() {
    let input = std::env::temp_dir().join("anon-telemetry-empty.jsonl");
    std::fs::write(&input, "").unwrap();
    let tmp = std::env::temp_dir().join("anon-telemetry-empty-out.jsonl");
    let report = filter_telemetry(
        &input,
        &tmp,
        &allowlist(),
        &CohortKey::generate("t", "p", "e", "1"),
    )
    .unwrap();
    assert_eq!(report.records_processed, 0);
    assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "");
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn pseudonymize_attributes_are_hmacd() {
    let tmp = std::env::temp_dir().join("anon-telemetry-pseudo.jsonl");
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let report =
        filter_telemetry(&fixture("sample_telemetry.jsonl"), &tmp, &allowlist(), &key).unwrap();
    assert!(report.attributes_pseudonymized > 0);

    let rows = read_rows(&tmp);
    assert_ne!(rows[0]["user.id"], "user-42");
    assert_eq!(rows[0]["user.id"].as_str().unwrap().len(), 64);
    assert_eq!(rows[0]["user.id"], key.pseudonymize_for("user-42", "user"));
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn removed_attributes_counted() {
    let tmp = std::env::temp_dir().join("anon-telemetry-count.jsonl");
    let report = filter_telemetry(
        &fixture("sample_telemetry.jsonl"),
        &tmp,
        &allowlist(),
        &CohortKey::generate("t", "p", "e", "1"),
    )
    .unwrap();
    assert!(
        report.attributes_removed >= 4,
        "expected >= 4 removed, got {}",
        report.attributes_removed
    );
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn pseudonymize_numeric_attribute_preserves_scalar() {
    let input = std::env::temp_dir().join("anon-telemetry-num-in.jsonl");
    std::fs::write(
        &input,
        "{\"user.id\":42,\"http.status_code\":200}\n{\"user.id\":77,\"http.status_code\":200}\n",
    )
    .unwrap();
    let tmp = std::env::temp_dir().join("anon-telemetry-num-out.jsonl");
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let report = filter_telemetry(&input, &tmp, &allowlist(), &key).unwrap();
    assert_eq!(report.attributes_pseudonymized, 2);

    let rows = read_rows(&tmp);
    assert_eq!(rows[0]["user.id"], key.pseudonymize_for("42", "user"));
    assert_eq!(rows[1]["user.id"], key.pseudonymize_for("77", "user"));
    assert_ne!(rows[0]["user.id"], rows[1]["user.id"]);
    std::fs::remove_file(&input).ok();
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn allowlist_from_policy_excludes_suppressed_and_coarsened_fields() {
    let yaml = std::fs::read_to_string(fixture("policy_valid.yaml")).unwrap();
    let policy = anon_cli::policy::Policy::from_yaml(&yaml).unwrap();
    let al = TelemetryAllowlist::from_policy(&policy);
    assert!(
        !al.allowed_attributes.contains("description"),
        "suppressed field must not be allowed"
    );
    assert!(
        al.allowed_attributes.contains("date"),
        "coarsened field stays allowed but must be coarsened"
    );
    assert!(
        al.coarsen_attributes.contains_key("date"),
        "coarsened field must carry granularity"
    );
    assert!(al.allowed_attributes.contains("customer_id"));
    assert!(al.pseudonymize_attributes.contains("customer_id"));
    assert!(al.allowed_attributes.contains("currency"));
}
