use anon_cli::policy::{Classification, Policy, PolicyError, Transform};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&path).expect("fixture must exist")
}

#[test]
fn loads_valid_policy() {
    let policy = Policy::from_yaml(&fixture("policy_valid.yaml")).unwrap();
    assert_eq!(policy.version, "1.0");
    assert_eq!(policy.tenant, "circit");
    assert_eq!(policy.purpose, "internal-analytics");

    let customer = policy
        .classify("customer_id")
        .expect("customer_id must be classified");
    assert_eq!(customer.classification, Classification::DirectIdentifier);
    match &customer.transform {
        Transform::Pseudonymize { entity_type } => assert_eq!(entity_type, "customer"),
        other => panic!("expected Pseudonymize, got {:?}", other),
    }

    let amount = policy
        .classify("amount")
        .expect("amount must be classified");
    assert_eq!(amount.classification, Classification::FinancialInvariant);
    match &amount.transform {
        Transform::Preserve { precision } => assert_eq!(*precision, Some(2)),
        other => panic!("expected Preserve, got {:?}", other),
    }

    let date = policy.classify("date").expect("date must be classified");
    match &date.transform {
        Transform::Coarsen { granularity } => {
            assert_eq!(format!("{:?}", granularity), "Month")
        }
        other => panic!("expected Coarsen, got {:?}", other),
    }

    let description = policy
        .classify("description")
        .expect("description must be classified");
    assert_eq!(description.classification, Classification::FreeText);
    assert_eq!(description.transform, Transform::Suppress);
}

#[test]
fn missing_required_field_errors() {
    let err = Policy::from_yaml(&fixture("policy_missing_fields.yaml")).unwrap_err();
    match err {
        PolicyError::MissingField(field) => assert_eq!(field, "tenant"),
        other => panic!("expected MissingField, got {:?}", other),
    }
}

#[test]
fn unknown_classification_errors() {
    let yaml = r#"
version: "1.0"
tenant: "circit"
purpose: "internal-analytics"
fields:
  customer_id:
    classification: secret_sauce
    transform: pseudonymize
    entity_type: customer
"#;
    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        PolicyError::UnknownClassification(c) => assert_eq!(c, "secret_sauce"),
        other => panic!("expected UnknownClassification, got {:?}", other),
    }
}

#[test]
fn default_deny_withholds_unclassified_fields() {
    let policy = Policy::from_yaml(&fixture("policy_valid.yaml")).unwrap();
    assert!(policy.is_withheld("ssn"));
    assert!(policy.is_withheld("home_address"));
    assert!(!policy.is_withheld("customer_id"));
    assert!(policy.classify("ssn").is_none());
}
