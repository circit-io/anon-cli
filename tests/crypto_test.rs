use anon_cli::crypto::{canonicalize, CohortKey};

#[test]
fn generates_32_byte_key() {
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    assert_eq!(key.key_bytes().len(), 32);
}

#[test]
fn deterministic_same_key_same_input() {
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let a = key.pseudonymize("cust-123");
    let b = key.pseudonymize("cust-123");
    assert_eq!(a, b);
}

#[test]
fn different_keys_differ() {
    let k1 = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let k2 = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    assert_ne!(k1.pseudonymize("cust-123"), k2.pseudonymize("cust-123"));
}

#[test]
fn domain_separator_differs_by_entity_type() {
    let customer = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let account = CohortKey::generate("circit", "internal-analytics", "account", "1.0");
    assert_ne!(
        customer.pseudonymize("same-id"),
        account.pseudonymize("same-id")
    );
}

#[test]
fn output_is_64_hex_chars() {
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let out = key.pseudonymize("cust-123");
    assert_eq!(out.len(), 64);
    assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn canonicalization_normalizes_case_and_whitespace() {
    assert_eq!(canonicalize("  John Doe "), canonicalize("john doe"));
    assert_eq!(canonicalize("John Doe"), canonicalize("john doe"));
}

#[test]
fn key_file_roundtrip() {
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    let json = key.to_key_file_json().unwrap();
    let loaded = CohortKey::from_key_file_json(&json).unwrap();
    assert_eq!(
        key.pseudonymize("cust-123"),
        loaded.pseudonymize("cust-123")
    );
}

#[test]
fn key_fingerprint_is_sha256_of_key() {
    let key = CohortKey::generate("circit", "internal-analytics", "customer", "1.0");
    assert_eq!(key.fingerprint().len(), 64);
    let reloaded = CohortKey::from_key_file_json(&key.to_key_file_json().unwrap()).unwrap();
    assert_eq!(key.fingerprint(), reloaded.fingerprint());
}

#[test]
fn colon_in_domain_components_does_not_collide() {
    let raw = [7u8; 32];
    let k1 = CohortKey::from_raw(raw, "a:b", "c", "person", "1.0");
    let k2 = CohortKey::from_raw(raw, "a", "b:c", "person", "1.0");
    assert_ne!(k1.pseudonymize("id-1"), k2.pseudonymize("id-1"));
}
