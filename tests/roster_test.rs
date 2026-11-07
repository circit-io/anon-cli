use anon_cli::roster::{
    extract_from_text, find_account_numbers, find_sort_codes, is_account_number, is_sort_code,
    parse_entity_filter, validate_entry, RosterEntity,
};

#[test]
fn sort_code_shape_accepts_real_codes() {
    for s in ["12-34-56", "01-00-01", "99-99-99", "60-00-00"] {
        assert!(is_sort_code(s), "{s} should be a sort code");
    }
}

#[test]
fn sort_code_shape_rejects_false_positives() {
    // full dates, malformed shapes, zero prefix; a bare "24-01-15" is
    // shape-valid as a sort code -- date rejection happens at extraction
    // time via boundary rules (see find_sort_codes tests)
    for s in [
        "2024-01-15", "00-34-56", "12-34-5", "12-345-6", "1-34-56", "12 34 56",
        "ab-cd-ef", "12-34-567", "", "12-34",
    ] {
        assert!(!is_sort_code(s), "{s:?} should be rejected");
    }
}

#[test]
fn account_number_shape_accepts_real_numbers() {
    for s in ["12345678", "1234-5678", "1234 5678"] {
        assert!(is_account_number(s), "{s} should be an account number");
    }
}

#[test]
fn account_number_shape_rejects_false_positives() {
    for s in [
        "123456789", "1234567", "1234-567", "2024-01-15", "1234-56-78", "1234.5678", "abcd-efgh", "",
    ] {
        assert!(!is_account_number(s), "{s:?} should be rejected");
    }
}

#[test]
fn find_sort_codes_ignores_dates_amounts_and_longer_runs() {
    let text = "statement dated 2024-01-15, amount 1,234-56-78 GBP, ref 12-34-56-78, sort code: 20-30-40.";
    assert_eq!(find_sort_codes(text), vec!["20-30-40".to_string()]);

    let dates = "2024-01-15 2024-01-15T10:30:00Z 15-01-2024 2024/01/15";
    assert!(find_sort_codes(dates).is_empty(), "dates must not match");

    let amounts = "total 12-34-56.78 and 99-88-77,00 EUR";
    assert!(find_sort_codes(amounts).is_empty(), "amounts must not match");
}

#[test]
fn find_sort_codes_finds_embedded_candidates() {
    let text = "Sort Code 40-00-17; other 12-34-56.";
    let mut found = find_sort_codes(text);
    found.sort();
    assert_eq!(found, vec!["12-34-56".to_string(), "40-00-17".to_string()]);
}

#[test]
fn find_account_numbers_ignores_dates_cards_and_decimals() {
    let text = "acct 12345678, card 1234-5678-9012-3456, date 2024-01-15, amount 1234.5678, ref 1234-5678.";
    let mut found = find_account_numbers(text);
    found.sort();
    assert_eq!(found, vec!["1234-5678".to_string(), "12345678".to_string()]);
}

#[test]
fn validate_entry_enforces_narrowed_shapes_fail_closed() {
    assert!(validate_entry("2024-01-15", "sort_code").is_err());
    assert!(validate_entry("1,234-56-78", "sort_code").is_err());
    assert!(validate_entry("12-34-56", "sort_code").is_ok());
    assert!(validate_entry("2024-01-15", "account_number").is_err());
    assert!(validate_entry("12345678", "account_number").is_ok());
    assert!(validate_entry("1234-5678", "account_number").is_ok());
    // other entity types pass through untouched
    assert!(validate_entry("John Smith", "customer_name").is_ok());
    assert!(validate_entry("2024-01-15", "free_text").is_ok());
}

#[test]
fn extract_from_text_emits_only_narrowed_matches_with_entity_tags() {
    let text = "Statement 2024-01-15. Sort code 20-30-40, account 12345678, card 1234-5678-9012-3456, amount 1234.5678, other acct 1234-5678.";
    let mut found = extract_from_text(text, None);
    found.sort();
    assert_eq!(
        found,
        vec![
            ("1234-5678".to_string(), "account_number".to_string()),
            ("12345678".to_string(), "account_number".to_string()),
            ("20-30-40".to_string(), "sort_code".to_string()),
        ]
    );
}

#[test]
fn extract_from_text_respects_entity_filter_and_dedupes() {
    let text = "20-30-40 and 20-30-40 again, 12345678";
    assert_eq!(
        extract_from_text(text, Some(RosterEntity::SortCode)),
        vec![("20-30-40".to_string(), "sort_code".to_string())]
    );
    assert_eq!(
        extract_from_text(text, Some(RosterEntity::AccountNumber)),
        vec![("12345678".to_string(), "account_number".to_string())]
    );
    assert!(parse_entity_filter("bogus").is_err());
    assert_eq!(parse_entity_filter(" ALL ").unwrap(), None);
}

#[test]
fn validate_entry_cannot_be_bypassed_by_casing_or_whitespace() {
    assert!(validate_entry("2024-01-15", "Sort_Code").is_err());
    assert!(validate_entry("2024-01-15", " SORT_CODE ").is_err());
    assert!(validate_entry("2024-01-15", "account_number\t").is_err());
    assert!(validate_entry("12-34-56", "SORT_CODE").is_ok());
    assert!(validate_entry("12345678", " Account_Number ").is_ok());
}
