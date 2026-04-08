use std::path::PathBuf;

use ferret::parsers;
use ferret::scanner::Scanner;

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(relative)
}

#[test]
fn test_scanner_detects_secrets_in_bruno() {
    let path = fixture_path("bruno");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    // Should find: GitHub token (SEC003), Stripe key (SEC004), hardcoded password (SEC015),
    // AWS key from .env (SEC001), DB_PASSWORD from .env (SEC015),
    // hardcoded bearer (SEC012), OWASP issues
    assert!(
        !findings.is_empty(),
        "Expected findings but got none"
    );

    // Check specific secrets were found
    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"SEC003"),
        "Expected SEC003 (GitHub token), found: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"SEC004"),
        "Expected SEC004 (Stripe key), found: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"SEC001"),
        "Expected SEC001 (AWS key from .env), found: {:?}",
        rule_ids
    );
}

#[test]
fn test_scanner_skips_template_variables() {
    let path = fixture_path("bruno");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    // The safe-request.bru uses {{token}} — should not flag as SEC012
    let safe_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.location
                .file
                .to_string_lossy()
                .contains("safe-request")
                && f.rule_id == "SEC012"
        })
        .collect();
    assert!(
        safe_findings.is_empty(),
        "Template variable should not be flagged: {:?}",
        safe_findings
    );
}

#[test]
fn test_scanner_detects_owasp_issues_in_bruno() {
    let path = fixture_path("bruno");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    // Login over HTTP should trigger OWA002
    assert!(
        rule_ids.contains(&"OWA002"),
        "Expected OWA002 (auth endpoint over HTTP), found: {:?}",
        rule_ids
    );
}

#[test]
fn test_scanner_detects_secrets_in_postman() {
    let path = fixture_path("postman/collection.json");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"SEC003"),
        "Expected SEC003 (GitHub token in Postman), found: {:?}",
        rule_ids
    );

    // Stripe key in pre-request script
    assert!(
        rule_ids.contains(&"SEC004"),
        "Expected SEC004 (Stripe key in script), found: {:?}",
        rule_ids
    );
}

#[test]
fn test_scanner_detects_secrets_in_insomnia() {
    let path = fixture_path("insomnia/export.json");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&"SEC003"),
        "Expected SEC003 (GitHub token in Insomnia), found: {:?}",
        rule_ids
    );

    // Stripe key in environment variables
    assert!(
        rule_ids.contains(&"SEC004"),
        "Expected SEC004 (Stripe key in env), found: {:?}",
        rule_ids
    );

    // Password in environment
    assert!(
        rule_ids.contains(&"SEC015"),
        "Expected SEC015 (password in env), found: {:?}",
        rule_ids
    );
}

#[test]
fn test_scanner_findings_are_sorted_by_severity() {
    let path = fixture_path("bruno");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    for window in findings.windows(2) {
        assert!(
            window[0].severity >= window[1].severity,
            "Findings should be sorted by severity (desc): {:?} before {:?}",
            window[0].severity,
            window[1].severity
        );
    }
}

#[test]
fn test_hardcoded_password_in_body() {
    let path = fixture_path("bruno");
    let collection = parsers::parse(&path).unwrap();
    let scanner = Scanner::new();
    let findings = scanner.scan(&collection);

    // login.bru has a hardcoded password in the JSON body
    let password_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.rule_id == "SEC015"
                && f.location.file.to_string_lossy().contains("login")
        })
        .collect();

    assert!(
        !password_findings.is_empty(),
        "Expected SEC015 for hardcoded password in login body"
    );
}

#[test]
fn test_redaction() {
    assert_eq!(ferret::redact("sk_live_abc123xyz456789012"), "sk_l••••••••••••••••••••");
    assert_eq!(ferret::redact("ab"), "••••");
}
