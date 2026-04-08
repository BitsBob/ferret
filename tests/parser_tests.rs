use std::path::PathBuf;

use ferret::parsers::{self, CollectionType};

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(relative)
}

#[test]
fn test_detect_bruno_collection() {
    let path = fixture_path("bruno");
    let ct = parsers::detect_collection_type(&path).unwrap();
    assert_eq!(ct, CollectionType::Bruno);
}

#[test]
fn test_detect_postman_collection() {
    let path = fixture_path("postman/collection.json");
    let ct = parsers::detect_collection_type(&path).unwrap();
    assert_eq!(ct, CollectionType::Postman);
}

#[test]
fn test_detect_insomnia_collection() {
    let path = fixture_path("insomnia/export.json");
    let ct = parsers::detect_collection_type(&path).unwrap();
    assert_eq!(ct, CollectionType::Insomnia);
}

#[test]
fn test_parse_bruno_collection() {
    let path = fixture_path("bruno");
    let collection = parsers::parse(&path).unwrap();
    assert_eq!(collection.collection_type, CollectionType::Bruno);
    assert!(collection.requests.len() >= 3);

    // Check a specific request was parsed
    let get_users = collection
        .requests
        .iter()
        .find(|r| r.name == "Get Users")
        .expect("Get Users request not found");
    assert_eq!(get_users.method, "GET");
    assert!(get_users.url.contains("api.example.com/users"));

    // Check env vars were parsed
    assert!(!collection.env_vars.is_empty());
    assert!(collection
        .env_vars
        .iter()
        .any(|(k, _, _)| k == "DB_PASSWORD"));
}

#[test]
fn test_parse_postman_collection() {
    let path = fixture_path("postman/collection.json");
    let collection = parsers::parse(&path).unwrap();
    assert_eq!(collection.collection_type, CollectionType::Postman);
    assert!(collection.requests.len() >= 3);

    // Check nested folder request was extracted
    let login = collection
        .requests
        .iter()
        .find(|r| r.name == "Login")
        .expect("Login request not found");
    assert_eq!(login.method, "POST");

    // Check script content is included
    let with_script = collection
        .requests
        .iter()
        .find(|r| r.name == "With Script")
        .expect("With Script request not found");
    assert!(with_script
        .body
        .as_ref()
        .unwrap()
        .contains("sk_live_"));
}

#[test]
fn test_parse_insomnia_collection() {
    let path = fixture_path("insomnia/export.json");
    let collection = parsers::parse(&path).unwrap();
    assert_eq!(collection.collection_type, CollectionType::Insomnia);
    assert!(collection.requests.len() >= 2);

    // Check env vars were parsed
    assert!(collection
        .env_vars
        .iter()
        .any(|(k, _, _)| k == "api_secret"));
}
