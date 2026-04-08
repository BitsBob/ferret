use regex::Regex;

use crate::{Finding, Location, Request, Severity};

use super::rules::Rule;

/// Build all OWASP API Top 10 heuristic rules.
pub fn owasp_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(Owa001),
        Box::new(Owa002),
        Box::new(Owa003),
        Box::new(Owa004),
        Box::new(Owa005),
        Box::new(Owa006),
        Box::new(Owa007),
        Box::new(Owa008),
        Box::new(Owa009),
    ]
}

// --- OWA001: Broken Object Level Auth ---
// Requests with IDs in URL path but no auth header present.

struct Owa001;

impl Rule for Owa001 {
    fn id(&self) -> &str {
        "OWA001"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let id_pattern = Regex::new(r"/\d+(?:/|$)").unwrap();
        let uuid_pattern =
            Regex::new(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                .unwrap();

        let has_id = id_pattern.is_match(&request.url) || uuid_pattern.is_match(&request.url);

        if !has_id {
            return Vec::new();
        }

        let has_auth = request.auth.is_some()
            || request.headers.iter().any(|(k, _)| {
                let k = k.to_lowercase();
                k == "authorization" || k == "x-api-key"
            });

        if has_auth {
            return Vec::new();
        }

        vec![Finding {
            rule_id: "OWA001".to_string(),
            severity: Severity::Low,
            title: "Missing Auth on ID-Based Endpoint".to_string(),
            description:
                "This request accesses a resource by ID but has no authorization header. \
                 This may indicate broken object-level authorization (OWASP API1)."
                    .to_string(),
            location: Location {
                file: request.source_file.clone(),
                line: None,
                field: "url".to_string(),
            },
            evidence: request.url.clone(),
            remediation: "Ensure this endpoint requires authentication and verifies the caller has access to the requested resource.".to_string(),
        }]
    }
}

// --- OWA002: Auth endpoints not using HTTPS ---

struct Owa002;

impl Rule for Owa002 {
    fn id(&self) -> &str {
        "OWA002"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let auth_paths = ["/login", "/token", "/auth", "/signin", "/signup", "/oauth"];
        let url_lower = request.url.to_lowercase();

        let is_auth_endpoint = auth_paths.iter().any(|p| url_lower.contains(p));
        if !is_auth_endpoint {
            return Vec::new();
        }

        if url_lower.starts_with("http://") {
            vec![Finding {
                rule_id: "OWA002".to_string(),
                severity: Severity::Medium,
                title: "Auth Endpoint Not Using HTTPS".to_string(),
                description:
                    "An authentication endpoint is using HTTP instead of HTTPS. \
                     Credentials may be transmitted in plaintext (OWASP API2)."
                        .to_string(),
                location: Location {
                    file: request.source_file.clone(),
                    line: None,
                    field: "url".to_string(),
                },
                evidence: request.url.clone(),
                remediation: "Always use HTTPS for authentication endpoints.".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

// --- OWA003: HTTP with auth headers ---

struct Owa003;

impl Rule for Owa003 {
    fn id(&self) -> &str {
        "OWA003"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        if !request.url.to_lowercase().starts_with("http://") {
            return Vec::new();
        }

        let has_auth = request.auth.is_some()
            || request
                .headers
                .iter()
                .any(|(k, _)| k.to_lowercase() == "authorization");

        if has_auth {
            vec![Finding {
                rule_id: "OWA003".to_string(),
                severity: Severity::Medium,
                title: "Auth Credentials Over HTTP".to_string(),
                description:
                    "This request sends authorization credentials over unencrypted HTTP (OWASP API2)."
                        .to_string(),
                location: Location {
                    file: request.source_file.clone(),
                    line: None,
                    field: "url".to_string(),
                },
                evidence: request.url.clone(),
                remediation: "Use HTTPS when sending authorization credentials.".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

// --- OWA004: Mass assignment (large PATCH/PUT bodies) ---

struct Owa004;

const MASS_ASSIGNMENT_BODY_THRESHOLD: usize = 2000;

impl Rule for Owa004 {
    fn id(&self) -> &str {
        "OWA004"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let method = request.method.to_uppercase();
        if method != "PUT" && method != "PATCH" {
            return Vec::new();
        }

        if let Some(ref body) = request.body {
            if body.len() > MASS_ASSIGNMENT_BODY_THRESHOLD {
                return vec![Finding {
                    rule_id: "OWA004".to_string(),
                    severity: Severity::Low,
                    title: "Potential Mass Assignment".to_string(),
                    description: format!(
                        "A {} request has a very large body ({} bytes), which may indicate \
                         mass assignment risk (OWASP API3).",
                        method,
                        body.len()
                    ),
                    location: Location {
                        file: request.source_file.clone(),
                        line: None,
                        field: "body".to_string(),
                    },
                    evidence: format!("{} request with {} byte body", method, body.len()),
                    remediation:
                        "Ensure the API only accepts expected fields and ignores unknown properties."
                            .to_string(),
                }];
            }
        }

        Vec::new()
    }
}

// --- OWA005: No pagination on collection GET ---

struct Owa005;

impl Rule for Owa005 {
    fn id(&self) -> &str {
        "OWA005"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        if request.method.to_uppercase() != "GET" {
            return Vec::new();
        }

        // Heuristic: URL ends with a plural resource name (e.g., /users, /items)
        // and has no pagination query params
        let url_lower = request.url.to_lowercase();
        let path = url_lower
            .split('?')
            .next()
            .unwrap_or(&url_lower)
            .trim_end_matches('/');

        // Check if path ends with a plural-looking segment (ends with 's')
        let last_segment = path.rsplit('/').next().unwrap_or("");
        if !last_segment.ends_with('s') || last_segment.len() < 3 {
            return Vec::new();
        }

        // Check if there are pagination params
        let pagination_params = ["page", "limit", "offset", "per_page", "pagesize", "cursor", "skip", "take"];
        let has_pagination = if let Some(query) = request.url.split('?').nth(1) {
            pagination_params
                .iter()
                .any(|p| query.to_lowercase().contains(p))
        } else {
            false
        };

        if has_pagination {
            return Vec::new();
        }

        vec![Finding {
            rule_id: "OWA005".to_string(),
            severity: Severity::Low,
            title: "No Pagination on Collection Endpoint".to_string(),
            description:
                "A GET request to a collection endpoint has no pagination parameters, \
                 which may lead to unrestricted resource consumption (OWASP API4)."
                    .to_string(),
            location: Location {
                file: request.source_file.clone(),
                line: None,
                field: "url".to_string(),
            },
            evidence: request.url.clone(),
            remediation: "Add pagination parameters (e.g., ?page=1&limit=20) to collection endpoints.".to_string(),
        }]
    }
}

// --- OWA006: Missing Content-Type on POST/PUT/PATCH with body ---

struct Owa006;

impl Rule for Owa006 {
    fn id(&self) -> &str {
        "OWA006"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let method = request.method.to_uppercase();
        if !matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
            return Vec::new();
        }

        if request.body.is_none() {
            return Vec::new();
        }

        let has_content_type = request
            .headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "content-type");

        if has_content_type {
            return Vec::new();
        }

        vec![Finding {
            rule_id: "OWA006".to_string(),
            severity: Severity::Low,
            title: "Missing Content-Type Header".to_string(),
            description:
                "A request with a body is missing the Content-Type header (OWASP API8)."
                    .to_string(),
            location: Location {
                file: request.source_file.clone(),
                line: None,
                field: "headers".to_string(),
            },
            evidence: format!("{} request with body but no Content-Type", method),
            remediation: "Add a Content-Type header (e.g., application/json) to requests with a body.".to_string(),
        }]
    }
}

// --- OWA007: X-Powered-By header present ---

struct Owa007;

impl Rule for Owa007 {
    fn id(&self) -> &str {
        "OWA007"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        for (key, value) in &request.headers {
            if key.to_lowercase() == "x-powered-by" {
                return vec![Finding {
                    rule_id: "OWA007".to_string(),
                    severity: Severity::Low,
                    title: "X-Powered-By Header Present".to_string(),
                    description:
                        "The X-Powered-By header reveals technology stack information (OWASP API8)."
                            .to_string(),
                    location: Location {
                        file: request.source_file.clone(),
                        line: None,
                        field: "header: X-Powered-By".to_string(),
                    },
                    evidence: value.clone(),
                    remediation: "Remove the X-Powered-By header to avoid revealing stack information.".to_string(),
                }];
            }
        }
        Vec::new()
    }
}

// --- OWA008: Non-versioned API paths ---

struct Owa008;

impl Rule for Owa008 {
    fn id(&self) -> &str {
        "OWA008"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let version_pattern = Regex::new(r"/v\d+[./]").unwrap();

        // Only check API-looking URLs
        let url_lower = request.url.to_lowercase();
        if !url_lower.contains("/api") && !url_lower.contains("api.") {
            return Vec::new();
        }

        if version_pattern.is_match(&request.url) {
            return Vec::new();
        }

        vec![Finding {
            rule_id: "OWA008".to_string(),
            severity: Severity::Info,
            title: "Non-Versioned API Path".to_string(),
            description:
                "This API request URL does not include a version identifier (e.g., /v1/), \
                 which may complicate API inventory management (OWASP API9)."
                    .to_string(),
            location: Location {
                file: request.source_file.clone(),
                line: None,
                field: "url".to_string(),
            },
            evidence: request.url.clone(),
            remediation: "Consider using versioned API paths (e.g., /v1/users) for better API lifecycle management.".to_string(),
        }]
    }
}

// --- OWA009: HTTP (non-TLS) third-party endpoints ---

struct Owa009;

impl Rule for Owa009 {
    fn id(&self) -> &str {
        "OWA009"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let url_lower = request.url.to_lowercase();

        if !url_lower.starts_with("http://") {
            return Vec::new();
        }

        // Skip localhost / internal addresses
        let safe_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "[::1]"];
        if safe_hosts.iter().any(|h| url_lower.contains(h)) {
            return Vec::new();
        }

        vec![Finding {
            rule_id: "OWA009".to_string(),
            severity: Severity::Medium,
            title: "HTTP (Non-TLS) Endpoint".to_string(),
            description:
                "This request uses HTTP instead of HTTPS, meaning data is transmitted \
                 without encryption (OWASP API10)."
                    .to_string(),
            location: Location {
                file: request.source_file.clone(),
                line: None,
                field: "url".to_string(),
            },
            evidence: request.url.clone(),
            remediation: "Use HTTPS to ensure data is encrypted in transit.".to_string(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_request(method: &str, url: &str, headers: Vec<(&str, &str)>) -> Request {
        Request {
            name: "Test".to_string(),
            method: method.to_string(),
            url: url.to_string(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: None,
            auth: None,
            source_file: PathBuf::from("test.bru"),
        }
    }

    #[test]
    fn test_owa001_id_without_auth() {
        let rule = Owa001;
        let req = make_request("GET", "https://api.example.com/users/123", vec![]);
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_owa001_id_with_auth() {
        let rule = Owa001;
        let req = make_request(
            "GET",
            "https://api.example.com/users/123",
            vec![("Authorization", "Bearer token")],
        );
        let findings = rule.scan_request(&req);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_owa002_http_auth_endpoint() {
        let rule = Owa002;
        let req = make_request("POST", "http://api.example.com/auth/login", vec![]);
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_owa003_http_with_auth_header() {
        let rule = Owa003;
        let req = make_request(
            "GET",
            "http://api.example.com/data",
            vec![("Authorization", "Bearer abc")],
        );
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_owa005_no_pagination() {
        let rule = Owa005;
        let req = make_request("GET", "https://api.example.com/users", vec![]);
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_owa005_with_pagination() {
        let rule = Owa005;
        let req = make_request("GET", "https://api.example.com/users?page=1&limit=20", vec![]);
        let findings = rule.scan_request(&req);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_owa009_http_external() {
        let rule = Owa009;
        let req = make_request("GET", "http://third-party.example.com/api/data", vec![]);
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_owa009_http_localhost_ok() {
        let rule = Owa009;
        let req = make_request("GET", "http://localhost:3000/api/data", vec![]);
        let findings = rule.scan_request(&req);
        assert!(findings.is_empty());
    }
}
