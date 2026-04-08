use std::path::Path;

use regex::Regex;

use crate::entropy::{is_high_entropy_secret, is_placeholder, is_template_variable};
use crate::{redact, Finding, Location, Request, Severity};

use super::rules::Rule;

/// A regex-based secret detection rule.
struct SecretPattern {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    pattern: Regex,
    remediation: &'static str,
    /// If true, skip matches that look like template variables.
    skip_templates: bool,
}

/// Build all secret detection rules.
pub fn secret_rules() -> Vec<Box<dyn Rule>> {
    let patterns = vec![
        SecretPattern {
            id: "SEC001",
            title: "AWS Access Key",
            description: "An AWS access key ID was found hardcoded.",
            severity: Severity::Critical,
            pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            remediation: "Use an environment variable for the AWS access key.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC002",
            title: "AWS Secret Key",
            description: "A potential AWS secret access key was found.",
            severity: Severity::Critical,
            pattern: Regex::new(r"(?i)(?:aws_secret|aws_secret_access_key|secret_key)\s*[:=]\s*[A-Za-z0-9/+=]{40}").unwrap(),
            remediation: "Use an environment variable for the AWS secret key.",
            skip_templates: true,
        },
        SecretPattern {
            id: "SEC003",
            title: "GitHub Token",
            description: "A GitHub personal access token was found hardcoded.",
            severity: Severity::Critical,
            pattern: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap(),
            remediation: "Replace the hardcoded token with an environment variable.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC004",
            title: "Stripe Secret Key",
            description: "A Stripe live secret key was found hardcoded.",
            severity: Severity::High,
            pattern: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            remediation: "Use an environment variable. Never commit live Stripe keys to collections.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC005",
            title: "Stripe Publishable Key",
            description: "A Stripe live publishable key was found hardcoded.",
            severity: Severity::Medium,
            pattern: Regex::new(r"pk_live_[0-9a-zA-Z]{24,}").unwrap(),
            remediation: "While publishable keys are less sensitive, prefer using an environment variable.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC006",
            title: "Slack Token",
            description: "A Slack token was found hardcoded.",
            severity: Severity::High,
            pattern: Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]{10,}").unwrap(),
            remediation: "Use an environment variable for Slack tokens.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC007",
            title: "Generic JWT",
            description: "A JWT was found hardcoded in the request.",
            severity: Severity::Medium,
            pattern: Regex::new(r"ey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}").unwrap(),
            remediation: "JWTs should be dynamically obtained, not hardcoded in collections.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC008",
            title: "Private Key Block",
            description: "A private key block was found in the request.",
            severity: Severity::Critical,
            pattern: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            remediation: "Never include private keys in API collections. Use environment variables or key management.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC009",
            title: "Google API Key",
            description: "A Google API key was found hardcoded.",
            severity: Severity::High,
            pattern: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            remediation: "Use an environment variable for the Google API key.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC010",
            title: "SendGrid API Key",
            description: "A SendGrid API key was found hardcoded.",
            severity: Severity::High,
            pattern: Regex::new(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}").unwrap(),
            remediation: "Use an environment variable for the SendGrid API key.",
            skip_templates: false,
        },
        SecretPattern {
            id: "SEC011",
            title: "Twilio Account SID",
            description: "A Twilio account SID was found hardcoded.",
            severity: Severity::High,
            pattern: Regex::new(r"AC[a-z0-9]{32}").unwrap(),
            remediation: "Use an environment variable for the Twilio account SID.",
            skip_templates: false,
        },
    ];

    let mut rules: Vec<Box<dyn Rule>> = patterns
        .into_iter()
        .map(|p| Box::new(RegexRule(p)) as Box<dyn Rule>)
        .collect();

    // Add Bearer token rule
    rules.push(Box::new(BearerTokenRule {
        pattern: Regex::new(r"Bearer\s+([A-Za-z0-9\-_\.]{20,})").unwrap(),
    }));

    // Add Basic auth rule
    rules.push(Box::new(BasicAuthRule {
        pattern: Regex::new(r"Basic\s+([A-Za-z0-9+/=]{10,})").unwrap(),
    }));

    // Add password-in-URL rule
    rules.push(Box::new(PasswordInUrlRule {
        pattern: Regex::new(r"https?://[^:]+:[^@]+@").unwrap(),
    }));

    // Add hardcoded password field rule
    rules.push(Box::new(HardcodedPasswordRule));

    // Add high-entropy string rule
    rules.push(Box::new(HighEntropyRule));

    rules
}

// --- Regex-based rule ---

struct RegexRule(SecretPattern);

impl Rule for RegexRule {
    fn id(&self) -> &str {
        self.0.id
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan URL
        if let Some(m) = self.0.pattern.find(&request.url) {
            if !self.should_skip(m.as_str()) {
                findings.push(self.make_finding(m.as_str(), &request.source_file, "url"));
            }
        }

        // Scan headers
        for (key, value) in &request.headers {
            let combined = format!("{}: {}", key, value);
            if let Some(m) = self.0.pattern.find(&combined) {
                if !self.should_skip(m.as_str()) {
                    findings.push(self.make_finding(
                        m.as_str(),
                        &request.source_file,
                        &format!("header: {}", key),
                    ));
                }
            }
        }

        // Scan body
        if let Some(ref body) = request.body {
            if let Some(m) = self.0.pattern.find(body) {
                if !self.should_skip(m.as_str()) {
                    findings.push(self.make_finding(m.as_str(), &request.source_file, "body"));
                }
            }
        }

        // Scan auth fields
        if let Some(ref auth) = request.auth {
            let auth_text = match auth {
                crate::Auth::Bearer(t) => t.clone(),
                crate::Auth::Basic { username, password } => {
                    format!("{} {}", username, password)
                }
                crate::Auth::ApiKey { key, value } => format!("{} {}", key, value),
                crate::Auth::Other(s) => s.clone(),
            };
            if let Some(m) = self.0.pattern.find(&auth_text) {
                if !self.should_skip(m.as_str()) {
                    findings.push(self.make_finding(m.as_str(), &request.source_file, "auth"));
                }
            }
        }

        findings
    }

    fn scan_env_var(&self, _key: &str, value: &str, source_file: &Path) -> Vec<Finding> {
        if let Some(m) = self.0.pattern.find(value) {
            if !self.should_skip(m.as_str()) {
                return vec![self.make_finding(m.as_str(), source_file, "environment variable")];
            }
        }
        Vec::new()
    }
}

impl RegexRule {
    fn should_skip(&self, matched: &str) -> bool {
        self.0.skip_templates && is_template_variable(matched)
    }

    fn make_finding(&self, matched: &str, file: &Path, field: &str) -> Finding {
        Finding {
            rule_id: self.0.id.to_string(),
            severity: self.0.severity,
            title: self.0.title.to_string(),
            description: self.0.description.to_string(),
            location: Location {
                file: file.to_path_buf(),
                line: None,
                field: field.to_string(),
            },
            evidence: redact(matched),
            remediation: self.0.remediation.to_string(),
        }
    }
}

// --- SEC012: Bearer token (live) ---

struct BearerTokenRule {
    pattern: Regex,
}

impl Rule for BearerTokenRule {
    fn id(&self) -> &str {
        "SEC012"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (key, value) in &request.headers {
            if let Some(caps) = self.pattern.captures(value) {
                let token = caps.get(1).unwrap().as_str();
                if !is_template_variable(value) && !is_placeholder(token) {
                    findings.push(Finding {
                        rule_id: "SEC012".to_string(),
                        severity: Severity::High,
                        title: "Bearer Token (Hardcoded)".to_string(),
                        description: "A Bearer token appears to be hardcoded rather than using a template variable.".to_string(),
                        location: Location {
                            file: request.source_file.clone(),
                            line: None,
                            field: format!("header: {}", key),
                        },
                        evidence: redact(token),
                        remediation: "Replace the hardcoded token with an environment variable: {{token}}".to_string(),
                    });
                }
            }
        }

        // Check auth field
        if let Some(crate::Auth::Bearer(ref token)) = request.auth {
            if !is_template_variable(token) && !is_placeholder(token) && token.len() >= 20 {
                findings.push(Finding {
                    rule_id: "SEC012".to_string(),
                    severity: Severity::High,
                    title: "Bearer Token (Hardcoded)".to_string(),
                    description: "A Bearer token appears to be hardcoded rather than using a template variable.".to_string(),
                    location: Location {
                        file: request.source_file.clone(),
                        line: None,
                        field: "auth: bearer".to_string(),
                    },
                    evidence: redact(token),
                    remediation: "Replace the hardcoded token with an environment variable: {{token}}".to_string(),
                });
            }
        }

        findings
    }
}

// --- SEC013: Basic auth (hardcoded) ---

struct BasicAuthRule {
    pattern: Regex,
}

impl Rule for BasicAuthRule {
    fn id(&self) -> &str {
        "SEC013"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (key, value) in &request.headers {
            if let Some(caps) = self.pattern.captures(value) {
                let encoded = caps.get(1).unwrap().as_str();
                if !is_template_variable(value) && !is_placeholder(encoded) {
                    findings.push(Finding {
                        rule_id: "SEC013".to_string(),
                        severity: Severity::High,
                        title: "Basic Auth (Hardcoded)".to_string(),
                        description: "A Basic auth header appears to contain hardcoded credentials.".to_string(),
                        location: Location {
                            file: request.source_file.clone(),
                            line: None,
                            field: format!("header: {}", key),
                        },
                        evidence: redact(encoded),
                        remediation: "Use environment variables for Basic auth credentials.".to_string(),
                    });
                }
            }
        }

        // Check auth field
        if let Some(crate::Auth::Basic { ref username, ref password }) = request.auth {
            if !password.is_empty()
                && !is_template_variable(password)
                && !is_placeholder(password)
            {
                findings.push(Finding {
                    rule_id: "SEC013".to_string(),
                    severity: Severity::High,
                    title: "Basic Auth (Hardcoded)".to_string(),
                    description: "Basic auth credentials appear to be hardcoded.".to_string(),
                    location: Location {
                        file: request.source_file.clone(),
                        line: None,
                        field: "auth: basic".to_string(),
                    },
                    evidence: format!("{}:{}", username, redact(password)),
                    remediation: "Use environment variables for Basic auth credentials.".to_string(),
                });
            }
        }

        findings
    }
}

// --- SEC014: Password in URL ---

struct PasswordInUrlRule {
    pattern: Regex,
}

impl Rule for PasswordInUrlRule {
    fn id(&self) -> &str {
        "SEC014"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        if self.pattern.is_match(&request.url) && !is_template_variable(&request.url) {
            vec![Finding {
                rule_id: "SEC014".to_string(),
                severity: Severity::High,
                title: "Password in URL".to_string(),
                description: "Credentials are embedded in the URL.".to_string(),
                location: Location {
                    file: request.source_file.clone(),
                    line: None,
                    field: "url".to_string(),
                },
                evidence: redact(&request.url),
                remediation: "Remove credentials from the URL. Use auth headers or environment variables instead.".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

// --- SEC015: Hardcoded password field ---

struct HardcodedPasswordRule;

impl Rule for HardcodedPasswordRule {
    fn id(&self) -> &str {
        "SEC015"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        let password_keys = ["password", "passwd", "pwd"];

        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            if password_keys.iter().any(|pk| key_lower.contains(pk))
                && !value.is_empty()
                && !is_template_variable(value)
                && !is_placeholder(value)
            {
                findings.push(Finding {
                    rule_id: "SEC015".to_string(),
                    severity: Severity::High,
                    title: "Hardcoded Password Field".to_string(),
                    description: "A password field contains a hardcoded value.".to_string(),
                    location: Location {
                        file: request.source_file.clone(),
                        line: None,
                        field: format!("header: {}", key),
                    },
                    evidence: redact(value),
                    remediation: "Use an environment variable for password values.".to_string(),
                });
            }
        }

        // Check body for password fields in JSON
        if let Some(ref body) = request.body {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                check_json_passwords(&json, &request.source_file, &mut findings);
            }
        }

        findings
    }

    fn scan_env_var(&self, key: &str, value: &str, source_file: &Path) -> Vec<Finding> {
        let key_lower = key.to_lowercase();
        let password_keys = ["password", "passwd", "pwd"];

        if password_keys.iter().any(|pk| key_lower.contains(pk))
            && !value.is_empty()
            && !is_template_variable(value)
            && !is_placeholder(value)
        {
            vec![Finding {
                rule_id: "SEC015".to_string(),
                severity: Severity::High,
                title: "Hardcoded Password Field".to_string(),
                description: "A password field in an environment file contains a hardcoded value.".to_string(),
                location: Location {
                    file: source_file.to_path_buf(),
                    line: None,
                    field: format!("env: {}", key),
                },
                evidence: redact(value),
                remediation: "Avoid storing passwords directly in collection files.".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

fn check_json_passwords(value: &serde_json::Value, file: &Path, findings: &mut Vec<Finding>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if ["password", "passwd", "pwd"]
                    .iter()
                    .any(|pk| key_lower.contains(pk))
                {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() && !is_template_variable(s) && !is_placeholder(s) {
                            findings.push(Finding {
                                rule_id: "SEC015".to_string(),
                                severity: Severity::High,
                                title: "Hardcoded Password Field".to_string(),
                                description: "A password field in the request body contains a hardcoded value.".to_string(),
                                location: Location {
                                    file: file.to_path_buf(),
                                    line: None,
                                    field: format!("body: {}", key),
                                },
                                evidence: redact(s),
                                remediation: "Use an environment variable for password values.".to_string(),
                            });
                        }
                    }
                }
                check_json_passwords(val, file, findings);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                check_json_passwords(item, file, findings);
            }
        }
        _ => {}
    }
}

// --- SEC099: High Entropy String ---

struct HighEntropyRule;

impl Rule for HighEntropyRule {
    fn id(&self) -> &str {
        "SEC099"
    }

    fn scan_request(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (key, value) in &request.headers {
            // Skip well-known non-secret headers
            let key_lower = key.to_lowercase();
            if matches!(
                key_lower.as_str(),
                "content-type"
                    | "accept"
                    | "user-agent"
                    | "host"
                    | "cache-control"
                    | "connection"
                    | "accept-encoding"
                    | "accept-language"
            ) {
                continue;
            }

            if is_high_entropy_secret(value) {
                findings.push(Finding {
                    rule_id: "SEC099".to_string(),
                    severity: Severity::Medium,
                    title: "High Entropy String (Potential Secret)".to_string(),
                    description: "A high-entropy string was detected that may be a secret.".to_string(),
                    location: Location {
                        file: request.source_file.clone(),
                        line: None,
                        field: format!("header: {}", key),
                    },
                    evidence: redact(value),
                    remediation: "If this is a secret, replace it with an environment variable.".to_string(),
                });
            }
        }

        findings
    }

    fn scan_env_var(&self, key: &str, value: &str, source_file: &Path) -> Vec<Finding> {
        if is_high_entropy_secret(value) {
            vec![Finding {
                rule_id: "SEC099".to_string(),
                severity: Severity::Medium,
                title: "High Entropy String (Potential Secret)".to_string(),
                description: "A high-entropy environment variable value was detected that may be a secret.".to_string(),
                location: Location {
                    file: source_file.to_path_buf(),
                    line: None,
                    field: format!("env: {}", key),
                },
                evidence: redact(value),
                remediation: "If this is a secret, avoid storing it directly in collection files.".to_string(),
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_request(headers: Vec<(&str, &str)>) -> Request {
        Request {
            name: "Test".to_string(),
            method: "GET".to_string(),
            url: "https://api.example.com/test".to_string(),
            headers: headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: None,
            auth: None,
            source_file: PathBuf::from("test.bru"),
        }
    }

    #[test]
    fn test_detects_aws_key() {
        let rules = secret_rules();
        let rule = rules.iter().find(|r| r.id() == "SEC001").unwrap();
        let req = make_request(vec![("X-Key", "AKIAIOSFODNN7EXAMPLE")]);
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SEC001");
    }

    #[test]
    fn test_detects_github_token() {
        let rules = secret_rules();
        let rule = rules.iter().find(|r| r.id() == "SEC003").unwrap();
        let req = make_request(vec![("Authorization", "Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")]);
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_skips_template_variables_for_bearer() {
        let rules = secret_rules();
        let rule = rules.iter().find(|r| r.id() == "SEC012").unwrap();
        let req = make_request(vec![("Authorization", "Bearer {{token}}")]);
        let findings = rule.scan_request(&req);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_password_in_url() {
        let rules = secret_rules();
        let rule = rules.iter().find(|r| r.id() == "SEC014").unwrap();
        let mut req = make_request(vec![]);
        req.url = "https://admin:secret123@api.example.com/data".to_string();
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_detects_hardcoded_password_in_body() {
        let rules = secret_rules();
        let rule = rules.iter().find(|r| r.id() == "SEC015").unwrap();
        let mut req = make_request(vec![]);
        req.body = Some(r#"{"username": "admin", "password": "supersecret123"}"#.to_string());
        let findings = rule.scan_request(&req);
        assert_eq!(findings.len(), 1);
    }
}
