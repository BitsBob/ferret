pub mod owasp;
pub mod rules;
pub mod secrets;

use crate::parsers::ParsedCollection;
use crate::Finding;

use self::rules::Rule;

/// The main scanner that orchestrates all rules.
pub struct Scanner {
    rules: Vec<Box<dyn Rule>>,
}

impl Scanner {
    /// Create a scanner with all default rules.
    pub fn new() -> Self {
        let mut rules = Vec::new();
        rules.extend(secrets::secret_rules());
        rules.extend(owasp::owasp_rules());
        Scanner { rules }
    }

    /// Scan a parsed collection and return all findings.
    pub fn scan(&self, collection: &ParsedCollection) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan each request with all rules
        for request in &collection.requests {
            for rule in &self.rules {
                findings.extend(rule.scan_request(request));
            }
        }

        // Scan environment variables with all rules
        for (key, value, source_file) in &collection.env_vars {
            for rule in &self.rules {
                findings.extend(rule.scan_env_var(key, value, source_file));
            }
        }

        // Deduplicate findings by (rule_id, file, field, evidence)
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        findings.dedup_by(|a, b| {
            a.rule_id == b.rule_id
                && a.location.file == b.location.file
                && a.location.field == b.location.field
                && a.evidence == b.evidence
        });

        findings
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
