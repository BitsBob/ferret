use crate::{Finding, Request};

/// Trait implemented by each scanner rule.
pub trait Rule: Send + Sync {
    /// Unique rule identifier (e.g. "SEC001").
    fn id(&self) -> &str;

    /// Scan a request and return any findings.
    fn scan_request(&self, request: &Request) -> Vec<Finding>;

    /// Scan an environment variable and return any findings.
    /// Default implementation returns no findings.
    fn scan_env_var(
        &self,
        _key: &str,
        _value: &str,
        _source_file: &std::path::Path,
    ) -> Vec<Finding> {
        Vec::new()
    }
}
