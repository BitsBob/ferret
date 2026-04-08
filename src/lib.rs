pub mod cli;
pub mod entropy;
pub mod parsers;
pub mod reporter;
pub mod scanner;

use std::path::PathBuf;

/// A single request extracted from any collection format.
#[derive(Debug, Clone)]
pub struct Request {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub auth: Option<Auth>,
    pub source_file: PathBuf,
}

/// Authentication information attached to a request.
#[derive(Debug, Clone)]
pub enum Auth {
    Bearer(String),
    Basic { username: String, password: String },
    ApiKey { key: String, value: String },
    Other(String),
}

/// A security finding produced by a scanner rule.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: Location,
    pub evidence: String,
    pub remediation: String,
}

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!("unknown severity: {s}")),
        }
    }
}

/// Location within a collection file where a finding was detected.
#[derive(Debug, Clone)]
pub struct Location {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub field: String,
}

/// Redact a secret value for display: show first 4 chars then bullets.
pub fn redact(value: &str) -> String {
    if value.len() <= 4 {
        "••••".to_string()
    } else {
        let prefix: String = value.chars().take(4).collect();
        let bullet_count = value.len().min(24) - 4;
        format!("{}{}", prefix, "•".repeat(bullet_count))
    }
}
