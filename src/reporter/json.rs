use serde::Serialize;

use crate::{Finding, Severity};

use super::{Reporter, ScanContext};

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn render(&self, findings: &[Finding], ctx: &ScanContext) -> String {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

        let report = JsonReport {
            ferret_version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            collection: CollectionInfo {
                collection_type: ctx.collection_type.as_str().to_lowercase(),
                path: ctx.collection_path.clone(),
                request_count: ctx.request_count,
            },
            summary: Summary {
                critical,
                high,
                medium,
                low,
                info,
            },
            findings: findings.iter().map(|f| JsonFinding::from(f)).collect(),
        };

        serde_json::to_string_pretty(&report).unwrap()
    }
}

#[derive(Serialize)]
struct JsonReport {
    ferret_version: String,
    scanned_at: String,
    collection: CollectionInfo,
    summary: Summary,
    findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
struct CollectionInfo {
    #[serde(rename = "type")]
    collection_type: String,
    path: String,
    request_count: usize,
}

#[derive(Serialize)]
struct Summary {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

#[derive(Serialize)]
struct JsonFinding {
    rule_id: String,
    severity: String,
    title: String,
    description: String,
    location: JsonLocation,
    evidence: String,
    remediation: String,
}

#[derive(Serialize)]
struct JsonLocation {
    file: String,
    line: Option<usize>,
    field: String,
}

impl From<&Finding> for JsonFinding {
    fn from(f: &Finding) -> Self {
        JsonFinding {
            rule_id: f.rule_id.clone(),
            severity: f.severity.as_str().to_string(),
            title: f.title.clone(),
            description: f.description.clone(),
            location: JsonLocation {
                file: f.location.file.display().to_string(),
                line: f.location.line,
                field: f.location.field.clone(),
            },
            evidence: f.evidence.clone(),
            remediation: f.remediation.clone(),
        }
    }
}
