use crate::{Finding, Severity};

use super::{Reporter, ScanContext};

pub struct HtmlReporter;

impl Reporter for HtmlReporter {
    fn render(&self, findings: &[Finding], ctx: &ScanContext) -> String {
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

        let mut findings_html = String::new();
        for finding in findings {
            let severity_class = finding.severity.as_str();
            findings_html.push_str(&format!(
                r#"<div class="finding {severity_class}">
  <div class="finding-header">
    <span class="severity-badge {severity_class}">{severity}</span>
    <span class="rule-id">{rule_id}</span>
    <span class="title">{title}</span>
  </div>
  <div class="finding-body">
    <div class="detail"><strong>File:</strong> {file}</div>
    <div class="detail"><strong>Field:</strong> {field}</div>
    <div class="detail"><strong>Evidence:</strong> <code>{evidence}</code></div>
    <div class="detail"><strong>Description:</strong> {description}</div>
    <div class="remediation"><strong>Fix:</strong> {remediation}</div>
  </div>
</div>
"#,
                severity_class = severity_class,
                severity = finding.severity.label(),
                rule_id = html_escape(&finding.rule_id),
                title = html_escape(&finding.title),
                file = html_escape(&finding.location.file.display().to_string()),
                field = html_escape(&finding.location.field),
                evidence = html_escape(&finding.evidence),
                description = html_escape(&finding.description),
                remediation = html_escape(&finding.remediation),
            ));
        }

        format!(
            r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ferret Security Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f1117; color: #c9d1d9; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ color: #f0f6fc; margin-bottom: 0.5rem; }}
  .meta {{ color: #8b949e; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; text-align: center; min-width: 100px; }}
  .summary-card .count {{ font-size: 2rem; font-weight: bold; }}
  .summary-card .label {{ font-size: 0.85rem; color: #8b949e; }}
  .summary-card.critical .count {{ color: #f85149; }}
  .summary-card.high .count {{ color: #da3633; }}
  .summary-card.medium .count {{ color: #d29922; }}
  .summary-card.low .count {{ color: #58a6ff; }}
  .summary-card.info .count {{ color: #8b949e; }}
  .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .finding-header {{ padding: 0.75rem 1rem; display: flex; align-items: center; gap: 0.75rem; cursor: pointer; }}
  .finding-body {{ padding: 0 1rem 1rem; }}
  .severity-badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; color: #fff; }}
  .severity-badge.critical {{ background: #f85149; }}
  .severity-badge.high {{ background: #da3633; }}
  .severity-badge.medium {{ background: #d29922; }}
  .severity-badge.low {{ background: #58a6ff; }}
  .severity-badge.info {{ background: #6e7681; }}
  .rule-id {{ color: #8b949e; font-family: monospace; }}
  .title {{ color: #f0f6fc; font-weight: 600; }}
  .detail {{ margin-bottom: 0.4rem; font-size: 0.9rem; }}
  .detail code {{ background: #0d1117; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
  .remediation {{ margin-top: 0.5rem; padding: 0.5rem; background: #0d1117; border-radius: 4px; border-left: 3px solid #3fb950; font-size: 0.9rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Ferret Security Report</h1>
  <div class="meta">
    <div>Collection: {path} ({collection_type})</div>
    <div>Requests scanned: {request_count}</div>
    <div>Ferret v{version}</div>
    <div>Generated: {timestamp}</div>
  </div>
  <div class="summary">
    <div class="summary-card critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="count">{high}</div><div class="label">High</div></div>
    <div class="summary-card medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="count">{low}</div><div class="label">Low</div></div>
    <div class="summary-card info"><div class="count">{info}</div><div class="label">Info</div></div>
  </div>
  <div class="findings">
    {findings_html}
  </div>
</div>
</body>
</html>"##,
            path = html_escape(&ctx.collection_path),
            collection_type = ctx.collection_type,
            request_count = ctx.request_count,
            version = env!("CARGO_PKG_VERSION"),
            timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            critical = critical,
            high = high,
            medium = medium,
            low = low,
            info = info,
            findings_html = findings_html,
        )
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
