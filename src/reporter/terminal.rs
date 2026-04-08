use colored::Colorize;

use crate::{Finding, Severity};

use super::{Reporter, ScanContext};

pub struct TerminalReporter;

impl Reporter for TerminalReporter {
    fn render(&self, findings: &[Finding], ctx: &ScanContext) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{} — API Security Scanner\n\n",
            format!("ferret v{}", env!("CARGO_PKG_VERSION")).bold()
        ));

        out.push_str(&format!(
            "Scanning: {} ({} collection)\n",
            ctx.collection_path, ctx.collection_type
        ));
        out.push_str(&format!("Found {} requests\n\n", ctx.request_count));

        if findings.is_empty() {
            out.push_str(&"No findings. All clear!".green().bold().to_string());
            out.push('\n');
            return out;
        }

        // Summary
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
        let info = findings.iter().filter(|f| f.severity == Severity::Info).count();

        let separator = "━".repeat(42);
        out.push_str(&separator);
        out.push('\n');
        out.push_str(" FINDINGS SUMMARY\n");
        out.push_str(&separator);
        out.push('\n');

        if critical > 0 {
            out.push_str(&format!(
                " {}  {}\n",
                "Critical".red().bold(),
                critical
            ));
        }
        if high > 0 {
            out.push_str(&format!(" {}      {}\n", "High".red(), high));
        }
        if medium > 0 {
            out.push_str(&format!(" {}    {}\n", "Medium".yellow(), medium));
        }
        if low > 0 {
            out.push_str(&format!(" {}       {}\n", "Low".blue(), low));
        }
        if info > 0 {
            out.push_str(&format!(" {}      {}\n", "Info".dimmed(), info));
        }

        out.push_str(&separator);
        out.push_str("\n\n");

        // Individual findings
        for finding in findings {
            let severity_tag = match finding.severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".red().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::Low => "LOW".blue().to_string(),
                Severity::Info => "INFO".dimmed().to_string(),
            };

            out.push_str(&format!(
                "[{}] {} — {}\n",
                severity_tag, finding.rule_id, finding.title
            ));
            out.push_str(&format!(
                "  File:     {}\n",
                finding.location.file.display()
            ));
            out.push_str(&format!("  Field:    {}\n", finding.location.field));
            out.push_str(&format!("  Evidence: {}\n", finding.evidence));
            out.push_str(&format!("  Fix:      {}\n\n", finding.remediation));
        }

        out.push_str(&format!(
            "Run `ferret scan . --format html --output report.html` to generate a full report.\n"
        ));

        out
    }
}
