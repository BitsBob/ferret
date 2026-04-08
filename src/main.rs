use std::process;

use clap::Parser;

use ferret::cli::{Cli, Commands, OutputFormat};
use ferret::parsers;
use ferret::reporter::terminal::TerminalReporter;
use ferret::reporter::json::JsonReporter;
use ferret::reporter::html::HtmlReporter;
use ferret::reporter::{Reporter, ScanContext};
use ferret::scanner::Scanner;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            fail_on,
        } => {
            let path = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: cannot access '{}': {}", path.display(), e);
                    process::exit(2);
                }
            };

            // Parse the collection
            let collection = match parsers::parse(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            };

            let ctx = ScanContext {
                collection_type: collection.collection_type,
                collection_path: path.display().to_string(),
                request_count: collection.requests.len(),
            };

            // Scan
            let scanner = Scanner::new();
            let findings = scanner.scan(&collection);

            // Report
            let reporter: Box<dyn Reporter> = match format {
                OutputFormat::Text => Box::new(TerminalReporter),
                OutputFormat::Json => Box::new(JsonReporter),
                OutputFormat::Html => Box::new(HtmlReporter),
            };

            let report = reporter.render(&findings, &ctx);

            if let Some(output_path) = output {
                if let Err(e) = std::fs::write(&output_path, &report) {
                    eprintln!("Error: failed to write report to {}: {}", output_path.display(), e);
                    process::exit(2);
                }
                eprintln!("Report written to {}", output_path.display());
            } else {
                print!("{}", report);
            }

            // Exit code based on --fail-on
            if let Some(fail_level) = fail_on {
                let threshold = fail_level.to_severity();
                if findings.iter().any(|f| f.severity >= threshold) {
                    process::exit(1);
                }
            }
        }
    }
}
