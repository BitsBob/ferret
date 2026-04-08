use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "ferret",
    version,
    about = "Ferret out secrets and vulnerabilities in your API collections"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan an API collection for secrets and vulnerabilities
    Scan {
        /// Path to the collection directory or file
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Write report to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Exit with code 1 if findings at or above this severity
        #[arg(long, value_enum)]
        fail_on: Option<FailOnLevel>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Html,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FailOnLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnLevel {
    pub fn to_severity(self) -> crate::Severity {
        match self {
            FailOnLevel::Info => crate::Severity::Info,
            FailOnLevel::Low => crate::Severity::Low,
            FailOnLevel::Medium => crate::Severity::Medium,
            FailOnLevel::High => crate::Severity::High,
            FailOnLevel::Critical => crate::Severity::Critical,
        }
    }
}
