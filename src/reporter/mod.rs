pub mod html;
pub mod json;
pub mod terminal;

use crate::Finding;
use crate::parsers::CollectionType;

/// Metadata about the scan for reporters.
pub struct ScanContext {
    pub collection_type: CollectionType,
    pub collection_path: String,
    pub request_count: usize,
}

/// Trait for report output formatters.
pub trait Reporter {
    fn render(&self, findings: &[Finding], ctx: &ScanContext) -> String;
}
