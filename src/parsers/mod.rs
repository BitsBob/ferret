pub mod bruno;
pub mod insomnia;
pub mod postman;

use std::path::Path;

use crate::Request;

/// Detected collection type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionType {
    Bruno,
    Postman,
    Insomnia,
}

impl CollectionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CollectionType::Bruno => "Bruno",
            CollectionType::Postman => "Postman",
            CollectionType::Insomnia => "Insomnia",
        }
    }
}

impl std::fmt::Display for CollectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of parsing a collection.
pub struct ParsedCollection {
    pub collection_type: CollectionType,
    pub requests: Vec<Request>,
    /// Environment variables found (key, value, source file).
    pub env_vars: Vec<(String, String, std::path::PathBuf)>,
}

/// Auto-detect collection type and parse the given path.
pub fn parse(path: &Path) -> Result<ParsedCollection, String> {
    let collection_type = detect_collection_type(path)?;

    match collection_type {
        CollectionType::Bruno => bruno::parse(path),
        CollectionType::Postman => postman::parse(path),
        CollectionType::Insomnia => insomnia::parse(path),
    }
}

/// Detect the collection type from a path.
pub fn detect_collection_type(path: &Path) -> Result<CollectionType, String> {
    if path.is_dir() {
        // Check for Bruno collection markers
        if path.join("bruno.json").exists() {
            return Ok(CollectionType::Bruno);
        }

        // Check for .bru files in the directory tree
        if has_bru_files(path) {
            return Ok(CollectionType::Bruno);
        }

        return Err(format!(
            "Could not detect collection type in directory: {}. \
             Expected a Bruno collection (with .bru files or bruno.json), \
             or pass a Postman/Insomnia JSON export file directly.",
            path.display()
        ));
    }

    // It's a file — inspect the JSON
    if path.extension().is_some_and(|ext| ext == "json") {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        let value: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON in {}: {}", path.display(), e))?;

        // Check for Postman: has info._postman_id or info.schema containing "postman"
        if let Some(info) = value.get("info") {
            if info.get("_postman_id").is_some() {
                return Ok(CollectionType::Postman);
            }
            if let Some(schema) = info.get("schema").and_then(|s| s.as_str()) {
                if schema.contains("postman") {
                    return Ok(CollectionType::Postman);
                }
            }
        }

        // Check for Insomnia: has _type: "export"
        if value.get("_type").and_then(|t| t.as_str()) == Some("export") {
            return Ok(CollectionType::Insomnia);
        }

        return Err(format!(
            "Could not detect collection type in {}: \
             not recognized as Postman or Insomnia format. \
             Check that the file is a valid collection export.",
            path.display()
        ));
    }

    Err(format!(
        "Unsupported file type: {}. Expected a .json export file or a directory.",
        path.display()
    ))
}

fn has_bru_files(dir: &Path) -> bool {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|e| e.path().extension().is_some_and(|ext| ext == "bru"))
}
