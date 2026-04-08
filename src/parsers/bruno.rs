use std::path::Path;

use walkdir::WalkDir;

use crate::Request;

use super::{CollectionType, ParsedCollection};

/// Parse a Bruno collection directory.
pub fn parse(dir: &Path) -> Result<ParsedCollection, String> {
    let mut requests = Vec::new();
    let mut env_vars = Vec::new();

    // Parse .env files
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(".env") || n == "environment.bru")
        })
    {
        let content = std::fs::read_to_string(entry.path()).map_err(|e| {
            format!(
                "Failed to read env file {}: {}",
                entry.path().display(),
                e
            )
        })?;

        if entry.file_name().to_str().is_some_and(|n| n.starts_with(".env")) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    env_vars.push((
                        key.trim().to_string(),
                        value.trim().to_string(),
                        entry.path().to_path_buf(),
                    ));
                }
            }
        } else {
            // environment.bru format: vars { key: value }
            parse_env_bru(&content, entry.path(), &mut env_vars);
        }
    }

    // Parse .bru request files
    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bru"))
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n != "environment.bru")
        })
    {
        let content = std::fs::read_to_string(entry.path()).map_err(|e| {
            format!(
                "Failed to read .bru file {}: {}",
                entry.path().display(),
                e
            )
        })?;

        if let Some(req) = parse_bru_file(&content, entry.path()) {
            requests.push(req);
        }
    }

    Ok(ParsedCollection {
        collection_type: CollectionType::Bruno,
        requests,
        env_vars,
    })
}

fn parse_env_bru(content: &str, path: &Path, env_vars: &mut Vec<(String, String, std::path::PathBuf)>) {
    let mut in_vars = false;
    let mut brace_depth = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("vars") && trimmed.contains('{') {
            in_vars = true;
            brace_depth += trimmed.matches('{').count();
            brace_depth -= trimmed.matches('}').count();
            continue;
        }

        if in_vars {
            brace_depth += trimmed.matches('{').count();
            brace_depth -= trimmed.matches('}').count();

            if brace_depth == 0 {
                in_vars = false;
                continue;
            }

            // Parse "key: value" lines
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if !key.is_empty() && !key.starts_with('~') {
                    env_vars.push((key.to_string(), value.to_string(), path.to_path_buf()));
                }
            }
        }
    }
}

/// Parse a single .bru file into a Request.
fn parse_bru_file(content: &str, path: &Path) -> Option<Request> {
    let mut name = String::new();
    let mut method = String::new();
    let mut url = String::new();
    let mut headers = Vec::new();
    let mut body: Option<String> = None;
    let mut auth: Option<crate::Auth> = None;

    let mut current_block: Option<String> = None;
    let mut brace_depth = 0;
    let mut block_lines: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect block start
        if brace_depth == 0 {
            if let Some(block_name) = detect_block_start(trimmed) {
                current_block = Some(block_name);
                brace_depth = 1;
                block_lines.clear();
                continue;
            }
        }

        if brace_depth > 0 {
            let opens = trimmed.matches('{').count();
            let closes = trimmed.matches('}').count();
            brace_depth += opens;
            brace_depth = brace_depth.saturating_sub(closes);

            if brace_depth == 0 {
                // Block ended — process it
                if let Some(ref block) = current_block {
                    match block.as_str() {
                        "meta" => {
                            for bl in &block_lines {
                                if let Some((k, v)) = parse_kv(bl) {
                                    if k == "name" {
                                        name = v;
                                    }
                                }
                            }
                        }
                        "get" | "post" | "put" | "patch" | "delete" | "options" | "head" => {
                            method = block.to_uppercase();
                            for bl in &block_lines {
                                if let Some((k, v)) = parse_kv(bl) {
                                    if k == "url" {
                                        url = v;
                                    }
                                }
                            }
                        }
                        "headers" => {
                            for bl in &block_lines {
                                if let Some((k, v)) = parse_kv(bl) {
                                    headers.push((k, v));
                                }
                            }
                        }
                        b if b.starts_with("body") => {
                            body = Some(block_lines.join("\n"));
                        }
                        "auth:bearer" => {
                            for bl in &block_lines {
                                if let Some((k, v)) = parse_kv(bl) {
                                    if k == "token" {
                                        auth = Some(crate::Auth::Bearer(v));
                                    }
                                }
                            }
                        }
                        "auth:basic" => {
                            let mut username = String::new();
                            let mut password = String::new();
                            for bl in &block_lines {
                                if let Some((k, v)) = parse_kv(bl) {
                                    match k.as_str() {
                                        "username" => username = v,
                                        "password" => password = v,
                                        _ => {}
                                    }
                                }
                            }
                            auth = Some(crate::Auth::Basic { username, password });
                        }
                        _ => {}
                    }
                }
                current_block = None;
                block_lines.clear();
            } else {
                block_lines.push(trimmed.to_string());
            }
        }
    }

    if method.is_empty() && url.is_empty() {
        return None;
    }

    Some(Request {
        name: if name.is_empty() {
            path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        } else {
            name
        },
        method,
        url,
        headers,
        body,
        auth,
        source_file: path.to_path_buf(),
    })
}

/// Detect a block start line like "get {" or "headers {" or "body:json {".
fn detect_block_start(line: &str) -> Option<String> {
    if !line.ends_with('{') {
        return None;
    }
    let name = line.trim_end_matches('{').trim();
    if name.is_empty() {
        return None;
    }
    // Valid block names are alphanumeric with optional : separator
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_')
    {
        Some(name.to_string())
    } else {
        None
    }
}

/// Parse a "key: value" line.
fn parse_kv(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let (key, value) = trimmed.split_once(':')?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_bru_file() {
        let content = r#"meta {
  name: Get Users
  type: http
  seq: 1
}

get {
  url: https://api.example.com/users
}

headers {
  Authorization: Bearer {{token}}
  X-Api-Key: sk_live_abc123xyz
}

body:json {
  {
    "limit": 10
  }
}
"#;
        let req = parse_bru_file(content, &PathBuf::from("test.bru")).unwrap();
        assert_eq!(req.name, "Get Users");
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://api.example.com/users");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].0, "Authorization");
        assert_eq!(req.headers[0].1, "Bearer {{token}}");
        assert_eq!(req.headers[1].0, "X-Api-Key");
        assert_eq!(req.headers[1].1, "sk_live_abc123xyz");
        assert!(req.body.is_some());
    }
}
