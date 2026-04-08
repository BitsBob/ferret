use std::path::Path;

use serde::Deserialize;

use crate::Request;

use super::{CollectionType, ParsedCollection};

/// Parse an Insomnia v4 export JSON file.
pub fn parse(path: &Path) -> Result<ParsedCollection, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let export: InsomniaExport = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse Insomnia export {}: {}", path.display(), e))?;

    let mut requests = Vec::new();
    let mut env_vars = Vec::new();

    for resource in &export.resources {
        match resource._type.as_str() {
            "request" => {
                let method = resource.method.clone().unwrap_or_else(|| "GET".to_string());
                let url = resource.url.clone().unwrap_or_default();

                let mut headers = Vec::new();
                if let Some(ref hdrs) = resource.headers {
                    for h in hdrs {
                        headers.push((h.name.clone(), h.value.clone()));
                    }
                }

                let body = resource
                    .body
                    .as_ref()
                    .and_then(|b| b.text.clone());

                let auth = resource.authentication.as_ref().and_then(|a| {
                    match a._type.as_deref() {
                        Some("bearer") => {
                            a.token.clone().map(crate::Auth::Bearer)
                        }
                        Some("basic") => Some(crate::Auth::Basic {
                            username: a.username.clone().unwrap_or_default(),
                            password: a.password.clone().unwrap_or_default(),
                        }),
                        _ => None,
                    }
                });

                requests.push(Request {
                    name: resource.name.clone().unwrap_or_default(),
                    method,
                    url,
                    headers,
                    body,
                    auth,
                    source_file: path.to_path_buf(),
                });
            }
            "environment" => {
                if let Some(ref data) = resource.data {
                    for (key, value) in data {
                        if let Some(s) = value.as_str() {
                            env_vars.push((key.clone(), s.to_string(), path.to_path_buf()));
                        }
                    }
                }
            }
            _ => {} // skip request_group, workspace, etc.
        }
    }

    Ok(ParsedCollection {
        collection_type: CollectionType::Insomnia,
        requests,
        env_vars,
    })
}

// --- Insomnia JSON schema types ---

#[derive(Deserialize)]
struct InsomniaExport {
    #[allow(dead_code)]
    _type: String, // "export"
    resources: Vec<InsomniaResource>,
}

#[derive(Deserialize)]
struct InsomniaResource {
    _type: String,
    name: Option<String>,
    method: Option<String>,
    url: Option<String>,
    headers: Option<Vec<InsomniaHeader>>,
    body: Option<InsomniaBody>,
    authentication: Option<InsomniaAuth>,
    data: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct InsomniaHeader {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct InsomniaBody {
    text: Option<String>,
}

#[derive(Deserialize)]
struct InsomniaAuth {
    #[serde(rename = "type")]
    _type: Option<String>,
    token: Option<String>,
    username: Option<String>,
    password: Option<String>,
}
