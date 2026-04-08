use std::path::Path;

use serde::Deserialize;

use crate::Request;

use super::{CollectionType, ParsedCollection};

/// Parse a Postman Collection v2.0/v2.1 JSON file.
pub fn parse(path: &Path) -> Result<ParsedCollection, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let collection: PostmanCollection = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse Postman collection {}: {}", path.display(), e))?;

    let mut requests = Vec::new();
    extract_requests(&collection.item, path, &mut requests);

    Ok(ParsedCollection {
        collection_type: CollectionType::Postman,
        requests,
        env_vars: Vec::new(),
    })
}

fn extract_requests(items: &[PostmanItem], source: &Path, requests: &mut Vec<Request>) {
    for item in items {
        // Recurse into folders
        if let Some(ref children) = item.item {
            extract_requests(children, source, requests);
            continue;
        }

        if let Some(ref request) = item.request {
            let method = match &request.method {
                Some(m) => m.clone(),
                None => "GET".to_string(),
            };

            let url = match &request.url {
                Some(PostmanUrl::String(s)) => s.clone(),
                Some(PostmanUrl::Object { raw, .. }) => raw.clone().unwrap_or_default(),
                None => String::new(),
            };

            let mut headers = Vec::new();
            if let Some(ref hdrs) = request.header {
                for h in hdrs {
                    headers.push((h.key.clone(), h.value.clone()));
                }
            }

            let body = request.body.as_ref().and_then(|b| b.raw.clone());

            let auth = request.auth.as_ref().and_then(|a| convert_auth(a));

            // Collect script text for scanning
            let mut extra_text = Vec::new();
            if let Some(ref events) = item.event {
                for event in events {
                    if let Some(ref script) = event.script {
                        if let Some(ref exec) = script.exec {
                            extra_text.push(exec.join("\n"));
                        }
                    }
                }
            }

            let mut full_body = body;
            if !extra_text.is_empty() {
                let script_text = extra_text.join("\n");
                full_body = Some(match full_body {
                    Some(b) => format!("{}\n{}", b, script_text),
                    None => script_text,
                });
            }

            requests.push(Request {
                name: item.name.clone().unwrap_or_default(),
                method,
                url,
                headers,
                body: full_body,
                auth,
                source_file: source.to_path_buf(),
            });
        }
    }
}

fn convert_auth(auth: &PostmanAuth) -> Option<crate::Auth> {
    match auth.auth_type.as_str() {
        "bearer" => {
            let token = auth
                .bearer
                .as_ref()?
                .iter()
                .find(|kv| kv.key == "token")
                .map(|kv| kv.value.clone())?;
            Some(crate::Auth::Bearer(token))
        }
        "basic" => {
            let items = auth.basic.as_ref()?;
            let username = items
                .iter()
                .find(|kv| kv.key == "username")
                .map(|kv| kv.value.clone())
                .unwrap_or_default();
            let password = items
                .iter()
                .find(|kv| kv.key == "password")
                .map(|kv| kv.value.clone())
                .unwrap_or_default();
            Some(crate::Auth::Basic { username, password })
        }
        "apikey" => {
            let items = auth.apikey.as_ref()?;
            let key = items
                .iter()
                .find(|kv| kv.key == "key")
                .map(|kv| kv.value.clone())
                .unwrap_or_default();
            let value = items
                .iter()
                .find(|kv| kv.key == "value")
                .map(|kv| kv.value.clone())
                .unwrap_or_default();
            Some(crate::Auth::ApiKey { key, value })
        }
        _ => None,
    }
}

// --- Postman JSON schema types ---

#[derive(Deserialize)]
struct PostmanCollection {
    #[allow(dead_code)]
    info: serde_json::Value,
    item: Vec<PostmanItem>,
}

#[derive(Deserialize)]
struct PostmanItem {
    name: Option<String>,
    request: Option<PostmanRequest>,
    item: Option<Vec<PostmanItem>>,
    event: Option<Vec<PostmanEvent>>,
}

#[derive(Deserialize)]
struct PostmanRequest {
    method: Option<String>,
    url: Option<PostmanUrl>,
    header: Option<Vec<PostmanHeader>>,
    body: Option<PostmanBody>,
    auth: Option<PostmanAuth>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PostmanUrl {
    String(String),
    Object {
        raw: Option<String>,
    },
}

#[derive(Deserialize)]
struct PostmanHeader {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct PostmanBody {
    raw: Option<String>,
}

#[derive(Deserialize)]
struct PostmanAuth {
    #[serde(rename = "type")]
    auth_type: String,
    bearer: Option<Vec<PostmanKV>>,
    basic: Option<Vec<PostmanKV>>,
    apikey: Option<Vec<PostmanKV>>,
}

#[derive(Deserialize)]
struct PostmanKV {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct PostmanEvent {
    script: Option<PostmanScript>,
}

#[derive(Deserialize)]
struct PostmanScript {
    exec: Option<Vec<String>>,
}
