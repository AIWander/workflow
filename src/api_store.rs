//! API Discovery Storage & Replay
//! 5 tools: api_store, api_call, api_list, api_test, api_delete

use crate::storage::JsonStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ApiStore {
    pub apis: Vec<ApiPattern>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ApiPattern {
    pub name: String,
    pub url_pattern: String,
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body_template: Option<Value>,
    #[serde(default)]
    pub response_shape: Option<Vec<String>>,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub last_used: Option<String>,
}

const FILE: &str = "apis.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    match tool {
        "api_store" => api_store(args, store),
        "api_call" => api_call(args, store),
        "api_list" => api_list(args, store),
        "api_test" => api_test(args, store),
        "api_delete" => api_delete(args, store),
        _ => json!({"error": format!("Unknown api tool: {}", tool)}),
    }
}

fn api_store(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let url_pattern = match args.get("url_pattern").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => return json!({"error": "url_pattern is required"}),
    };
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();

    let headers: HashMap<String, String> = args
        .get("headers")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();

    let body_template = args.get("body_template").cloned();
    let response_shape = args
        .get("response_shape")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let credential_ref = args
        .get("credential_ref")
        .and_then(|v| v.as_str())
        .map(String::from);
    let notes = args.get("notes").and_then(|v| v.as_str()).map(String::from);

    let mut data: ApiStore = store.load_or_default(FILE);

    // Replace if name exists
    data.apis.retain(|a| a.name != name);

    data.apis.push(ApiPattern {
        name: name.clone(),
        url_pattern,
        method,
        headers,
        body_template,
        response_shape,
        credential_ref,
        notes,
        created_at: Utc::now().to_rfc3339(),
        last_used: None,
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "name": name, "total_apis": data.apis.len()}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn api_call(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let data: ApiStore = store.load_or_default(FILE);
    let api = match data.apis.iter().find(|a| a.name == name) {
        Some(a) => a,
        None => return json!({"error": format!("API '{}' not found", name)}),
    };

    // Resolve URL placeholders
    let params = args.get("params").and_then(|v| v.as_object());
    let mut url = api.url_pattern.clone();
    if let Some(p) = params {
        for (key, val) in p {
            let placeholder = format!("{{{}}}", key);
            url = url.replace(&placeholder, val.as_str().unwrap_or(&val.to_string()));
        }
    }

    // Build headers
    let mut headers = api.headers.clone();
    if let Some(extra) = args.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in extra {
            headers.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }

    // Resolve credential
    let cred_ref = args
        .get("credential_ref")
        .and_then(|v| v.as_str())
        .or(api.credential_ref.as_deref());
    if let Some(cref) = cred_ref {
        if let Ok(cred_val) = crate::credential::get_credential_value(cref, store) {
            let cred_type = crate::credential::get_credential_type(cref, store).unwrap_or_default();
            match cred_type.as_str() {
                "bearer" => {
                    headers.insert("Authorization".into(), format!("Bearer {}", cred_val));
                }
                "api_key" => {
                    headers.insert("X-API-Key".into(), cred_val);
                }
                "basic" => {
                    headers.insert("Authorization".into(), format!("Basic {}", cred_val));
                }
                "cookie" => {
                    headers.insert("Cookie".into(), cred_val);
                }
                _ => {
                    headers.insert("Authorization".into(), cred_val);
                }
            }
        }
    }

    // Build body — apply same placeholder substitution as URL
    let body = args.get("body").cloned().or_else(|| {
        let mut tmpl = api.body_template.clone()?;
        if let Some(p) = params {
            let mut s = tmpl.to_string();
            for (key, val) in p {
                let placeholder = format!("{{{}}}", key);
                s = s.replace(&placeholder, val.as_str().unwrap_or(&val.to_string()));
            }
            tmpl = serde_json::from_str(&s).unwrap_or(Value::String(s));
        }
        Some(tmpl)
    });

    let method = api.method.clone();

    // Update last_used
    let mut data_mut: ApiStore = store.load_or_default(FILE);
    if let Some(a) = data_mut.apis.iter_mut().find(|a| a.name == name) {
        a.last_used = Some(Utc::now().to_rfc3339());
    }
    let _ = store.save(FILE, &data_mut);

    // Execute HTTP request synchronously within the tokio runtime
    let rt = tokio::runtime::Handle::current();
    let result = rt.block_on(async {
        let client = reqwest::Client::new();
        let mut req = match method.as_str() {
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            "PATCH" => client.patch(&url),
            "HEAD" => client.head(&url),
            _ => client.get(&url),
        };

        for (k, v) in &headers {
            req = req.header(k, v);
        }

        if let Some(b) = &body {
            req = req.json(b);
        }

        let start = std::time::Instant::now();
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_headers: HashMap<String, String> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body_text = resp.text().await.unwrap_or_default();
                let elapsed = start.elapsed().as_millis();

                let body_val =
                    serde_json::from_str::<Value>(&body_text).unwrap_or_else(|_| json!(body_text));

                let mut result = json!({
                    "success": (200..300).contains(&status),
                    "status": status,
                    "response_time_ms": elapsed,
                    "headers": resp_headers,
                    "body": body_val,
                });

                if !(200..300).contains(&status) {
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert(
                            "fallback_hint".into(),
                            json!("API failed — consider replaying via browser UI"),
                        );
                    }
                }
                result
            }
            Err(e) => json!({
                "success": false,
                "error": format!("Request failed: {}", e),
                "fallback_hint": "API failed — consider replaying via browser UI",
            }),
        }
    });

    result
}

fn api_list(args: &Value, store: &JsonStore) -> Value {
    let data: ApiStore = store.load_or_default(FILE);
    let filter = args.get("filter").and_then(|v| v.as_str());
    let filter_re = filter.and_then(|f| regex::Regex::new(f).ok());

    let apis: Vec<Value> = data
        .apis
        .iter()
        .filter(|a| {
            if let Some(ref re) = filter_re {
                re.is_match(&a.name) || re.is_match(&a.url_pattern)
            } else {
                true
            }
        })
        .map(|a| {
            json!({
                "name": a.name,
                "method": a.method,
                "url_pattern": a.url_pattern,
                "credential_ref": a.credential_ref,
                "last_used": a.last_used,
                "created_at": a.created_at,
            })
        })
        .collect();

    json!({"apis": apis, "count": apis.len()})
}

fn api_test(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let result = api_call(&json!({"name": name, "params": args.get("params")}), store);
    let works = result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let status = result.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
    let time = result
        .get("response_time_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let error = result.get("error").cloned();

    json!({
        "works": works,
        "status": status,
        "response_time_ms": time,
        "error": error,
    })
}

fn api_delete(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: ApiStore = store.load_or_default(FILE);
    let before = data.apis.len();
    data.apis.retain(|a| a.name != name);

    if data.apis.len() == before {
        return json!({"error": format!("API '{}' not found", name)});
    }

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "deleted": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}
