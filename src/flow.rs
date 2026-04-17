//! Flow Recording & Replay
//! 8 tools: flow_record_start, flow_record_step, flow_record_stop, flow_replay,
//!          flow_adapt, flow_dispatch, flow_list, flow_delete

use crate::storage::JsonStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct FlowStore {
    pub flows: Vec<Flow>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Flow {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub status: String, // "recording", "ready", "failed"
    pub steps: Vec<FlowStep>,
    pub created_at: String,
    #[serde(default)]
    pub last_run: Option<String>,
    #[serde(default)]
    pub last_result: Option<String>,
    #[serde(default)]
    pub duration_seconds: Option<f64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FlowStep {
    pub tool_name: String,
    pub tool_params: Value,
    #[serde(default)]
    pub result_summary: Option<String>,
    #[serde(default)]
    pub screenshot_path: Option<String>,
    #[serde(default)]
    pub expected_url: Option<String>,
    #[serde(default)]
    pub expected_text: Option<String>,
    pub recorded_at: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct DispatchStore {
    pub dispatches: Vec<Dispatch>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Dispatch {
    pub dispatch_id: String,
    pub flow_name: String,
    pub schedule: String,
    pub enabled: bool,
    pub notify_on_failure: bool,
    pub created_at: String,
    #[serde(default)]
    pub next_run: Option<String>,
}

const FILE: &str = "flows.json";
const DISPATCH_FILE: &str = "dispatches.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    match tool {
        "flow_record_start" => flow_record_start(args, store),
        "flow_record_step" => flow_record_step(args, store),
        "flow_record_stop" => flow_record_stop(args, store),
        "flow_replay" => flow_replay(args, store),
        "flow_adapt" => flow_adapt(args, store),
        "flow_dispatch" => flow_dispatch(args, store),
        "flow_list" => flow_list(args, store),
        "flow_delete" => flow_delete(args, store),
        _ => json!({"error": format!("Unknown flow tool: {}", tool)}),
    }
}

fn flow_record_start(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut data: FlowStore = store.load_or_default(FILE);

    // Check if flow with same name exists and is recording
    if let Some(existing) = data.flows.iter().find(|f| f.name == name) {
        if existing.status == "recording" {
            return json!({"error": format!("Flow '{}' is already recording. Stop it first.", name)});
        }
    }

    // Remove existing flow with same name (overwrite)
    data.flows.retain(|f| f.name != name);

    data.flows.push(Flow {
        name: name.clone(),
        description,
        status: "recording".into(),
        steps: Vec::new(),
        created_at: Utc::now().to_rfc3339(),
        last_run: None,
        last_result: None,
        duration_seconds: None,
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "name": name, "status": "recording"}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn flow_record_step(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required (flow being recorded)"}),
    };
    let tool_name = match args.get("tool_name").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return json!({"error": "tool_name is required"}),
    };
    let tool_params = args.get("tool_params").cloned().unwrap_or(json!({}));

    let mut data: FlowStore = store.load_or_default(FILE);
    let flow = match data.flows.iter_mut().find(|f| f.name == name) {
        Some(f) => f,
        None => return json!({"error": format!("Flow '{}' not found", name)}),
    };

    if flow.status != "recording" {
        return json!({"error": format!("Flow '{}' is not recording (status: {})", name, flow.status)});
    }

    let step_num = flow.steps.len();
    flow.steps.push(FlowStep {
        tool_name,
        tool_params,
        result_summary: args
            .get("result_summary")
            .and_then(|v| v.as_str())
            .map(String::from),
        screenshot_path: args
            .get("screenshot_path")
            .and_then(|v| v.as_str())
            .map(String::from),
        expected_url: args
            .get("expected_url")
            .and_then(|v| v.as_str())
            .map(String::from),
        expected_text: args
            .get("expected_text")
            .and_then(|v| v.as_str())
            .map(String::from),
        recorded_at: Utc::now().to_rfc3339(),
    });

    match store.save(FILE, &data) {
        Ok(_) => {
            json!({"success": true, "flow": name, "step": step_num, "total_steps": step_num + 1})
        }
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn flow_record_stop(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: FlowStore = store.load_or_default(FILE);
    let flow = match data.flows.iter_mut().find(|f| f.name == name) {
        Some(f) => f,
        None => return json!({"error": format!("Flow '{}' not found", name)}),
    };

    if flow.status != "recording" {
        return json!({"error": format!("Flow '{}' is not recording (status: {})", name, flow.status)});
    }

    flow.status = "ready".into();
    let steps_count = flow.steps.len();
    let created = flow.created_at.clone();

    // Calculate duration
    if let Ok(start) = chrono::DateTime::parse_from_rfc3339(&created) {
        let duration = (Utc::now() - start.with_timezone(&Utc)).num_seconds() as f64;
        flow.duration_seconds = Some(duration);
    }

    match store.save(FILE, &data) {
        Ok(_) => {
            json!({"success": true, "name": name, "steps_count": steps_count, "status": "ready"})
        }
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn flow_replay(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };
    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let start_from = args
        .get("start_from_step")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let _adapt = args
        .get("adapt_on_failure")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut data: FlowStore = store.load_or_default(FILE);
    let flow = match data.flows.iter_mut().find(|f| f.name == name) {
        Some(f) => f,
        None => return json!({"error": format!("Flow '{}' not found", name)}),
    };

    if flow.status == "recording" {
        return json!({"error": format!("Flow '{}' is still recording. Stop it first.", name)});
    }

    // Return steps for the calling session to execute
    let steps: Vec<Value> = flow
        .steps
        .iter()
        .enumerate()
        .skip(start_from)
        .map(|(i, step)| {
            json!({
                "step": i,
                "tool_name": step.tool_name,
                "tool_params": step.tool_params,
                "expected_url": step.expected_url,
                "expected_text": step.expected_text,
            })
        })
        .collect();

    flow.last_run = Some(Utc::now().to_rfc3339());
    let _ = store.save(FILE, &data);

    json!({
        "name": name,
        "dry_run": dry_run,
        "steps": steps,
        "total_steps": steps.len(),
        "start_from": start_from,
        "hint": if dry_run { "Dry run — steps listed but not executed." } else { "Execute each step's tool_name with tool_params sequentially. Report results back via flow_record_step for adaptation." },
    })
}

fn flow_adapt(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };
    let failed_step = match args.get("failed_step").and_then(|v| v.as_u64()) {
        Some(s) => s as usize,
        None => return json!({"error": "failed_step is required"}),
    };
    let screenshot_path = args
        .get("screenshot_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let error_message = args
        .get("error_message")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let data: FlowStore = store.load_or_default(FILE);
    let flow = match data.flows.iter().find(|f| f.name == name) {
        Some(f) => f,
        None => return json!({"error": format!("Flow '{}' not found", name)}),
    };

    let step = match flow.steps.get(failed_step) {
        Some(s) => s,
        None => {
            return json!({"error": format!("Step {} not found in flow '{}'", failed_step, name)})
        }
    };

    // Analyze the failure and suggest adaptation
    let has_selector = step.tool_params.get("selector").is_some();
    let has_a11y_ref = step.tool_params.get("a11y_ref").is_some();

    let (analysis, adapted_step, confidence) = if error_message.contains("not found")
        || error_message.contains("No element")
    {
        if has_selector && !has_a11y_ref {
            // Selector-based step failed — suggest using a11y_ref instead
            let mut new_params = step.tool_params.clone();
            if let Some(obj) = new_params.as_object_mut() {
                obj.remove("selector");
                obj.insert("hint".into(), json!("Take a fresh browser_a11y_snapshot and find the element by role/name, then pass a11y_ref"));
            }
            (
                "Element selector no longer matches. The page may have been updated.".to_string(),
                json!({"tool_name": step.tool_name, "tool_params": new_params}),
                "medium",
            )
        } else {
            (
                "Element not found. The page structure may have changed significantly.".to_string(),
                json!({"tool_name": step.tool_name, "tool_params": step.tool_params, "hint": "Re-record from this step."}),
                "low",
            )
        }
    } else if error_message.contains("not clickable") || error_message.contains("intercepted") {
        let mut new_params = step.tool_params.clone();
        if let Some(obj) = new_params.as_object_mut() {
            obj.insert("force".into(), json!(true));
        }
        (
            "Element exists but is blocked by an overlay or not interactable.".to_string(),
            json!({"tool_name": step.tool_name, "tool_params": new_params}),
            "high",
        )
    } else {
        (
            format!(
                "Step failed with: {}. Consider re-recording.",
                error_message
            ),
            json!({"tool_name": step.tool_name, "tool_params": step.tool_params}),
            "low",
        )
    };

    json!({
        "analysis": analysis,
        "adapted_step": adapted_step,
        "confidence": confidence,
        "original_step": {
            "tool_name": step.tool_name,
            "tool_params": step.tool_params,
        },
        "screenshot_path": screenshot_path,
        "suggestion": if confidence == "low" {
            "Consider re-recording the flow from this step."
        } else {
            "Try the adapted step. If it fails, re-record."
        },
    })
}

fn flow_dispatch(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let schedule = match args.get("schedule").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return json!({"error": "schedule is required (cron expression or interval)"}),
    };
    let enabled = args
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let notify_on_failure = args
        .get("notify_on_failure")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Verify flow exists
    let flows: FlowStore = store.load_or_default(FILE);
    if !flows
        .flows
        .iter()
        .any(|f| f.name == name && f.status == "ready")
    {
        return json!({"error": format!("Flow '{}' not found or not ready", name)});
    }

    let dispatch_id = uuid::Uuid::new_v4().to_string();
    let mut dispatches: DispatchStore = store.load_or_default(DISPATCH_FILE);

    // Remove existing dispatch for this flow
    dispatches.dispatches.retain(|d| d.flow_name != name);

    dispatches.dispatches.push(Dispatch {
        dispatch_id: dispatch_id.clone(),
        flow_name: name.clone(),
        schedule: schedule.clone(),
        enabled,
        notify_on_failure,
        created_at: Utc::now().to_rfc3339(),
        next_run: None,
    });

    match store.save(DISPATCH_FILE, &dispatches) {
        Ok(_) => json!({
            "success": true,
            "dispatch_id": dispatch_id,
            "flow": name,
            "schedule": schedule,
            "hint": "Register this with the scheduled-tasks server for unattended execution.",
        }),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn flow_list(args: &Value, store: &JsonStore) -> Value {
    let data: FlowStore = store.load_or_default(FILE);
    let dispatches: DispatchStore = store.load_or_default(DISPATCH_FILE);
    let filter = args.get("filter").and_then(|v| v.as_str());
    let filter_re = filter.and_then(|f| regex::Regex::new(f).ok());

    let flows: Vec<Value> = data
        .flows
        .iter()
        .filter(|f| {
            if let Some(ref re) = filter_re {
                re.is_match(&f.name)
                    || f.description
                        .as_deref()
                        .map(|d| re.is_match(d))
                        .unwrap_or(false)
            } else {
                true
            }
        })
        .map(|f| {
            let dispatched = dispatches.dispatches.iter().any(|d| d.flow_name == f.name);
            json!({
                "name": f.name,
                "description": f.description,
                "steps_count": f.steps.len(),
                "status": f.status,
                "last_run": f.last_run,
                "last_result": f.last_result,
                "dispatched": dispatched,
            })
        })
        .collect();

    json!({"flows": flows, "count": flows.len()})
}

fn flow_delete(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: FlowStore = store.load_or_default(FILE);
    let before = data.flows.len();
    data.flows.retain(|f| f.name != name);

    if data.flows.len() == before {
        return json!({"error": format!("Flow '{}' not found", name)});
    }

    // Also remove any dispatch for this flow
    let mut dispatches: DispatchStore = store.load_or_default(DISPATCH_FILE);
    dispatches.dispatches.retain(|d| d.flow_name != name);
    let _ = store.save(DISPATCH_FILE, &dispatches);

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "deleted": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}
