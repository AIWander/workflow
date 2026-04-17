//! Watch / Polling
//! 5 tools: watch_define, watch_list, watch_check, watch_schedule, watch_delete

use crate::storage::JsonStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WatchStore {
    pub watches: Vec<Watch>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Watch {
    pub name: String,
    pub check_tool: String,
    pub check_params: Value,
    pub condition: String,
    #[serde(default)]
    pub action_flow: Option<String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default)]
    pub active_hours: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub last_check: Option<String>,
    #[serde(default)]
    pub last_result: Option<Value>,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub task_id: Option<String>,
}

fn default_poll_interval() -> u64 {
    300
}

const FILE: &str = "watches.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    match tool {
        "watch_define" => watch_define(args, store),
        "watch_list" => watch_list(args, store),
        "watch_check" => watch_check(args, store),
        "watch_schedule" => watch_schedule(args, store),
        "watch_delete" => watch_delete(args, store),
        _ => json!({"error": format!("Unknown watch tool: {}", tool)}),
    }
}

fn watch_define(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let check_tool = match args.get("check_tool").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return json!({"error": "check_tool is required"}),
    };
    let check_params = args.get("check_params").cloned().unwrap_or(json!({}));
    let condition = match args.get("condition").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => return json!({"error": "condition is required"}),
    };
    let action_flow = args
        .get("action_flow")
        .and_then(|v| v.as_str())
        .map(String::from);
    let poll_interval = args
        .get("poll_interval_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    let active_hours = args
        .get("active_hours")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut data: WatchStore = store.load_or_default(FILE);
    data.watches.retain(|w| w.name != name);

    data.watches.push(Watch {
        name: name.clone(),
        check_tool,
        check_params,
        condition,
        action_flow,
        poll_interval_seconds: poll_interval,
        active_hours,
        created_at: Utc::now().to_rfc3339(),
        last_check: None,
        last_result: None,
        is_active: true,
        task_id: None,
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "name": name, "poll_interval_seconds": poll_interval}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn watch_list(_args: &Value, store: &JsonStore) -> Value {
    let data: WatchStore = store.load_or_default(FILE);

    let watches: Vec<Value> = data
        .watches
        .iter()
        .map(|w| {
            json!({
                "name": w.name,
                "check_tool": w.check_tool,
                "condition": w.condition,
                "poll_interval_seconds": w.poll_interval_seconds,
                "last_check": w.last_check,
                "last_result": w.last_result,
                "is_active": w.is_active,
                "action_flow": w.action_flow,
                "active_hours": w.active_hours,
            })
        })
        .collect();

    json!({"watches": watches, "count": watches.len()})
}

fn watch_check(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let data: WatchStore = store.load_or_default(FILE);
    let watch = match data.watches.iter().find(|w| w.name == name) {
        Some(w) => w,
        None => return json!({"error": format!("Watch '{}' not found", name)}),
    };

    let check_instruction = json!({
        "check_tool": watch.check_tool,
        "check_params": watch.check_params,
    });
    let condition_desc = watch.condition.clone();
    let last_result = watch.last_result.clone();
    let action_flow = watch.action_flow.clone();

    // Update last_check timestamp
    let mut data_mut: WatchStore = store.load_or_default(FILE);
    if let Some(w) = data_mut.watches.iter_mut().find(|w| w.name == name) {
        w.last_check = Some(Utc::now().to_rfc3339());
    }
    let _ = store.save(FILE, &data_mut);

    json!({
        "name": name,
        "check_instruction": check_instruction,
        "condition": condition_desc,
        "last_result": last_result,
        "action_flow": action_flow,
        "hint": "Execute check_instruction.check_tool with check_instruction.check_params. Then evaluate the condition against the result. If condition_met, trigger the action_flow if set.",
    })
}

fn watch_schedule(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };
    let enabled = args
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut data: WatchStore = store.load_or_default(FILE);
    let watch = match data.watches.iter_mut().find(|w| w.name == name) {
        Some(w) => w,
        None => return json!({"error": format!("Watch '{}' not found", name)}),
    };

    let task_id = uuid::Uuid::new_v4().to_string();
    watch.is_active = enabled;
    watch.task_id = Some(task_id.clone());

    let poll = watch.poll_interval_seconds;
    let active_hours = watch.active_hours.clone();

    match store.save(FILE, &data) {
        Ok(_) => json!({
            "scheduled": true,
            "task_id": task_id,
            "name": name,
            "poll_interval_seconds": poll,
            "active_hours": active_hours,
            "hint": "Register this task_id with the scheduled-tasks server for automatic polling.",
        }),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn watch_delete(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: WatchStore = store.load_or_default(FILE);
    let before = data.watches.len();
    data.watches.retain(|w| w.name != name);

    if data.watches.len() == before {
        return json!({"error": format!("Watch '{}' not found", name)});
    }

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "deleted": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}
