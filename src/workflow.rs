//! Workflow Chains — trigger → action orchestration
//! 5 tools: workflow_define, workflow_run, workflow_list, workflow_status, workflow_delete

use crate::storage::JsonStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WorkflowStore {
    pub workflows: Vec<Workflow>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Workflow {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub trigger: WorkflowTrigger,
    pub steps: Vec<WorkflowStep>,
    pub created_at: String,
    #[serde(default)]
    pub runs: Vec<WorkflowRun>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WorkflowTrigger {
    #[serde(rename = "type")]
    pub trigger_type: String, // "watch", "schedule", "manual"
    #[serde(rename = "ref")]
    #[serde(default)]
    pub trigger_ref: Option<String>, // watch name or cron
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WorkflowStep {
    pub tool_name: String,
    pub params: Value,
    #[serde(default = "default_on_fail")]
    pub on_fail: String, // "stop", "skip", "retry"
}

fn default_on_fail() -> String {
    "stop".into()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WorkflowRun {
    pub run_id: String,
    pub started_at: String,
    #[serde(default)]
    pub completed_at: Option<String>,
    pub status: String, // "running", "completed", "failed"
    pub steps_completed: usize,
    #[serde(default)]
    pub error: Option<String>,
}

const FILE: &str = "workflows.json";

pub fn handle(tool: &str, args: &Value, store: &JsonStore) -> Value {
    match tool {
        "workflow_define" => workflow_define(args, store),
        "workflow_run" => workflow_run(args, store),
        "workflow_list" => workflow_list(args, store),
        "workflow_status" => workflow_status(args, store),
        "workflow_delete" => workflow_delete(args, store),
        _ => json!({"error": format!("Unknown workflow tool: {}", tool)}),
    }
}

fn workflow_define(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return json!({"error": "name is required"}),
    };

    let trigger = match args.get("trigger") {
        Some(t) => {
            let trigger_type = t
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("manual")
                .to_string();
            let trigger_ref = t.get("ref").and_then(|v| v.as_str()).map(String::from);
            WorkflowTrigger {
                trigger_type,
                trigger_ref,
            }
        }
        None => return json!({"error": "trigger is required"}),
    };

    let steps = match args.get("steps").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .map(|s| WorkflowStep {
                tool_name: s
                    .get("tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                params: s.get("params").cloned().unwrap_or(json!({})),
                on_fail: s
                    .get("on_fail")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stop")
                    .to_string(),
            })
            .collect(),
        None => return json!({"error": "steps array is required"}),
    };

    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut data: WorkflowStore = store.load_or_default(FILE);
    data.workflows.retain(|w| w.name != name);

    data.workflows.push(Workflow {
        name: name.clone(),
        description,
        trigger,
        steps,
        created_at: Utc::now().to_rfc3339(),
        runs: Vec::new(),
    });

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "name": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}

fn workflow_run(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };
    let start_from = args.get("start_from").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let mut data: WorkflowStore = store.load_or_default(FILE);
    let wf = match data.workflows.iter_mut().find(|w| w.name == name) {
        Some(w) => w,
        None => return json!({"error": format!("Workflow '{}' not found", name)}),
    };

    let run_id = uuid::Uuid::new_v4().to_string();
    wf.runs.push(WorkflowRun {
        run_id: run_id.clone(),
        started_at: Utc::now().to_rfc3339(),
        completed_at: None,
        status: "running".into(),
        steps_completed: 0,
        error: None,
    });

    // Return the execution plan for the calling session
    let steps: Vec<Value> = wf
        .steps
        .iter()
        .enumerate()
        .skip(start_from)
        .map(|(i, step)| {
            json!({
                "step": i,
                "tool_name": step.tool_name,
                "params": step.params,
                "on_fail": step.on_fail,
            })
        })
        .collect();

    let wf_name = wf.name.clone();
    let _ = store.save(FILE, &data);

    json!({
        "name": wf_name,
        "run_id": run_id,
        "steps": steps,
        "total_steps": steps.len(),
        "start_from": start_from,
        "hint": "Execute each step's tool_name with its params. Respect on_fail (stop/skip/retry). Report completion via workflow_status.",
    })
}

fn workflow_list(_args: &Value, store: &JsonStore) -> Value {
    let data: WorkflowStore = store.load_or_default(FILE);

    let workflows: Vec<Value> = data
        .workflows
        .iter()
        .map(|w| {
            let last_run = w.runs.last();
            json!({
                "name": w.name,
                "description": w.description,
                "trigger_type": w.trigger.trigger_type,
                "trigger_ref": w.trigger.trigger_ref,
                "steps_count": w.steps.len(),
                "total_runs": w.runs.len(),
                "last_run_status": last_run.map(|r| r.status.clone()),
                "last_run_at": last_run.map(|r| r.started_at.clone()),
            })
        })
        .collect();

    json!({"workflows": workflows, "count": workflows.len()})
}

fn workflow_status(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let data: WorkflowStore = store.load_or_default(FILE);
    let wf = match data.workflows.iter().find(|w| w.name == name) {
        Some(w) => w,
        None => return json!({"error": format!("Workflow '{}' not found", name)}),
    };

    let runs: Vec<Value> = wf
        .runs
        .iter()
        .rev()
        .take(10)
        .map(|r| {
            json!({
                "run_id": r.run_id,
                "started_at": r.started_at,
                "completed_at": r.completed_at,
                "status": r.status,
                "steps_completed": r.steps_completed,
                "error": r.error,
            })
        })
        .collect();

    json!({
        "name": name,
        "description": wf.description,
        "trigger": {
            "type": wf.trigger.trigger_type,
            "ref": wf.trigger.trigger_ref,
        },
        "steps_count": wf.steps.len(),
        "runs": runs,
        "total_runs": wf.runs.len(),
    })
}

fn workflow_delete(args: &Value, store: &JsonStore) -> Value {
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return json!({"error": "name is required"}),
    };

    let mut data: WorkflowStore = store.load_or_default(FILE);
    let before = data.workflows.len();
    data.workflows.retain(|w| w.name != name);

    if data.workflows.len() == before {
        return json!({"error": format!("Workflow '{}' not found", name)});
    }

    match store.save(FILE, &data) {
        Ok(_) => json!({"success": true, "deleted": name}),
        Err(e) => json!({"error": format!("Failed to save: {}", e)}),
    }
}
