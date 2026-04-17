//! Data Transform Pipeline
//! 2 tools: transform_pipe, pipe_test

use serde_json::{json, Value};

pub fn handle(tool: &str, args: &Value) -> Value {
    match tool {
        "transform_pipe" => transform_pipe(args),
        "pipe_test" => pipe_test(args),
        _ => json!({"error": format!("Unknown pipe tool: {}", tool)}),
    }
}

fn unwrap_string_json(v: Value) -> Value {
    // If input arrived as a JSON string (MCP serialization), parse it
    if let Value::String(s) = &v {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return parsed;
        }
    }
    v
}

fn transform_pipe(args: &Value) -> Value {
    let input = match args.get("input") {
        Some(v) => unwrap_string_json(v.clone()),
        None => return json!({"error": "input is required"}),
    };
    let operations = match args.get("operations").and_then(|v| v.as_array()) {
        Some(ops) => ops.clone(),
        None => return json!({"error": "operations array is required"}),
    };

    match apply_operations(input, &operations) {
        Ok(result) => json!({"success": true, "result": result}),
        Err(e) => json!({"success": false, "error": e}),
    }
}

fn pipe_test(args: &Value) -> Value {
    let input = match args.get("input") {
        Some(v) => unwrap_string_json(v.clone()),
        None => return json!({"error": "input is required"}),
    };
    let operations = match args.get("operations").and_then(|v| v.as_array()) {
        Some(ops) => ops.clone(),
        None => return json!({"error": "operations array is required"}),
    };
    let show_intermediate = args
        .get("show_intermediate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut current = input;
    let mut intermediates: Vec<Value> = Vec::new();

    for (i, op) in operations.iter().enumerate() {
        current = match apply_single_op(current, op) {
            Ok(v) => v,
            Err(e) => {
                return json!({
                    "success": false,
                    "error": format!("Operation {} failed: {}", i, e),
                    "failed_at": i,
                    "intermediates": if show_intermediate { Some(&intermediates) } else { None },
                })
            }
        };
        if show_intermediate {
            intermediates.push(json!({
                "step": i,
                "op": op.get("op"),
                "result": current.clone(),
            }));
        }
    }

    json!({
        "success": true,
        "result": current,
        "intermediates": if show_intermediate { Some(intermediates) } else { None },
    })
}

fn apply_operations(mut value: Value, operations: &[Value]) -> Result<Value, String> {
    for op in operations {
        value = apply_single_op(value, op)?;
    }
    Ok(value)
}

fn apply_single_op(value: Value, op: &Value) -> Result<Value, String> {
    let op_type = op
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "operation missing 'op' field".to_string())?;

    match op_type {
        "pick" => {
            let keys = op
                .get("keys")
                .and_then(|v| v.as_array())
                .ok_or("pick requires 'keys' array")?;
            let key_strs: Vec<&str> = keys.iter().filter_map(|v| v.as_str()).collect();

            match &value {
                Value::Object(map) => {
                    let mut new_map = serde_json::Map::new();
                    for key in &key_strs {
                        if let Some(v) = map.get(*key) {
                            new_map.insert(key.to_string(), v.clone());
                        }
                    }
                    Ok(Value::Object(new_map))
                }
                Value::Array(arr) => {
                    let picked: Vec<Value> = arr
                        .iter()
                        .map(|item| {
                            if let Some(obj) = item.as_object() {
                                let mut new_map = serde_json::Map::new();
                                for key in &key_strs {
                                    if let Some(v) = obj.get(*key) {
                                        new_map.insert(key.to_string(), v.clone());
                                    }
                                }
                                Value::Object(new_map)
                            } else {
                                item.clone()
                            }
                        })
                        .collect();
                    Ok(Value::Array(picked))
                }
                _ => Err("pick requires object or array input".into()),
            }
        }

        "rename" => {
            let from = op
                .get("from")
                .and_then(|v| v.as_str())
                .ok_or("rename requires 'from' string")?;
            let to = op
                .get("to")
                .and_then(|v| v.as_str())
                .ok_or("rename requires 'to' string")?;

            match value {
                Value::Object(mut map) => {
                    if let Some(v) = map.remove(from) {
                        map.insert(to.to_string(), v);
                    }
                    Ok(Value::Object(map))
                }
                Value::Array(arr) => {
                    let renamed: Vec<Value> = arr
                        .into_iter()
                        .map(|item| {
                            if let Value::Object(mut obj) = item {
                                if let Some(v) = obj.remove(from) {
                                    obj.insert(to.to_string(), v);
                                }
                                Value::Object(obj)
                            } else {
                                item
                            }
                        })
                        .collect();
                    Ok(Value::Array(renamed))
                }
                _ => Err("rename requires object or array input".into()),
            }
        }

        "flatten" => {
            let key = op
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("flatten requires 'key' string")?;

            match &value {
                Value::Array(arr) => {
                    let mut result = Vec::new();
                    for item in arr {
                        if let Some(nested) = item.get(key).and_then(|v| v.as_array()) {
                            result.extend(nested.clone());
                        }
                    }
                    Ok(Value::Array(result))
                }
                Value::Object(obj) => {
                    if let Some(nested) = obj.get(key).and_then(|v| v.as_array()) {
                        Ok(Value::Array(nested.clone()))
                    } else {
                        Err(format!("key '{}' not found or not an array", key))
                    }
                }
                _ => Err("flatten requires object or array input".into()),
            }
        }

        "filter" => {
            let key = op
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("filter requires 'key' string")?;
            let equals = op.get("equals");

            match value {
                Value::Array(arr) => {
                    let filtered: Vec<Value> = arr
                        .into_iter()
                        .filter(|item| {
                            if let Some(val) = item.get(key) {
                                if let Some(eq) = equals {
                                    val == eq
                                } else {
                                    !val.is_null()
                                }
                            } else {
                                false
                            }
                        })
                        .collect();
                    Ok(Value::Array(filtered))
                }
                _ => Err("filter requires array input".into()),
            }
        }

        "template" => {
            let format_str = op
                .get("format")
                .and_then(|v| v.as_str())
                .ok_or("template requires 'format' string")?;

            match &value {
                Value::Object(map) => {
                    let mut result = format_str.to_string();
                    for (k, v) in map {
                        let val_str = match v {
                            Value::String(s) => s.clone(),
                            Value::Number(n) => n.to_string(),
                            other => other.to_string(),
                        };
                        result = result.replace(&format!("{{{}}}", k), &val_str);
                    }
                    Ok(Value::String(result))
                }
                Value::Array(arr) => {
                    let results: Vec<Value> = arr
                        .iter()
                        .map(|item| {
                            if let Some(map) = item.as_object() {
                                let mut result = format_str.to_string();
                                for (k, v) in map {
                                    let val_str = match v {
                                        Value::String(s) => s.clone(),
                                        Value::Number(n) => n.to_string(),
                                        other => other.to_string(),
                                    };
                                    result = result.replace(&format!("{{{}}}", k), &val_str);
                                }
                                Value::String(result)
                            } else {
                                item.clone()
                            }
                        })
                        .collect();
                    Ok(Value::Array(results))
                }
                _ => Err("template requires object or array input".into()),
            }
        }

        "group_by" => {
            let key = op
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("group_by requires 'key' string")?;

            match value {
                Value::Array(arr) => {
                    let mut groups: serde_json::Map<String, Value> = serde_json::Map::new();
                    for item in arr {
                        let group_key = item
                            .get(key)
                            .map(|v| match v {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            })
                            .unwrap_or_else(|| "null".to_string());
                        let group = groups
                            .entry(group_key)
                            .or_insert_with(|| Value::Array(Vec::new()));
                        if let Some(arr) = group.as_array_mut() {
                            arr.push(item);
                        }
                    }
                    Ok(Value::Object(groups))
                }
                _ => Err("group_by requires array input".into()),
            }
        }

        "math" => {
            let key = op
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("math requires 'key' string")?;
            let math_op = op
                .get("math_op")
                .or_else(|| op.get("op_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("sum");

            match &value {
                Value::Array(arr) => {
                    let values: Vec<f64> = arr
                        .iter()
                        .filter_map(|item| item.get(key).and_then(|v| v.as_f64()))
                        .collect();

                    if values.is_empty() {
                        return Ok(json!({"value": 0, "key": key, "op": math_op, "count": 0}));
                    }

                    let result = match math_op {
                        "sum" => values.iter().sum::<f64>(),
                        "avg" | "average" => values.iter().sum::<f64>() / values.len() as f64,
                        "min" => values.iter().cloned().fold(f64::INFINITY, f64::min),
                        "max" => values.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                        "count" => values.len() as f64,
                        _ => return Err(format!("Unknown math op: {}", math_op)),
                    };
                    // Return object so math is chainable with template/pick/rename
                    Ok(json!({"value": result, "key": key, "op": math_op, "count": values.len()}))
                }
                _ => Err("math requires array input".into()),
            }
        }

        _ => Err(format!("Unknown operation: {}", op_type)),
    }
}
