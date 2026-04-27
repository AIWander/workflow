---
name: workflow
description: |
  API pattern storage and replay, DPAPI-encrypted credential vault, flow
  recording/replay, scheduled watches, data transform pipelines, and
  trigger→action workflow chains — all through one MCP server. Teaches the
  graduation pipeline (browser→API), credential-by-reference pattern, flow
  recording, watch polling, and workflow composition. For workflow v1.1.1+.
---

# Workflow MCP Server — Skill Reference

Workflow is a single Rust binary that gives you API pattern storage with live
HTTP replay, a Windows DPAPI-encrypted credential vault, flow recording and
adaptive replay, scheduled watch polling, JSON transform pipelines, and
trigger→action workflow chains — all over MCP. 31 tools across 7 modules, zero
runtime dependencies beyond Rust, one process.

This skill teaches you how to use it effectively, not just what tools exist.

---

## The Graduation Pipeline — workflow's Reason to Exist

Browser automation is expensive. Every Chrome session costs startup time, memory,
page load latency, and fragile selectors that break when sites update. But if the
browser successfully completed a task, the real work happened over HTTP — API
calls were made, tokens were exchanged, data came back as JSON.

**The insight:** capture those API calls, store them as named patterns with URL
placeholders, and replay them as cheap HTTP later. Skip the browser entirely.

This is the **graduation pipeline**:

```
Day 1: Browser automation (hands MCP server)
        ↓ hands:browser_learn_api extracts endpoint patterns from network traffic
Day 2: Store patterns (workflow:api_store)
        ↓ Named pattern with URL template, headers, credential reference
Day N: Direct HTTP replay (workflow:api_call)
        ↓ No browser. No Chrome. No selectors. Just HTTP.
```

**The economics:**
- Browser session: ~3-5 seconds startup + page load + interaction + fragile selectors
- API call: ~50-200ms, no browser process, no DOM, no breakage from UI redesigns

**The discipline:** Whenever you find yourself doing the same browser task twice,
it's time to graduate it. Use `hands:browser_learn_api` to extract the endpoint
pattern from a recorded browser session, then `workflow:api_store` to save it.
Future runs skip the browser entirely.

### How the two halves fit together

The **hands** MCP server is the discovery half — it drives the browser, records
network traffic, and extracts API patterns via `browser_learn_api`. The
**workflow** MCP server is the storage and replay half — it persists those
patterns, manages credentials, and replays the calls via direct HTTP.

Together they form a pipeline. Apart they're each useful (workflow can store
manually-discovered APIs, hands can automate browsers without graduating), but
together they eliminate browser automation for any task that has an underlying
API.

### Production proof

This isn't theoretical. Workflow has been used in production for healthcare
integration work — 24 stored API patterns across healthcare payer FHIR
endpoints, with real `last_used` timestamps. These patterns run daily without
a browser window ever opening.

---

## Tool Reference

31 tools across 7 categories. Every tool name below is verified against source.

---

### API Pattern Storage & Replay (5 tools)

These are the core tools. Master these first.

#### `api_store`

Save a discovered API pattern for later replay.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Human-readable name, e.g. `payer_member_search` |
| `url_pattern` | string | yes | URL with `{placeholders}`, e.g. `https://api.example.com/fhir/Patient/{id}` |
| `method` | string | yes | HTTP method: GET, POST, PUT, DELETE, PATCH |
| `headers` | object | no | Request headers (content-type, custom headers). Auth goes through `credential_ref`. |
| `body_template` | any | no | Request body template for POST/PUT. Supports same `{placeholder}` substitution as URL. |
| `response_shape` | string[] | no | Expected response keys — documentation only, helps future callers know what to expect |
| `credential_ref` | string | no | Name of a stored credential to inject into the Authorization header automatically |
| `notes` | string | no | How this API was discovered, what it does, any caveats |

**Behavior:** If a pattern with the same `name` already exists, it's replaced
(upsert). Timestamps `created_at` automatically. Returns `total_apis` count.

**Key pattern — credential by reference:**
```
workflow:api_store(
  name: "acme_fhir_patient",
  url_pattern: "https://fhir.example-health.com/api/Patient/{patient_id}",
  method: "GET",
  credential_ref: "payer_bearer_token",
  notes: "Discovered via browser_learn_api on 2026-03-15"
)
```

The credential value is never stored in the API pattern. It's looked up at call
time from the encrypted vault. This means you can rotate tokens without touching
any of your stored patterns.

#### `api_call`

Execute a stored API pattern via live HTTP.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Name of a stored API pattern |
| `params` | object | no | Values to fill URL placeholders, e.g. `{"patient_id": "12345"}` |
| `body` | any | no | Override the stored body template for this call |
| `headers` | object | no | Additional or override headers for this call |
| `credential_ref` | string | no | Override which credential to use (default: use the one stored in the pattern) |

**Behavior:**
1. Looks up the named pattern
2. Resolves `{placeholders}` in URL and body template using `params`
3. Resolves credential by ref — decrypts via DPAPI, injects into headers based on credential type:
   - `bearer` → `Authorization: Bearer <value>`
   - `api_key` → `X-API-Key: <value>`
   - `basic` → `Authorization: Basic <value>`
   - `cookie` → `Cookie: <value>`
   - `custom` → `Authorization: <value>`
4. Executes the HTTP request
5. Updates `last_used` timestamp on the pattern
6. Returns: `success`, `status`, `response_time_ms`, `headers`, `body`
7. On failure: includes `fallback_hint` suggesting browser UI replay

**The fallback hint is important.** If an API call fails (token expired, endpoint
changed), the response tells you to fall back to the browser. This is the
graduation pipeline in reverse — when the API breaks, go back to the browser,
fix it, re-graduate.

#### `api_list`

List all stored API patterns.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filter` | string | no | Regex filter on name or URL pattern |

Returns: array of `{name, method, url_pattern, credential_ref, last_used, created_at}` plus `count`.

Use `filter: "acme"` to see only a specific payer's patterns, or `filter: "FHIR"` to see all
FHIR endpoints regardless of payer.

#### `api_test`

Validate a stored API still works by making a test call.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | API name to test |
| `params` | object | no | Placeholder values needed for the test call |

Returns: `{works, status, response_time_ms, error}`. This is a lightweight
wrapper around `api_call` that strips the response body and just tells you
pass/fail. Use it before production runs, after token rotation, or as a health
check.

**Best practice:** Run `api_test` after every `credential_refresh` to confirm
the new token works before trusting it in a pipeline.

#### `api_delete`

Remove a stored API pattern.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | API name to delete |

No undo. If you delete a pattern that's referenced by a workflow chain, the
chain will fail when it tries to call it.

---

### Credential Vault (5 tools)

Windows DPAPI-encrypted credential storage. Values are encrypted with the
current Windows user's key and can only be decrypted by the same user on the
same machine. This is the same encryption Windows uses for stored passwords
and certificates.

On non-Windows platforms, credentials are stored unencrypted (development/testing
only — do not use for production secrets outside Windows).

#### `credential_store`

Save a credential securely.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Reference name, e.g. `payer_bearer_token` |
| `value` | string | yes | The secret value (token, password, API key) |
| `credential_type` | string | no | One of: `bearer`, `api_key`, `basic`, `cookie`, `custom`. Defaults to `bearer`. Determines how the credential is injected into HTTP requests. |
| `service` | string | no | Service name for organization (e.g. `acme_health`, `github`) |
| `notes` | string | no | Description, expiry info, how to refresh |

**Behavior:** Encrypts `value` via DPAPI before writing to disk. The plaintext
value never touches the filesystem. If a credential with the same name exists,
it's replaced.

**Critical rule:** Always store credentials by reference name, then use
`credential_ref` in `api_store`. Never hardcode tokens in URL patterns or body
templates. When tokens expire, you update one credential — all patterns that
reference it automatically get the new value.

#### `credential_get`

Retrieve and decrypt a stored credential.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Credential name to retrieve |

Returns the decrypted value. Only succeeds for the same Windows user who stored
it. Use this when you need to pass a credential to a non-workflow tool (e.g.,
passing a token to a hands browser session that needs to authenticate).

#### `credential_list`

List stored credentials — names and types only, never values.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | no | Filter by service name |

Returns: array of `{name, credential_type, service, created_at}` plus `count`.
This is safe to call freely — it never exposes secret values.

#### `credential_delete`

Remove a stored credential.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Credential name to delete |

**Warning:** If API patterns reference this credential via `credential_ref`,
those patterns will fail on the next `api_call`. Check with `api_list` first.

#### `credential_refresh`

Refresh an OAuth token using a stored refresh_token.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Name of the credential to refresh |
| `token_url` | string | first use | OAuth token endpoint. Stored after first use for subsequent refreshes. |
| `client_id` | string | first use | OAuth client ID. Stored after first use. |
| `client_secret` | string | no | OAuth client secret (stored DPAPI-encrypted if provided) |

**Behavior:**
1. On first call: requires `token_url` and `client_id` (stores them for future use)
2. Reads the current credential value as the refresh_token
3. POSTs to the token endpoint with `grant_type=refresh_token`
4. If successful: stores the new `access_token` as the credential value
5. Returns: `{refreshed, new_expiry_seconds}` or `{refreshed: false, error, hint}`

**The hint on failure** tells you to re-authenticate via browser. This connects
back to the graduation pipeline — when OAuth refresh fails, you go back to
hands, re-authenticate, capture the new tokens, and store them again.

**Pattern for FHIR endpoints:**
```
workflow:credential_store(name: "payer_refresh", value: "<refresh_token>", credential_type: "bearer", service: "acme_health")
workflow:credential_refresh(name: "payer_refresh", token_url: "https://auth.example-health.com/oauth2/token", client_id: "<client_id>")
workflow:api_test(name: "acme_fhir_patient", params: {"patient_id": "test"})
```

---

### Flow Recording & Replay (8 tools) — EXPERIMENTAL

**Status: experimental.** The flow recording interface exists and is functionally
complete in the source, but has not yet been production-validated. Use for
prototyping and testing. A follow-up release will harden flow recording based on real-world
usage.

Flows are replayable sequences of MCP tool calls — record what you did, replay
it later. Unlike API patterns (which are single HTTP calls), flows are multi-step
procedures that can span multiple tools across multiple servers.

**Important architectural note:** `flow_replay` does NOT execute tools directly.
It returns a step-by-step execution plan that the calling session is responsible
for executing. This is by design — the workflow server doesn't have access to
other MCP servers. It's a data store and planner, not an executor.

#### `flow_record_start`

Begin recording a new flow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name, e.g. `login_to_dashboard` |
| `description` | string | no | What this flow does |

Creates a flow in `recording` status. If a flow with the same name exists and
isn't currently recording, it's replaced.

#### `flow_record_step`

Add a step to the currently recording flow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name being recorded |
| `tool_name` | string | yes | The MCP tool that was called, e.g. `hands:browser_click` |
| `tool_params` | any | yes | The params that were passed to the tool |
| `result_summary` | string | no | Brief summary of what happened |
| `screenshot_path` | string | no | Path to a checkpoint screenshot (used by flow_adapt for failure analysis) |
| `expected_url` | string | no | Expected URL at this point (used for replay verification) |
| `expected_text` | string | no | Expected text visible on page (used for replay verification) |

Call this after each significant tool call during recording. The optional
verification fields (`expected_url`, `expected_text`, `screenshot_path`) enable
adaptive replay — when a step fails during replay, `flow_adapt` can compare
the current state against what was expected.

#### `flow_record_stop`

Finish recording. Marks the flow as `ready` for replay.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name to stop recording |

Also calculates the recording duration. A flow must be in `recording` status.

#### `flow_replay`

Get a step-by-step execution plan for replaying a recorded flow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name to replay |
| `adapt_on_failure` | boolean | no | If a step fails, analyze and suggest adaptation. Default: true. |
| `dry_run` | boolean | no | Just list steps without marking as executed. Default: false. |
| `start_from_step` | integer | no | Resume from a specific step number (0-indexed) |

**Returns** an array of steps, each with `{step, tool_name, tool_params, expected_url, expected_text}`.
The calling session executes each step sequentially. Does NOT execute anything itself.

#### `flow_adapt`

Analyze a failed flow step and suggest an adapted version.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name |
| `failed_step` | integer | yes | Step index that failed (0-indexed) |
| `screenshot_path` | string | yes | Screenshot taken at point of failure |
| `error_message` | string | yes | The error from the failed step |

**Behavior:** Analyzes the failure against the recorded step and suggests
adaptations:
- Element not found + selector-based → suggests switching to `a11y_ref`
- Element not clickable → suggests adding `force: true`
- Other failures → suggests re-recording from this step

Returns `{analysis, adapted_step, confidence, suggestion}` where confidence
is `high`, `medium`, or `low`.

#### `flow_dispatch`

Register a flow to run on a schedule.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name (must be in `ready` status) |
| `schedule` | string | yes | Cron expression or interval, e.g. `0 8 * * 1-5` or `every 2h` |
| `enabled` | boolean | no | Default: true |
| `notify_on_failure` | boolean | no | Default: true |

**Note:** This creates a dispatch record. Actual scheduling requires integration
with an external scheduled-tasks server. The dispatch is a registration, not an
execution engine.

#### `flow_list`

List all recorded flows.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filter` | string | no | Regex filter on name or description |

Returns: array of `{name, description, steps_count, status, last_run, last_result, dispatched}` plus `count`.

#### `flow_delete`

Remove a recorded flow and its dispatch schedule.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Flow name to delete |

Also removes any associated dispatch record.

---

### Watch / Polling (5 tools)

Define conditions to watch for by polling MCP tools periodically. Watches are
the "trigger" side of event-driven automation — define what to check, how often,
and what to do when the condition is met.

Like flows, watches don't execute tools directly. `watch_check` returns check
instructions for the calling session to execute.

#### `watch_define`

Define a new watch condition.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Watch name, e.g. `check_new_enrollments` |
| `check_tool` | string | yes | MCP tool to call for checking, e.g. `hands:browser_get_text` |
| `check_params` | any | yes | Params for the check tool |
| `condition` | string | yes | Expression to evaluate, e.g. `result.length > 0` or `result != last_result` |
| `action_flow` | string | no | Name of a flow to trigger when condition is true |
| `poll_interval_seconds` | integer | no | How often to check. Default: 300 (5 min). |
| `active_hours` | string | no | e.g. `08:00-18:00` to only check during business hours |

If a watch with the same name exists, it's replaced.

#### `watch_list`

List all defined watches.

No parameters. Returns: array of `{name, check_tool, condition, poll_interval_seconds, last_check, last_result, is_active, action_flow, active_hours}` plus `count`.

#### `watch_check`

Manually trigger a watch check now.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Watch name to check |

Returns check instructions (what tool to call with what params) plus the
condition to evaluate. The calling session executes the check and evaluates the
condition. Updates `last_check` timestamp.

#### `watch_schedule`

Register a watch with the scheduled-tasks server for unattended polling.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Name of a defined watch |
| `enabled` | boolean | no | Default: true |

Returns a `task_id` for tracking. Like `flow_dispatch`, actual scheduling
requires an external scheduled-tasks server.

#### `watch_delete`

Remove a watch and its schedule.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Watch name to delete |

---

### Data Transform Pipelines (2 tools)

Transform JSON data between workflow steps. These are pure functions — no
storage, no side effects, no network calls. They take JSON in, apply operations
in sequence, and return JSON out.

#### `transform_pipe`

Apply a sequence of transform operations to JSON data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `input` | any | yes | JSON data to transform |
| `operations` | array | yes | Array of transform operations to apply in sequence |

**Available operations:**

| Operation | Required Fields | Description |
|-----------|----------------|-------------|
| `pick` | `keys: string[]` | Keep only specified keys from objects. Works on single objects or arrays of objects. |
| `rename` | `from: string, to: string` | Rename a key in objects. Works on single objects or arrays. |
| `flatten` | `key: string` | Extract a nested array by key. |
| `filter` | `key: string`, optional `equals: any` | Keep array items where key exists (and optionally equals a value). |
| `template` | `format: string` | Format objects into strings using `{key}` placeholders. |
| `group_by` | `key: string` | Group array items by a key value into an object of arrays. |
| `math` | `key: string`, optional `math_op: string` | Aggregate numeric values. Ops: `sum`, `avg`, `min`, `max`, `count`. Default: `sum`. |

**Example — extract and summarize API response data:**
```
workflow:transform_pipe(
  input: <api_call response body>,
  operations: [
    {"op": "flatten", "key": "entry"},
    {"op": "pick", "keys": ["resourceType", "id", "name"]},
    {"op": "filter", "key": "resourceType", "equals": "Patient"},
    {"op": "template", "format": "Patient {id}: {name}"}
  ]
)
```

Operations chain sequentially — the output of each step feeds into the next.
Math returns `{value, key, op, count}` as an object, making it chainable with
template/pick/rename for further processing.

#### `pipe_test`

Test a transform pipeline with sample data. Same as `transform_pipe` but with
optional intermediate result display.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `input` | any | yes | Sample input data |
| `operations` | array | yes | Same as transform_pipe |
| `show_intermediate` | boolean | no | Show result after each step. Default: false. |

Use this to debug pipelines before putting them in production workflows. With
`show_intermediate: true`, you see the data shape after every operation, making
it easy to find where a pipeline goes wrong.

---

### Workflow Chains (5 tools)

Compose watches, flows, and API calls into trigger→action chains. A workflow
defines: what triggers it, what steps to run, and what to do when a step fails.

Like flows and watches, `workflow_run` returns an execution plan — it doesn't
execute tools directly.

#### `workflow_define`

Define a new trigger→action workflow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Workflow name, e.g. `new_enrollment_to_sheets` |
| `trigger` | object | yes | `{type: "watch"|"schedule"|"manual", ref: "<watch name or cron>"}` |
| `steps` | array | yes | Array of `{tool_name, params, on_fail: "stop"|"skip"|"retry"}` |
| `description` | string | no | What this workflow does |

**Trigger types:**
- `watch` — fires when a defined watch's condition is met. `ref` = watch name.
- `schedule` — fires on a cron schedule. `ref` = cron expression.
- `manual` — no automatic trigger. Run explicitly via `workflow_run`.

**Failure handling per step:**
- `stop` — abort the workflow (default)
- `skip` — log the failure and continue to the next step
- `retry` — retry the failed step once before stopping

#### `workflow_run`

Manually execute a workflow. Returns the step-by-step execution plan.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Workflow name to run |
| `start_from` | integer | no | Resume from step N (0-indexed) |

Creates a run record with a `run_id` for tracking. Returns the steps for the
calling session to execute.

#### `workflow_list`

List all defined workflows.

No parameters. Returns: array of `{name, description, trigger_type, trigger_ref, steps_count, total_runs, last_run_status, last_run_at}` plus `count`.

#### `workflow_status`

Get detailed status and run history for a workflow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Workflow name |

Returns the workflow definition plus the last 10 runs with
`{run_id, started_at, completed_at, status, steps_completed, error}`.

#### `workflow_delete`

Remove a workflow definition and all its run history.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Workflow name to delete |

---

### Frontmatter Lint Query (1 tool)

Read-only access to a frontmatter lint report. This tool queries a
pre-generated report file — it doesn't run the linter itself.



| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mode` | string | no | `summary` (default), `file`, or `drift` |
| `path` | string | for `file` mode | File path to look up in the report |
| `limit` | integer | for `drift` mode | Number of top-drift files to return. Default: 10. |

**Modes:**
- `summary` — top-level stats: total files, total insights, schema version distribution, format distribution, top 5 drift files
- `file` — stats for a specific file path (supports exact and suffix matching)
- `drift` — top N files ranked by drift score

---

## Common Patterns

### Pattern 1: Graduate a browser task to API

```
# Step 1: Use hands to do the task via browser and capture network traffic
hands:browser_launch()
hands:browser_navigate(url: "https://portal.example-health.com")
# ... interact with the page ...
hands:browser_learn_api()  → extracts endpoint patterns

# Step 2: Store the discovered pattern
workflow:credential_store(name: "payer_token", value: "<captured_token>", credential_type: "bearer", service: "acme_health")
workflow:api_store(name: "payer_member_search", url_pattern: "https://api.example-health.com/fhir/Patient?name={name}", method: "GET", credential_ref: "payer_token")

# Step 3: Test it works
workflow:api_test(name: "payer_member_search", params: {"name": "Smith"})

# Step 4: From now on, skip the browser
workflow:api_call(name: "payer_member_search", params: {"name": "Jones"})
```

### Pattern 2: Token rotation without touching patterns

```
# New token obtained (via browser re-auth or credential_refresh)
workflow:credential_store(name: "payer_token", value: "<new_token>", credential_type: "bearer", service: "acme_health")

# All patterns referencing "payer_token" automatically use the new value
# No need to update any api_store entries
workflow:api_test(name: "payer_member_search", params: {"name": "test"})
```

### Pattern 3: Transform API response data

```
# Call an API that returns FHIR bundle
result = workflow:api_call(name: "payer_fhir_search", params: {"name": "Smith"})

# Transform the response to extract just what you need
workflow:transform_pipe(
  input: result.body,
  operations: [
    {"op": "flatten", "key": "entry"},
    {"op": "pick", "keys": ["id", "name", "birthDate"]},
    {"op": "group_by", "key": "birthDate"}
  ]
)
```

### Pattern 4: Watch + workflow chain

```
# Define a watch
workflow:watch_define(
  name: "new_enrollment_check",
  check_tool: "workflow:api_call",
  check_params: {"name": "enrollment_api", "params": {"since": "today"}},
  condition: "result.body.total > 0",
  poll_interval_seconds: 3600,
  active_hours: "08:00-18:00"
)

# Define a workflow triggered by the watch
workflow:workflow_define(
  name: "process_new_enrollments",
  trigger: {"type": "watch", "ref": "new_enrollment_check"},
  steps: [
    {"tool_name": "workflow:api_call", "params": {"name": "enrollment_api"}, "on_fail": "stop"},
    {"tool_name": "workflow:transform_pipe", "params": {...}, "on_fail": "stop"},
    {"tool_name": "google:gdrive_upload", "params": {...}, "on_fail": "retry"}
  ]
)
```

---

## Pairs With: hands MCP Server

Workflow and hands are designed as two halves of the same pipeline.

**hands** is the discovery half:
- Drives browsers via Playwright CDP (a11y-first interaction model)
- Records browser sessions with network traffic capture
- Extracts API endpoint patterns via `browser_learn_api`
- Provides the UI fallback when API calls fail

**workflow** is the storage and replay half:
- Stores discovered API patterns with URL templates and credential references
- Manages DPAPI-encrypted credentials
- Replays API calls as direct HTTP (no browser needed)
- Provides `fallback_hint` when API calls fail, pointing back to browser replay

### The handoff

```
hands:browser_learn_api()
  → outputs: {url_pattern, method, headers, body_template}
  → feed directly into workflow:api_store()
```

### When to use which

| Scenario | Use |
|----------|-----|
| First time doing a task | hands (browser) |
| Task has a known API pattern | workflow (api_call) |
| API call fails / token expired | hands (browser re-auth) → workflow (credential_store) |
| Need to interact with native Windows app | hands (UIA tools — workflow doesn't do desktop) |
| Need to transform API response data | workflow (transform_pipe) |
| Need to poll for changes | workflow (watch_define) |

### Where to find hands

The hands MCP server is published at https://github.com/AIWander/hands.
See the hands skill reference for full tool documentation.

---

## Anti-Patterns

**Don't hardcode credentials in api_store headers or body templates.**
Always use `credential_ref` to reference the vault. Hardcoded tokens become
stale, can't be rotated, and are visible in the JSON store file.

**Don't skip api_test after credential rotation.**
A successful `credential_refresh` or `credential_store` doesn't guarantee the
token actually works. Always test.

**Don't use flow_record for single API calls.**
If the task is one HTTP request, use `api_store` + `api_call`. Flows are for
multi-step procedures that span multiple tools.

**Don't expect flow_replay to execute tools.**
It returns a plan. Your session executes the plan. This is by design — workflow
doesn't have access to other MCP servers.

**Don't rely on flows for production-critical tasks (yet).**
Flow recording is experimental. API patterns and credentials are production-solid.
Use flows for prototyping and testing until a follow-up release hardens them.

**Don't delete a credential that's referenced by API patterns.**
Check `api_list` first. Credential deletion is immediate and there's no
referential integrity check.

**Don't use workflow for browser automation.**
That's what hands is for. Workflow is HTTP-only. If the task requires clicking
buttons, filling forms, or reading screen content, use hands.

---

## Data Storage

All workflow data lives in `C:\CPC\workflows\` as JSON files:
- `apis.json` — stored API patterns
- `credentials.json` — encrypted credentials (values are DPAPI-encrypted, base64-encoded)
- `flows.json` — recorded flows
- `dispatches.json` — flow dispatch schedules
- `watches.json` — watch definitions
- `workflows.json` — workflow chain definitions

Writes are atomic (write to `.tmp`, then rename). Safe against crashes
mid-write.

---

## Troubleshooting

**"Credential decryption failed"**
You're running as a different Windows user than the one who stored the credential,
or the credential was stored on a different machine. DPAPI keys are per-user,
per-machine. Re-store the credential as the current user.

**"API call returns fallback_hint"**
The API request failed (4xx/5xx or network error). Check: is the token expired?
(`credential_refresh`). Is the endpoint still valid? (`api_test`). If both look
fine, the API may have changed — go back to hands and re-discover.

**"Flow is still recording"**
You called `flow_record_start` but never called `flow_record_stop`. Either stop
it (`flow_record_stop(name: "...")`) or delete it and start over.

**"Watch condition never triggers"**
Check that: (1) the `check_tool` and `check_params` are correct, (2) the
`condition` expression matches the actual response shape, (3) `active_hours`
isn't filtering out the current time. Use `watch_check` to manually test.

**"transform_pipe says 'pick requires object or array input'"**
Your input is probably a string that contains JSON. The pipe will auto-parse
JSON strings, but nested strings-within-strings won't work. Make sure your
input is actual JSON, not a stringified JSON string.

**Empty api_list / credential_list**
The store files may not exist yet (`C:\CPC\workflows\`). The first `api_store`
or `credential_store` call creates them. Or the directory doesn't exist — workflow
creates it on startup, but check if something deleted it.

---

## Roadmap

**v1.1.1** (current) — stable API patterns, credentials, transforms, watches,
workflow chains. Experimental flow recording.

**Follow-up release** (planned):
- Harden flow recording based on real-world usage
- Flow versioning (keep old recordings when re-recording)
- Credential expiry tracking and automatic refresh scheduling
- Watch result history (currently only stores last result)
- Workflow chain completion reporting (update run status automatically)
- Integration with hands `browser_learn_api` for one-command graduation
- Rate limiting for api_call (respect API rate limits in stored patterns)

---

## Quick Reference — All 31 Tools

| Category | Tool | Description |
|----------|------|-------------|
| API Patterns | `api_store` | Save an API pattern for replay |
| API Patterns | `api_call` | Execute a stored API pattern via HTTP |
| API Patterns | `api_list` | List stored patterns |
| API Patterns | `api_test` | Validate a pattern still works |
| API Patterns | `api_delete` | Remove a pattern |
| Credentials | `credential_store` | Save encrypted credential |
| Credentials | `credential_get` | Retrieve and decrypt credential |
| Credentials | `credential_list` | List credentials (names only) |
| Credentials | `credential_delete` | Remove credential |
| Credentials | `credential_refresh` | OAuth token refresh |
| Flows | `flow_record_start` | Begin recording (EXPERIMENTAL) |
| Flows | `flow_record_step` | Add step to recording (EXPERIMENTAL) |
| Flows | `flow_record_stop` | Finish recording (EXPERIMENTAL) |
| Flows | `flow_replay` | Get replay execution plan (EXPERIMENTAL) |
| Flows | `flow_adapt` | Analyze failed step (EXPERIMENTAL) |
| Flows | `flow_dispatch` | Schedule a flow (EXPERIMENTAL) |
| Flows | `flow_list` | List flows (EXPERIMENTAL) |
| Flows | `flow_delete` | Remove flow (EXPERIMENTAL) |
| Watches | `watch_define` | Define a polling condition |
| Watches | `watch_list` | List watches |
| Watches | `watch_check` | Manual check trigger |
| Watches | `watch_schedule` | Register for unattended polling |
| Watches | `watch_delete` | Remove watch |
| Pipes | `transform_pipe` | JSON transform pipeline |
| Pipes | `pipe_test` | Test pipeline with intermediates |
| Workflows | `workflow_define` | Define trigger→action chain |
| Workflows | `workflow_run` | Execute a workflow (returns plan) |
| Workflows | `workflow_list` | List workflows |
| Workflows | `workflow_status` | Workflow detail + run history |
| Workflows | `workflow_delete` | Remove workflow |
