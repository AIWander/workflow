# Example: API Pattern Storage and Replay

Advanced patterns for API storage, replay, and data transformation.

## Store a Pattern with Placeholders

URL placeholders use `{name}` syntax. Filled at call time via `params`.

```
workflow:api_store(
  name: "github_repo_issues",
  url_pattern: "https://api.github.com/repos/{owner}/{repo}/issues?state={state}&per_page={limit}",
  method: "GET",
  credential_ref: "github_pat",
  response_shape: ["id", "title", "state", "created_at", "user"],
  notes: "GitHub Issues API. Supports state=open|closed|all."
)
```

## Call with Parameters

```
workflow:api_call(
  name: "github_repo_issues",
  params: {"owner": "AIWander", "repo": "workflow", "state": "open", "limit": "10"}
)
→ {success: true, status: 200, response_time_ms: 234, body: [...]}
```

## POST Pattern with Body Template

```
workflow:api_store(
  name: "create_github_issue",
  url_pattern: "https://api.github.com/repos/{owner}/{repo}/issues",
  method: "POST",
  headers: {"Content-Type": "application/json", "Accept": "application/vnd.github.v3+json"},
  body_template: {"title": "{title}", "body": "{body}", "labels": ["{label}"]},
  credential_ref: "github_pat"
)

workflow:api_call(
  name: "create_github_issue",
  params: {"owner": "AIWander", "repo": "workflow", "title": "Bug report", "body": "Details here", "label": "bug"}
)
```

## List and Filter Patterns

```
workflow:api_list()
→ [{name: "github_repo_issues", method: "GET", url_pattern: "...", last_used: "2026-04-10T..."}, ...]

workflow:api_list(filter: "github")
→ only patterns with "github" in name or URL

workflow:api_list(filter: "FHIR")
→ all FHIR endpoints regardless of payer
```

## Chain API Call with Transform

Fetch data and reshape it in one flow:

```
# Get open issues
result = workflow:api_call(
  name: "github_repo_issues",
  params: {"owner": "AIWander", "repo": "workflow", "state": "open", "limit": "50"}
)

# Transform: extract titles grouped by label
workflow:transform_pipe(
  input: result.body,
  operations: [
    {"op": "pick", "keys": ["title", "labels", "created_at"]},
    {"op": "template", "format": "{title} (created: {created_at})"}
  ]
)
```

## Aggregate with Math

```
workflow:transform_pipe(
  input: [{"name": "API-A", "ms": 120}, {"name": "API-B", "ms": 340}, {"name": "API-C", "ms": 95}],
  operations: [
    {"op": "math", "key": "ms", "math_op": "avg"}
  ]
)
→ {value: 185, key: "ms", op: "avg", count: 3}
```

## Debug a Pipeline with Intermediates

```
workflow:pipe_test(
  input: {"entry": [{"resourceType": "Patient", "id": "1", "name": "Smith"}, {"resourceType": "Practitioner", "id": "2", "name": "Jones"}]},
  operations: [
    {"op": "flatten", "key": "entry"},
    {"op": "filter", "key": "resourceType", "equals": "Patient"},
    {"op": "pick", "keys": ["id", "name"]}
  ],
  show_intermediate: true
)
→ Shows result after each step — find where the pipeline goes wrong
```

## Validate Before Production

Always test after storing or updating a pattern:

```
workflow:api_test(name: "github_repo_issues", params: {"owner": "AIWander", "repo": "workflow", "state": "open", "limit": "1"})
→ {works: true, status: 200, response_time_ms: 187}
```

`api_test` is a lightweight wrapper around `api_call` — same request, but strips the body and returns pass/fail. Use after token rotation, endpoint changes, or initial setup.
