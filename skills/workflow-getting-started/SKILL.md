---
name: workflow-getting-started
description: 'Getting started with Workflow — the 37-tool automation server for API discovery, credential vault, flow recording/replay, watches, data piping, and TOTP/2FA. Use when: automating API calls, managing credentials, recording replayable flows, polling for changes, piping data between steps, or generating 2FA codes.'
---

## What Workflow Is

A single MCP server (workflow.exe) with 37 tools across 7 modules. It handles automation infrastructure: credentials, API patterns, recorded flows, scheduled watches, data transforms, and 2FA codes.

| Module | Tools | What It Does |
|--------|-------|-------------|
| API Discovery | 5 | Store, call, test, list, delete learned API patterns |
| Credential Vault | 5 | DPAPI-encrypted credential storage (Windows-only) |
| Flow Recording | 8 | Record, replay, adapt, and dispatch multi-step flows |
| Watch/Polling | 5 | Define watches, schedule checks, poll for changes |
| Data Piping | 2 | Transform and pipe data between steps |
| Workflow Chains | 5 | Define and run multi-step workflow sequences |
| TOTP/2FA | 6 | Register, generate, and manage TOTP/HOTP codes |

## Key Tools

| I want to... | Use |
|--------------|-----|
| Store an API pattern | api_store(name="...", method="POST", url="...", headers={...}) |
| Call a stored API | api_call(name="...") |
| Store credentials securely | credential_store(name="...", username="...", password="...") |
| Get credentials | credential_get(name="...") |
| Record a multi-step flow | flow_record_start → flow_record_step (repeat) → flow_record_stop |
| Replay a recorded flow | flow_replay(name="...") |
| Watch for a change | watch_define(name="...", url="...", selector="...") → watch_schedule |
| Generate a TOTP code | totp_generate(name="...") |
| Register 2FA secret | totp_register(name="...", secret="...") or totp_register_from_uri(uri="otpauth://...") |
| Pipe data between steps | transform_pipe(input="...", steps=[...]) |

## Common Patterns

**Learn an API from browser, then replay:**
workflow:api_store(name="create-issue", method="POST", url="https://api.example.com/issues", headers={"Authorization": "Bearer {{token}}"}, body={"title": "{{title}}"})
workflow:api_call(name="create-issue", params={"token": "...", "title": "Bug fix"})

**Secure credential flow:**
workflow:credential_store(name="github", username="user", password="ghp_xxx")
workflow:credential_get(name="github") → use in api_call

**2FA automation:**
workflow:totp_register(name="aws", secret="JBSWY3DPEHPK3PXP")
workflow:totp_generate(name="aws") → returns current 6-digit code

## Anti-Patterns

- Don't store credentials in plain text — always use credential_store (DPAPI-encrypted)
- Don't manually replay API sequences — record them with flow_record_* and replay with flow_replay
