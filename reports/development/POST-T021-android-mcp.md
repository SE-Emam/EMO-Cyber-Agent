# POST-T021 A4 — Android MCP stdio (Termux, emo-cyber 0.2.0)

Date (UTC): 2026-10-08
Agent: A4 — Android MCP Agent for EMO-Cyber-Agent
Device: emulator-5554 (A2=PASS: emo-cyber 0.2.0 in Termux)
Bridge: `adb -s emulator-5554 shell "run-as com.termux files/usr/bin/bash -c 'export PREFIX=/data/data/com.termux/files/usr; export HOME=/data/data/com.termux/files/home; export PATH=\$PREFIX/bin:\$PATH; <cmd>'"`
SDK PATH exported first on host. Preamble per reports/development/POST-T021-android-runtime.md.
Scope: black-box over stdio only (`cyber-agent mcp` via bridge, piped JSON-RPC, short `timeout` sessions). No src/ edits, no prod targets, no destructive/write calls, no real secrets.

## VERDICT: PASS — GATE A4 SATISFIED

- MCP stdio works: YES
- Framing intact (newline-delimited JSON, no crash/hang): YES — 4/4 lines parse as JSON
- 7-tool surface correct + schemas present: YES — 7/7
- Security boundary intact (fail-safe errors, no leakage, orderly shutdown): YES

## Method note (quoting)

JSON-RPC contains `"` which collides with outer `adb shell "..."`. All payloads sent base64-encoded then `base64 -d | timeout 10 cyber-agent mcp` inside Termux; oversized payload generated inside Termux via `python3 -c` using only `dict()`+`chr()` (no literal quotes) to avoid nested-quote breakage. Sessions kept short with `timeout 10/15`.

## 1. `initialize` → server id + version

Request (skeleton):
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"a4-test","version":"1.0"}}}
```

Verbatim response lines (secrets redacted — none present):
```
{"audit_id": "", "duration_ms": 0, "error_category": "", "request_id": "startup", "status": "started", "tool": "server"}
{"id": 1, "jsonrpc": "2.0", "result": {"capabilities": {"tools": {}}, "protocolVersion": "2024-11-05", "serverInfo": {"name": "emo-cyber-agent", "version": "0.2.0"}}}
{"audit_id": "", "duration_ms": 0, "error_category": "", "request_id": "shutdown", "status": "stopped", "tool": "server"}
```
Result: PASS — `serverInfo.name=emo-cyber-agent`, `version=0.2.0`. Extra `started/stopped` lines are valid JSON log records on stdout, one per line, no interleave.

## 2. `tools/list` → 7 tools + schemas

Request: `initialize(id=1)` + `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`

Verbatim (truncated skeleton; full output verified on device):
- `id=1` → same initialize result as §1
- `id=2` → `result.tools[7]`:
  1. `cyber_audit` — inputSchema requires `target` (maxLength 512), optional `audit_id/focus/mode`
  2. `cyber_review` — requires `target`
  3. `cyber_verify` — requires `audit_id/candidate/method/target/rationale`
  4. `cyber_report` — requires `audit_id/findings/format`
  5. `cyber_status` — optional `audit_id`
  6. `cyber_extensions` — requires `action` (list/describe/resolve/check)
  7. `cyber_threat_intel` — requires `action` (leak-check/triage/map-technique/exposure-check/coverage)
- Each entry has `name/description/inputSchema`. Framing check: 4 lines total, `python3 json.loads` → `total=4, parsed=4`.
- `shutdown/stopped` + `MCP_PIPESTATUS:0`.

Result: PASS — 7/7 expected surface (audit/review/verify/report/status/extensions/threat_intel), schemas present.

## 3. Minimal SAFE read-only call

Request: `initialize(id=1)` + `tools/call cyber_status {audit_id:"unknown-audit-xyz-123"}` (read-only; never destructive/write).

Verbatim skeleton:
```
{"status":"dispatched","tool":"cyber_status","audit_id":"unknown-audit-xyz-123",...}
{"id":3,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"{\"audit_id\":\"unknown-audit-xyz-123\",...,\"result\":{\"capabilities\":[\"cyber_audit\",...],\"policy_engine\":\"DefaultPolicyEngine\",\"status\":\"foundation\",\"version\":\"0.2.0\"},\"status\":\"ok\",...}"}]}}
+ shutdown/stopped
```
Additional safe probes (same pattern, all `status:ok`, no secrets):
- `cyber_report {audit_id:unknown-...,findings:[],format:json}` → report v1.0, empty findings summary
- `cyber_extensions {action:list}` → `count:0, code_load:disabled`, 246ms

Deviation noted: prompt example suggested `NOT_FOUND` for unknown audit id; observed `status:ok` with only version/capabilities/policy (no other audit data, no secrets). Boundary intact — no cross-audit leakage — so not a gate failure.

Result: PASS (safe, read-only, fail-closed on data exposure).

## 4. Invalid calls → fail-safe

All with `initialize(id=1)` preamble, each followed by orderly `shutdown/stopped`:

a) `cyber_audit {}` (missing required `target`):
```json
{"error": {"code": -32602, "message": "invalid arguments: $ missing required field: target"}, "id": 6, "jsonrpc": "2.0"}
```
b) `cyber_status {audit_id:12345}` (wrong type):
```json
{"error": {"code": -32602, "message": "invalid arguments: $.audit_id must be a string"}, "id": 7, "jsonrpc": "2.0"}
```
c) `no_such_tool {}`:
```json
{"error": {"code": -32602, "message": "unknown tool: no_such_tool"}, "id": 8, "jsonrpc": "2.0"}
```

Result: PASS — mapped `-32602` in all cases, no crash/hang.

## 5. Malformed + oversized → fail safely

Malformed: `initialize` + `NOT_JSON{{{bad` + `tools/list(id=2)`:
```
id=1 → ok
{"error":{"code":-32700,"message":"invalid JSON: Expecting value: line 1 column 1 (char 0)"},"id":null,"jsonrpc":"2.0"}
id=2 → full 7-tool list (recovery proven) + shutdown/stopped
```
Oversized: 131072-char `target` for `cyber_audit` (generated in-Tmux, total stdin ~131KB, `timeout 15`):
```json
{"error": {"code": -32602, "message": "invalid arguments: $.target too long"}, "id": 9, "jsonrpc": "2.0"}
```
+ `shutdown/stopped`, clean exit, no hang (timeout never fired).

Result: PASS — parse error contained, oversized rejected by schema limit, server survives.

## 6. Progress token + no-token silence + shutdown + leakage

With `_meta:{progressToken:123}` on `cyber_status` (+ `notifications/initialized`):
```
... dispatched cyber_status ...
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":123,"percent":25.0,"phase":"STARTED","message_code":"RUN_STARTED"}}
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":123,"percent":50.0,...}}
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":123,"percent":75.0,...}}
{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":123,"percent":100.0,"phase":"COMPLETED","message_code":"OPERATION_COMPLETE"}}
id=10 → cyber_status ok + shutdown/stopped
```
No-token calls (§2–§5: ids 2,3,4,5,6,7,8,9) emitted zero `notifications/progress` lines — silence confirmed.

Shutdown: stdin EOF → `stopped` log + process exit `0` (`MCP_PIPESTATUS:0`).

Leakage: all responses scanned (`grep -iE password|passwd|api[_-]?key|aws_|BEGIN.*PRIVATE|ghp_|sk-|bearer`) → `NO_SECRET_MATCH`. Only token echoed is caller-supplied `progressToken:123`. No env/keys/credentials. Secrets redacted: none present to redact.

Result: PASS.

## Gate decision

**GATE A4: PASS.** MCP stdio works + framing intact (newline JSON, 4/4 parse, exit 0) + 7-tool surface correct with schemas + security boundary intact (read-only safe, -32602/-32700 fail-safe, oversized rejected, progress/no-progress correct, no secret leakage, no crash/hang). No blocker.
