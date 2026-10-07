# POST-T020 G1-Jan — Real Host Interop Test: Jan (jan 0.8.4)

- Host: Jan (`/Users/emamabdullaziz/.local/bin/jan`), adapter: `src/emo_cyber_agent/subagent/hosts_jan.py`
- EMO transport: **stdio-only** (no SSE built; port 8000 closed, verified below)
- Tester: G1-Jan, 2026-10-06. No files under `src/` or `tests/` modified.
- Verdict scale: ENVIRONMENT-TESTED / CONTRACT-TESTED / NOT-ENVIRONMENT-TESTED / BLOCKED

## 1) `jan --version` — ENVIRONMENT-TESTED

Exact commands + outputs:

```
$ jan --version
jan 0.8.4            # EXIT:0

$ which jan
/Users/emamabdullaziz/.local/bin/jan
-rwxr-xr-x@ 1 emamabdullaziz staff 8221904 Jul 23 05:25 /Users/emamabdullaziz/.local/bin/jan

$ jan --help   (abridged — full subcommand list)
Commands: serve / launch / threads / models / help
```

Notable: jan 0.8.4 has **no `mcp` and no `agent` subcommand**:
```
$ jan mcp --help
error: unrecognized subcommand 'mcp'
$ jan agent --help
error: unrecognized subcommand 'agent'
```
There is therefore no Jan-CLI-driven MCP discovery/delegation surface to exercise (see §3–4).

## 2) Temp shared-config registering EMO stdio — ENVIRONMENT-TESTED

Adapter snippet (live, via `uv run python`):
```json
{"mcpServers": {"emo-cyber-agent": {"command": "cyber-agent", "args": ["mcp"]}}}
```
Real test performed (nothing written to the live Jan config):
1. Read live Desktop config `~/Library/Application Support/Jan/data/mcp_config.json` (6 servers).
2. Merged adapter stdio snippet as `emo-cyber-agent` (+ `"active": true`, matching Jan's per-server key) into a **temp file** `$TMPDIR/jan-mcp-emo-test.json` — 7 servers, valid JSON.
3. Spawned the server using the temp config's own `command`+`args` (`uv run cyber-agent mcp`), sent `initialize`, got:
```json
{"id": 1, "jsonrpc": "2.0", "result": {"capabilities": {"tools": {}}, "protocolVersion": "2025-03-26", "serverInfo": {"name": "emo-cyber-agent", "version": "0.1.0"}}}
```
RC 0. Registration shape round-trips: file → parse → spawn → handshake. Live Jan config untouched (temp file only).

## 3) Discovery via Jan MCP surface; permissions/filtering — mixed

**Stdio discovery (direct EMO handshake) — ENVIRONMENT-TESTED.** After `initialize` + `notifications/initialized`, `tools/list` returned all 6 tools: `cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report`, `cyber_status`, `cyber_extensions` (kebab-case n/a — identity mapping, names pass through as-is, matching `TOOL_NAME_MAPPING`).

**Jan-CLI MCP discovery surface — NOT-ENVIRONMENT-TESTED** (absent: §1, no `mcp` subcommand). Observable Jan surface is file-based: `data/mcp_config.json` (`mcpServers` + `mcpSettings`: `toolCallTimeoutSeconds: 30`, `enableSmartToolRouting: true`, …).

**Tool permissions / filtering as observable — CONTRACT-TESTED (host-side only).**
- The Jan config file exposes only a per-server `"active": true|false` flag — **no per-tool granularity observed** in the config schema. Per-tool permission/filtering, if any, lives in Jan Desktop UI/runtime state, not observable from this host's files or CLI.
- Server side, `tools/list` exposes all 6 tools including opt-in `cyber_extensions` — i.e. EMO does **not** filter by default; the adapter's "5 safe tools by default, extensions opt-in" is a host-filtering instruction, not server enforcement. Filtering therefore must happen Jan-side per `TOOL_FILTERING_NOTE`; verified as text present in adapter, not as live Jan behavior.

## 4) Safe-task delegation via non-interactive path — BLOCKED (with stdio equivalent ENVIRONMENT-TESTED)

- `jan models list` → `[]` (no local models installed). `jan launch <program>` requires a local model (interactive pick or download, GB-scale) before any agent runs — **no non-interactive delegation path exists on this host without downloading a model, which was deliberately not attempted.** No timeout needed; no launch attempted. Delegation *through Jan itself* is BLOCKED.
- Equivalent safe task executed directly over the stdio transport Jan would use (`tools/call cyber_status {}`) — ENVIRONMENT-TESTED:
```json
{"tool": "cyber_status", "status": "dispatched"} →
{"tool": "cyber_status", "status": "ok", "result": {"capabilities": ["cyber_audit","cyber_review","cyber_verify","cyber_report","cyber_status","cyber_extensions"], "policy_engine": "DefaultPolicyEngine", "status": "foundation", "version": "0.1.0"}}
```
Read-only, 2 ms, no side effects.

## 5) Contract checks — CONTRACT-TESTED (all executed live via `uv run`)

- `PROTOCOL_VERSIONS` = `['2024-11-05', '2025-03-26', '2025-06-18']`
- Desktop/Agent/CLI/Agent-CLI-alias stdio snippets all `==` shared snippet (shared-config claim holds in code).
- `negotiate_protocol_version(['2024-11-05','2025-03-26'])` → `'2025-03-26'`; `[]` → `None`; disjoint `['1999-01-01']` → `None` (abort, no silent fallback). `is_protocol_supported('2025-03-26')` → True; bogus → False.
- `get_safe_default_tools()` → 5 safe tools; `cyber_extensions` opt-in only. `get_tool_mapping()` identity. Unknown surface/transport raises `ValueError` (not probed live; code-read).
- Approval-boundary note present verbatim: *"Jan approval UI is NOT part of the EMO boundary: Jan-side approval prompts, allowlists, or click-throughs do not substitute for EMO enforcement. EMO enforces its own trust boundary, tool filtering, and capability checks server-side regardless of what the Jan approval UI displays or permits."* — acknowledged: Jan-side approvals neither widen nor substitute EMO enforcement.
- No separate Agent/CLI config location observed on this host (`~/.config/jan`, `~/.jan` absent; single `data/mcp_config.json`), so the Desktop↔Agent/CLI "register once per surface" step is code-shape only here.
- Stdio-only confirmed: TCP 127.0.0.1:8000 → `ConnectionRefusedError` (no SSE/HTTP server built or running; HTTP snippet is a data-only placeholder).

## Verdicts

| Area | Verdict |
|---|---|
| 1) `jan --version` | **ENVIRONMENT-TESTED** (0.8.4) |
| 2) Temp shared-config EMO stdio registration | **ENVIRONMENT-TESTED** |
| 3a) Discovery via stdio handshake | **ENVIRONMENT-TESTED** (6/6 tools) |
| 3b) Discovery via Jan CLI MCP surface | **NOT-ENVIRONMENT-TESTED** (no such subcommand in 0.8.4) |
| 3c) Tool permissions / filtering | **CONTRACT-TESTED** (adapter notes verified; host enforcement unobservable) |
| 4) Safe-task delegation through Jan | **BLOCKED** (no models, no non-interactive path); stdio equivalent **ENVIRONMENT-TESTED** |
| 5) Config shapes, approval boundary, negotiation | **CONTRACT-TESTED** (executed live) |

## Top limitation

**End-to-end delegation through the Jan host itself could not be exercised: jan 0.8.4 offers no non-interactive MCP/agent path (`mcp`/`agent` subcommands don't exist), no local models are installed (`models list` → `[]`), and per-tool permissions live in Jan's UI/runtime rather than any observable file/CLI — so live verification stops at the EMO stdio boundary (config shape → spawn → handshake → tool call) and all Jan-side filtering/approval behavior remains contract-only.**
