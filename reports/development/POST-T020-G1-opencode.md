# POST-T020 G1 — OpenCode Host Interop (REAL, no EMO mocks)

- Date (UTC): 2026-10-06
- Tester: G1-OpenCode (real host interop)
- Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
- Scope: live `opencode` binary + real temp configs (outside repo) + real `cyber-agent mcp` stdio server. No `src/`/`tests/` modifications. One read-only pytest run.
- Adapter under test: `src/emo_cyber_agent/subagent/hosts_opencode.py` (POST-T018 Agent 9A, data-only).
- Versions recorded:
  - `opencode --version` → `1.18.34` (exit 0), binary `/Users/emamabdullaziz/.opencode/bin/opencode`
  - `cyber-agent --version` → `emo-cyber-agent 0.1.0` (exit 0), binary `/Users/emamabdullaziz/.local/bin/cyber-agent` (pipx shim)
  - `discovery.PROTOCOL_VERSIONS` → `['2024-11-05', '2025-03-26', '2025-06-18']`
  - `discovery.build_advertisement()` → server `emo-cyber-agent 0.1.0`

## Per-area verdicts

| # | Area | Verdict | One-line evidence |
|---|------|---------|-------------------|
| 1 | Binary probe (`opencode --version`) | ENVIRONMENT-TESTED | `1.18.34`, exit 0, real binary on PATH |
| 2 | Temp stdio config registration (real file, temp dir) | ENVIRONMENT-TESTED | `xdg-real/opencode/opencode.json` with `mcp.emo-cyber-agent type=local command=[cyber-agent,mcp]` resolves in `debug config` |
| 3 | Discovery (`opencode mcp list` shows emo server) | ENVIRONMENT-TESTED | `✓ emo-cyber-agent connected / cyber-agent mcp / 1 server(s)`, exit 0 |
| 4 | Delegated safe task (non-interactive `opencode run` → `cyber_status`) | ENVIRONMENT-TESTED | Host invoked `emo-cyber-agent_cyber_status`, server returned `version 0.1.0`, exit 0 |
| 5 | Tool filtering (subset vs full discovery) | ENVIRONMENT-TESTED | Live `tools/list` = 6/6 tools; `build_advertisement(only=safe5)` = 5/5; server default is FULL, safe-5 is adapter metadata only |
| 6 | Failure path (bad EMO target) | ENVIRONMENT-TESTED | `✗ emo-bad failed / ENOENT posix_spawn`, exit 0, no crash |
| 7a | Contract: registration config validity vs `hosts_opencode.py` | CONTRACT-TESTED (MISMATCH FOUND) | Adapter emits `mcpServers`+`{command:str,args:[]}`; opencode 1.18.34 consumes `mcp`+`{type:local,command:[]}` — adapter snippet yields "No MCP servers configured" |
| 7b | Contract: protocol negotiation helper | CONTRACT-TESTED | `negotiate_protocol_version` latest-common-wins verified against live `discovery` values; live MCP handshake negotiated `2025-03-26` |
| 7c | Contract: safe-default surface | CONTRACT-TESTED (DRIFT FOUND) | Adapter claims 5 safe + `cyber_extensions` opt-in and `kebab-case`/identity naming; live server exposes 6/6 and host namespaced tool as `emo-cyber-agent_cyber_status` |

Notes on verdict scale: ENVIRONMENT-TESTED = real binary + real temp config + real connection/call observed. CONTRACT-TESTED = code/discovery assertions only, never upgraded to PASS. Nothing here is NOT-ENVIRONMENT-TESTED or BLOCKED — all planned live steps executed.

## 1) Binary probe — ENVIRONMENT-TESTED

Exact commands (workdir = repo root):

```
$ opencode --version
1.18.34
EXIT:0

$ which opencode
/Users/emamabdullaziz/.opencode/bin/opencode

$ cyber-agent --version
emo-cyber-agent 0.1.0
EXIT:0
```

`opencode mcp --help` confirms subcommands `add/list/auth/logout/debug` — `list` (alias `ls`) is the discovery path used below. `opencode run --help` confirms non-interactive `opencode run [message..]` with `--format default|json`, `--dir`, `--model`, `--auto` flags.

## 2) Real temp configs (temp dir, NOT repo) — ENVIRONMENT-TESTED

Temp root (pre-approved scratch): `/var/folders/78/ggfty0h91k797r7nkl3qmdf80000gn/T/opencode/post-t020-g1/`
Repo and user config untouched — isolation via `XDG_CONFIG_HOME=<tmp-xdg>` per invocation (verified: `opencode debug paths` shows `config /tmp/opencode` when overridden; default user config at `~/.config/opencode/opencode.jsonc` was only READ).

Three real files written under temp (not repo):

- `xdg-real/opencode/opencode.json` (live shape, observed from working configs + `$schema: https://opencode.ai/config.json`):
```json
{"$schema":"https://opencode.ai/config.json","mcp":{"emo-cyber-agent":{"type":"local","command":["cyber-agent","mcp"],"enabled":true}}}
```
- `xdg-adapterfmt/opencode/opencode.json` (verbatim adapter shape from `get_registration_config()`):
```json
{"mcpServers":{"emo-cyber-agent":{"command":"cyber-agent","args":["mcp"]}}}
```
- `xdg-bad/opencode/opencode.json` (failure path):
```json
{"$schema":"https://opencode.ai/config.json","mcp":{"emo-bad":{"type":"local","command":["/nonexistent/cyber-agent-bad","mcp"],"enabled":true}}}
```

Resolved-config check (real):
```
$ XDG_CONFIG_HOME=.../xdg-real opencode debug config
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "emo-cyber-agent": {
      "type": "local",
      "command": ["cyber-agent","mcp"],
      "enabled": true
    }
  },
  ...
  "username": "emamabdullaziz"
}
EXIT:0
```

## 3) Discovery — ENVIRONMENT-TESTED

```
$ XDG_CONFIG_HOME=.../xdg-real opencode mcp list
┌  MCP Servers
│
●  ✓ emo-cyber-agent connected
│      cyber-agent mcp
│
└  1 server(s)
EXIT:0
```

Control — adapter-claimed `mcpServers` shape is IGNORED by opencode 1.18.34:
```
$ XDG_CONFIG_HOME=.../xdg-adapterfmt opencode mcp list
┌  MCP Servers
│
▲  No MCP servers configured
│
└  Add servers with: opencode mcp add
EXIT:0
```
For reference, the pre-existing user config uses key `mcp` (not `mcpServers`): entry `emo-x` = `{"type":"local","command":[...]}` — consistent with the live shape, inconsistent with `get_registration_config()`.

## 4) Delegated safe task — ENVIRONMENT-TESTED

Non-interactive run is supported (`opencode run [message..] --format json`). macOS has no `timeout(1)` (`zsh: command not found: timeout`); timeouts enforced via harness (90–120 s). Workdir for runs: the temp dir (not the repo).

Smoke (no tools):
```
$ XDG_CONFIG_HOME=.../xdg-real opencode run --format json "Reply with exactly: INTEROP-PROBE-OK. Do not modify anything."
{"type":"text",...,"text":"INTEROP-PROBE-OK",...}
{"type":"step_finish",...,"reason":"stop",...,"tokens":{"total":9292,...}}
EXIT:0
```

Real EMO delegation (read-only `cyber_status`):
```
$ XDG_CONFIG_HOME=.../xdg-real opencode run --format json "Use the emo-cyber-agent MCP server's cyber_status tool with audit_id '' and report the server version. Do not modify anything."
```
Verbatim key events (truncated to load-bearing fields):
- `tool_use ... "tool":"emo-cyber-agent_cyber_status" ... "state":{"status":"completed","input":{"audit_id":""},"output":"{\"audit_id\": \"\", \"references\": {}, \"result\": {\"capabilities\": [\"cyber_audit\", \"cyber_review\", \"cyber_verify\", \"cyber_report\", \"cyber_status\", \"cyber_extensions\"], \"policy_engine\": \"DefaultPolicyEngine\", \"status\": \"foundation\", \"version\": \"0.1.0\"}, \"status\": \"ok\", \"tool\": \"cyber_status\"}...}`
- `text ... "Server version: **0.1.0**\n\nFull cyber_status result (read-only, no modifications made):\n- status: foundation\n- policy_engine: DefaultPolicyEngine\n- capabilities: cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions"`
- `step_finish reason=stop`, `EXIT:0`.

Observed host tool naming: `emo-cyber-agent_cyber_status` (`<server>_<tool>`, underscores) — NOT `kebab-case`, NOT bare `cyber_*`. Adapter constants `TOOL_NAMING = "kebab-case"` and `OPENCODE_TOOL_NAMESPACE_NOTE` ("exposed as-is with no rename") do not describe this host behavior.

## 5) Tool filtering: subset vs full — ENVIRONMENT-TESTED

Live MCP `tools/list` over real stdio (`cyber-agent mcp`, JSON-RPC `initialize` → `notifications/initialized` → `tools/list`):
- `initialize` response: `{"capabilities": {"tools": {}}, "protocolVersion": "2025-03-26", "serverInfo": {"name": "emo-cyber-agent", "version": "0.1.0"}}`
- `tools/list` names (6/6, full surface): `cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions` (descriptions redacted here; full schemas captured in shell output).

Discovery contract comparison (real `discovery` module via `PYTHONPATH=src`):
- `build_advertisement()` → 6 tools: `['cyber_audit', 'cyber_extensions', 'cyber_report', 'cyber_review', 'cyber_status', 'cyber_verify']`
- `build_advertisement(only=[5 safe])` → 5 tools: `['cyber_audit', 'cyber_report', 'cyber_review', 'cyber_status', 'cyber_verify']` (`cyber_extensions` excluded)
- Per-tool capabilities match adapter `CAPABILITY_MAPPING` (e.g. `cyber_audit → (repo.read, codeintel.read, evidence.read)`, `cyber_status → ()`).

Comparison outcome: the live server exposes FULL 6 by default; the 5-safe default exists only as adapter metadata (`get_safe_default_tools()`). No per-MCP-tool allowlist was observed in the opencode 1.18.34 config surface (`mcp` entry supports `type/command/enabled`; `mcp add` flags are `--url/--env/--header` only). Safe-default enforcement, if desired, must happen host-side (permissions/agent config) or server-side — it is not a wire-level filter today.

## 6) Failure path — ENVIRONMENT-TESTED

```
$ XDG_CONFIG_HOME=.../xdg-bad opencode mcp list
┌  MCP Servers
│
●  ✗ emo-bad failed
│      ENOENT: no such file or directory, posix_spawn '/nonexistent/cyber-agent-bad'
│      /nonexistent/cyber-agent-bad mcp
│
└  1 server(s)
EXIT:0
```
Graceful: clear `ENOENT` error, `failed` status, exit 0, no crash/hang. (Mirrors the pre-existing user config state where `emo-x` shows `failed ... Connection closed` without crashing the CLI.)

## 7) Contract checks — CONTRACT-TESTED (with two drift findings)

Read-only pytest (no writes): `PYTHONPATH=src python3 -m pytest tests/unit/subagent/test_hosts_opencode.py -v` → `8 passed in 1.06s`, exit 0.

- 7a Registration validity: `get_registration_config()` returns JSON-serializable, credential-free `{"mcpServers": {"emo-cyber-agent": {"command": "cyber-agent", "args": ["mcp"]}}}` — VALID JSON but WRONG SCHEMA for opencode 1.18.34 (proven by §3 control: "No MCP servers configured"). Correct live shape is `{"mcp": {"<name>": {"type": "local", "command": ["cyber-agent", "mcp"], "enabled": true}}}`.
- 7b Negotiation helper: `negotiate_protocol_version(tuple(PROTOCOL_VERSIONS)) == PROTOCOL_VERSIONS[-1]` (`2025-06-18`); partial overlap → latest common; no-overlap/empty/non-list → `None` (abort, no silent fallback); `is_protocol_supported` membership-tested against `discovery.PROTOCOL_VERSIONS` (no hardcode). Live handshake negotiated `2025-03-26` (within advertised range) — helper and wire behavior are consistent.
- 7c Safe-default surface: `SAFE_DEFAULT_TOOLS` (5) + `OPT_IN_TOOLS == ("cyber_extensions",)` + identity `TOOL_NAME_MAPPING` + capability mapping all match `discovery`/`mcp_tools.TOOL_NAMES` in unit tests — but live observations (§4–§5) show the host namespace (`emo-cyber-agent_<tool>`) and full-6 server default, so the adapter's naming/namespace note and "default exposure" framing describe adapter intent, not enforced host/server behavior.

Adapter honesty labels remain accurate: `SUPPORT_STATUS == NOT_TESTED`, `HOST_MATRIX["opencode"].support_status == NOT_TESTED`, lifecycle notes state "not verified against a live host" — this report is the first live evidence and it finds schema/naming drift.

## Top limitation

**Adapter registration snippet + tool-naming metadata do not match opencode 1.18.34 reality**: `get_registration_config()` emits `mcpServers/{command:str,args:[]}` which the live host ignores, and the host invokes tools as `emo-cyber-agent_<tool>` rather than the documented `kebab-case`/identity mapping — so an integrator following only `hosts_opencode.py` would register zero servers and address tools under the wrong names. (Live end-to-end works once the real `mcp/type:local/command:[]` shape is used, as proven by the connected server and successful `cyber_status` delegation.)

## Reproduction (exact, read-only to repo)

```sh
opencode --version
cyber-agent --version
# temp configs under /var/folders/78/ggfty0h91k797r7nkl3qmdf80000gn/T/opencode/post-t020-g1/xdg-{real,adapterfmt,bad}/opencode/opencode.json (contents in §2)
XDG_CONFIG_HOME=.../xdg-real opencode mcp list
XDG_CONFIG_HOME=.../xdg-adapterfmt opencode mcp list
XDG_CONFIG_HOME=.../xdg-bad opencode mcp list
XDG_CONFIG_HOME=.../xdg-real opencode debug config
XDG_CONFIG_HOME=.../xdg-real opencode run --format json "Use the emo-cyber-agent MCP server's cyber_status tool with audit_id '' and report the server version. Do not modify anything."
PYTHONPATH=src python3 -m pytest tests/unit/subagent/test_hosts_opencode.py -v
```

No mocks of EMO were used at any point; all MCP traffic went to the real `cyber-agent mcp` stdio server. No repo files created or modified except this report.
