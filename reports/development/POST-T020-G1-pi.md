# POST-T020 G1-Pi — Real Host Interop Test (pi 0.84.4 × EMO stdio)

- Date (UTC): 2026-10-06
- Tester: G1-Pi (real host interop, read-only; one-file write scope)
- Working directory: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
- Adapter under test: `src/emo_cyber_agent/subagent/hosts_pi.py` (task brief said `subagent/hosts_pi.py`; real path is `src/emo_cyber_agent/subagent/hosts_pi.py`)
- EMO binary: `/Users/emamabdullaziz/.local/bin/cyber-agent` → `emo-cyber-agent 0.1.0` (pipx venv)
- Standing constraint honored: EMO is **stdio-only**. Streamable HTTP is config-data only. **No EMO HTTP server exists; no HTTP testing against EMO was attempted or claimed.**
- No files under `src/` or `tests/` were modified. Only this report was written.

## 1. `pi --version` — ENVIRONMENT-TESTED (pass)

Exact command + output:

```
$ pi --version
0.84.4
EXIT:0
```

```
$ pi --help | head -n 120   # confirms non-interactive flag exists
...
--print, -p   Non-interactive mode: process prompt and exit
--mode <mode> Output mode: text (default), json, or rpc
...
```

Global settings file observed (read-only): `~/.pi/agent/settings.json`

```json
{
 "lastChangelogVersion": "0.84.4",
 "theme": "dark",
  "defaultProvider": "Cyber-Attac",
  "defaultModel": "hotdogs-cyber"
}
```

No `~/.config/pi/` directory exists. No `.pi/settings.json` project config exists in the repo (verified: `ls .pi` → `No such file or directory`). Real user config was **not** modified.

## 2. Real temp user-config + project-config registering EMO stdio — ENVIRONMENT-TESTED (pass)

Generated for real from the adapter (not hand-written), written to temp paths only:

```
$ PYTHONPATH=src python3 -c "from emo_cyber_agent.subagent import hosts_pi; ..."
/tmp/post-t020-g1-pi/pi-user-config.json
/tmp/post-t020-g1-pi/pi-project-config.json
```

Both files contain byte-identical content (adapter returns the same snippet for both scopes):

```json
{
  "mcpServers": {
    "emo-cyber-agent": {
      "command": "cyber-agent",
      "args": ["mcp"]
    }
  }
}
```

Source: `hosts_pi.get_user_config_stdio()` / `hosts_pi.get_project_config_stdio()` — verified equal to `get_registration_config(scope, "stdio")` for both scopes (see §7).

**Applicability caveat (environment finding, not a pass/fail on the JSON itself):** pi core 0.84.4 has **no native MCP consumer** for an `mcpServers` key. Evidence:
- `docs/settings.md` documents only `~/.pi/agent/settings.json` (global) vs `.pi/settings.json` (project) with model/UI/trust keys — no `mcpServers` key.
- `README.md` states explicitly: "**No MCP.** Build CLI tools with READMEs (see Skills), or build an extension that adds MCP support."
- `pi list` manages *packages/extensions*, not MCP servers (see §3).
So the snippet is well-formed config **data**, but there is nothing in pi core to paste it into. It would only become actionable via a third-party MCP extension (none installed).

## 3. Discovery via pi — ENVIRONMENT-TESTED (negative result, recorded exactly)

```
$ pi list
No packages installed.
EXIT:0
```

`pi list` lists installed *extensions/packages from settings*, not MCP servers. With zero packages installed, there is no MCP extension present, hence **no discovery path from pi to EMO exists in this environment**. `pi config --help` confirms `pi config` edits global settings (`~/.pi/agent/settings.json`) or project overrides (`.pi/settings.json`) for *package resources* — again, not MCP servers.

Compensating live verification (EMO side, stdio — the transport the adapter claims): `cyber-agent mcp` answers `initialize` and `tools/list` for real:

```
$ printf '{"jsonrpc":"2.0","id":1,...,"method":"initialize",...}' | cyber-agent mcp
{"id": 1, "jsonrpc": "2.0", "result": {"capabilities": {"tools": {}}, "protocolVersion": "2025-06-18", "serverInfo": {"name": "emo-cyber-agent", "version": "0.1.0"}}}
```

`tools/list` returns 6 tools: `cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report`, `cyber_status`, `cyber_extensions` (default exposure per adapter is the first 5; `cyber_extensions` opt-in). Full schemas captured in probe output; descriptions match the read-only contract.

## 4. Delegate safe task via pi non-interactive mode — BLOCKED (environment, recorded exactly)

Non-interactive mode exists (`-p` / `--print`). Safe delegation was attempted with a 60 s timeout:

```
$ pi -p --no-session "Reply with exactly: PI-PROBE-OK"
STDOUT: (empty)
STDERR: 404 The endpoint reappoint-gray-startle.ngrok-free.dev is offline.
        ERR_NGROK_3200
RC: 1
```

Supporting check:

```
$ pi auth check --provider google
not_ready
```

The configured default provider (`Cyber-Attac` / `hotdogs-cyber`) points at an offline ngrok endpoint, and no usable provider credential is present. Therefore **no live LLM-mediated delegation (and hence no live tool call into EMO through pi) could be executed**. No retry was possible without credentials/network — correctly out of scope for a read-only probe. No сессии or config were altered by the attempt.

## 5. Reload / reconnect behavior — NOT-ENVIRONMENT-TESTED

- There is no live pi↔EMO session to reload: no MCP extension installed, no MCP server registered in pi, delegation blocked (§4).
- No non-interactive `reload`/`reconnect` command was found in `pi --help` (commands are `install/remove/uninstall/update/list/config/auth` only).
- The adapter's `RELOAD_NOTE` ("reload the Pi session after registration/edit; stale sessions keep the old tool list") and `EXPOSURE_CHANGE_NOTE` are therefore **unverifiable live** here. They remain plausible per pi's extension model (`pi.registerTool()` refreshes in-session per `docs/extensions.md`), but that is documentation, not an observation. Verdict is honestly NOT-ENVIRONMENT-TESTED, not a failure.

## 6. Project-scoping check — CONTRACT-TESTED (docs only, no live instance)

Observed file layout (read-only `ls`/`cat`):
- Global scope exists: `~/.pi/agent/settings.json` (shown in §1).
- Project scope: `.pi/settings.json` mechanism documented in `docs/settings.md` ("Project settings overriding global settings"); no `.pi/` directory exists in this repo, and none was created (out of write scope).
- Trust flow documented: interactive startup prompts before trusting project-local settings; non-interactive modes (`-p`, `--mode json/rpc`) use `defaultProjectTrust` (`ask` default → project resources ignored) unless `--approve` overrides.

The adapter's `PROJECT_SCOPE_NOTE` (project-bound server visible only inside that project) is **consistent** with this scoping model, and `get_project_config_stdio()` returns the project-scoped snippet as data. But with no MCP extension and no registered server, **scoping isolation could not be observed live** — hence CONTRACT-TESTED, not ENVIRONMENT-TESTED.

## 7. Contract checks (adapter shapes, transport matrix, negotiation) — CONTRACT-TESTED

Executed for real (`PYTHONPATH=src python3`, direct import — no mocks):

```
HOST_ID: pi
TRANSPORTS: ('stdio', 'streamable-http')
TOOL_NAMING: kebab-case
SESSION: server-managed
STATUS: Not-tested
user stdio {"mcpServers": {"emo-cyber-agent": {"command": "cyber-agent", "args": ["mcp"]}}}
user streamable-http {"mcpServers": {"emo-cyber-agent": {"url": "http://localhost:8000/mcp", "transport": "streamable-http"}}}
project stdio (identical to user stdio)
project streamable-http (identical to user http)
TOOLS: ('cyber_audit', 'cyber_review', 'cyber_verify', 'cyber_report', 'cyber_status')
PROTO_VERSIONS: ['2024-11-05', '2025-03-26', '2025-06-18']
is_supported('2025-06-18'): True
negotiate(('2024-11-05','2025-06-18')): 2025-06-18
negotiate(()): None
bad-scope raises: unknown scope: 'bogus' (expected 'user' or 'project')
bad-transport raises: unknown transport: 'bogus' (expected 'stdio' or 'streamable-http')
```

Read-only test suite: `python3 -m pytest tests/unit/subagent/test_hosts_pi.py -v` → **11 passed**.

Findings / mismatches (contract-level, all verified, none hand-waved):

1. **Transport matrix mismatch (internal):** `hosts_pi.TRANSPORTS = ('stdio', 'streamable-http')` but `compat_matrix.HOST_MATRIX['pi'].transports == ('stdio',)` and its lifecycle notes say "Assumed standard MCP lifecycle; not verified against a live host." One of the two needs reconciling; neither is live-verified.
2. **`mcpServers` key has no core consumer:** the adapter's four registration snippets all use an `mcpServers` mapping, but pi core 0.84.4 settings/extensions docs define no such key (see §2 evidence). Any consumer must be an MCP extension, which the adapter does not name or pin.
3. **`TOOL_NAMING = "kebab-case"` vs reality:** actual server tool names are `snake_case` (`cyber_*`) and `TOOL_NAME_MAPPING` is the identity map. The kebab-case label appears to describe pi host convention, not an applied transformation — worth a clarifying comment, since a reader could expect renaming.
4. **HTTP variant is config-data only (correct per brief):** `get_*_config_http()` returns `{"url": "http://localhost:8000/mcp", "transport": "streamable-http"}`. No EMO HTTP serving capability was found (`cyber-agent mcp --help`: "Start the MCP server over stdio"; repo-wide grep for streamable/uvicorn/SSE shows no EMO HTTP server). The adapter docstring already flags the URL as a placeholder; confirmed accurate. **No HTTP test was run against EMO.**
5. **Negotiation helpers are sound:** `is_protocol_supported` checks membership in `discovery.PROTOCOL_VERSIONS` at call time (no hardcoding); `negotiate_protocol_version` returns latest-common or `None` (abort, no silent fallback). Live EMO advertises `2025-06-18`, which is within `discovery.PROTOCOL_VERSIONS` and the compat-matrix `[2024-11-05, 2025-06-18]` range — consistent, but negotiated only against the local EMO binary, not against any pi-side offered versions (pi exposes none observably).

## Verdicts per area

| Area | Verdict | Basis |
|---|---|---|
| 1. pi binary presence/version | ENVIRONMENT-TESTED | `pi --version` → `0.84.4`, exit 0 |
| 2. Temp user + project stdio configs | ENVIRONMENT-TESTED | Real files in `/tmp/post-t020-g1-pi/` generated from adapter; EMO stdio `initialize` + `tools/list` verified live |
| 3. Discovery via pi | ENVIRONMENT-TESTED | `pi list` → `No packages installed`; core pi has no native MCP/discovery (README "No MCP"); negative result observed, not assumed |
| 4. Safe-task delegation (`-p`) | BLOCKED | `pi -p` → RC 1, ngrok endpoint offline (`ERR_NGROK_3200`); `pi auth check --provider google` → `not_ready` |
| 5. Reload / reconnect | NOT-ENVIRONMENT-TESTED | No live session to reload; no non-interactive reload command in `pi --help` |
| 6. Project-scoping | CONTRACT-TESTED | Scoping + trust model confirmed in `docs/settings.md` and file layout; no live scoped server to observe |
| 7. Contract checks (shapes, transports, negotiation) | CONTRACT-TESTED | Direct-import checks pass; `test_hosts_pi.py` 11/11 pass; 4 documented mismatches/clarifications above; HTTP correctly untested |

## Top limitation

**pi core 0.84.4 has no native MCP support — MCP integration requires an unnamed third-party extension that is not installed (`pi list` → empty), and the configured LLM provider endpoint is offline — so no end-to-end live pi→EMO delegation is possible in this environment.** The adapter's `mcpServers` snippets are well-formed data (and EMO's stdio side is live-verified: `initialize` → `2025-06-18`, 6 tools listed), but they currently have no actionable consumer. Closing the loop needs, at minimum: (a) a pinned MCP extension for pi plus its actual config schema (to validate/replace the `mcpServers` snippets), and (b) a reachable provider credential for `-p` delegation. Separately, the internal `TRANSPORTS` vs compat-matrix (`streamable-http` in vs out) discrepancy should be reconciled, and the `TOOL_NAMING = "kebab-case"` label clarified against the snake_case identity mapping.
