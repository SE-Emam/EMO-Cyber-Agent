# POST-T021 Pi Native Integration — T21-B Report

**Agent:** T21-B (Pi Native Integration Agent) · **Date (UTC):** 2026-10-08
**Working directory:** `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
**Scope:** write-only this file; no `src/`/`tests/` modifications; no network installs; no quota/credential bypass.
**Verdict: ENVIRONMENT-BLOCKED** — pi 0.84.4 (re-verified today, not trusted stale) has no built-in/native MCP consumer path; the only MCP path is a 3rd-party extension that is **not installed** (installing it requires network `pi install`, deliberately NOT executed per task constraints). No live delegation round-trip occurred, so PASS criteria (real delegation proof) are unmet.

---

## 1. Binary discovery + version (verbatim, re-verified 2026-10-08)

### 1.1 `which pi` + `ls`

```
$ which pi
/Users/emamabdullaziz/.local/bin/pi
$ ls -l "$(which pi)"
lrwxr-xr-x  1 emamabdullaziz  staff  70 Sep  2 19:09 /Users/emamabdullaziz/.local/bin/pi -> ../lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js
```

Package: `@earendil-works/pi-coding-agent` (realpath `/Users/emamabdullaziz/.local/lib/node_modules/@earendil-works/pi-coding-agent/`).

### 1.2 `pi --version`

```
0.84.4
```

Identical to the prior report's 0.84.4 — confirmed fresh today, not carried over.

### 1.3 `pi --help` (verbatim)

```
pi - AI coding assistant with read, bash, edit, write tools

Usage:
  pi [options] [--] [@files...] [messages...]

Commands:
  pi install <source> [-l]     Install extension source and add to settings
  pi remove <source> [-l]      Remove extension source from settings
  pi uninstall <source> [-l]   Alias for remove
  pi update [source|self|pi]   Update pi, extensions, or model catalogs
  pi list                      List installed extensions from settings
  pi config [-l]               Open TUI to enable/disable package resources (Tab switches scope)
  pi auth <command>            Print credentials or check provider readiness
  pi <command> --help          Show help for install/remove/uninstall/update/list/config/auth
```

Full options list includes `--provider/--model/--api-key`, `--mode`, `--print/-p`, `--continue/--resume/--session*`, `--tools/-t`, `--exclude-tools/-xt`, `--extension/-e`, `--no-extensions/-ne`, `--offline`, `--help/--version`. Built-in tools:

```
Built-in Tool Names:
  read       - Read file contents
  bash       - Execute bash commands
  powershell - Execute PowerShell commands on Windows
  edit       - Edit files with find/replace
  write      - Write files (creates/overwrites)
  grep       - Search file contents (read-only, off by default)
  find       - Find files by glob pattern (read-only, off by default)
  ls         - List directory contents (read-only, off by default)
```

No `mcp` tool, no `mcpServers` flag, no MCP transport option anywhere in `--help`.

### 1.4 `pi mcp --help` (verbatim — NO native `mcp` subcommand)

Running `pi mcp --help` prints the **same top-level help** as `pi --help` (unknown-subcommand fallback), exit 0. There is no `mcp` command, no `mcp add`, no `mcpServers` management.

### 1.5 `pi list` + settings + config-file inventory (key-names/sizes only, no secret values)

```
$ pi list
No packages installed.
```

```
$ ls -la ~/.pi/agent/
auth.json (279 B, 0600) · auth.json.bak (337 B) · bin/ · models-store.json (18804 B) · models-store.json.bak ·
models.json (2633 B) · models.json.bak · sessions/ · settings.json (126 B)
$ cat ~/.pi/agent/settings.json
{
 "lastChangelogVersion": "0.84.4",
 "theme": "dark",
  "defaultProvider": "Cyber-Attac",
  "defaultModel": "hotdogs-cyber"
}
```

Absent (all checked today, none exist): `~/.pi/agent/mcp.json`, `.pi/mcp.json`, `.mcp.json`, `./mcp.json`, `~/.config/mcp/mcp.json`.

### 1.6 Design-principle confirmation (shipped docs, verbatim, re-verified at corrected path)

Package docs live at `<pkg>/docs/` (the prior report's `dist/docs/` path no longer resolves; content confirmed at `docs/`):

`docs/usage.md`:

> "It intentionally does not include built-in MCP, sub-agents, permission popups, plan mode, to-dos, or background bash. You can build or install those workflows as extensions or packages, or use external tools such as containers and tmux."

`docs/extensions.md`: **zero** case-insensitive matches for `mcp` (verified today: `grep -c -i mcp docs/extensions.md` → `0`). The extension mechanism is generic `pi.registerTool()` custom tools. Conclusion: **no native MCP consumer exists in the installed binary**.

---

## 2. Native MCP consumer path? (pi 0.84.4)

**Answer: NO native path. Extension-gated path only, via 3rd-party extension, NOT installed.**

| Question | Finding (2026-10-08) |
|---|---|
| Built-in `mcp` command / `mcpServers` config / MCP transport flag in 0.84.4? | **No.** `pi mcp --help` → top-level help fallback; `pi --help` lists no MCP surface; docs explicitly disclaim built-in MCP. |
| Extension system present? | **Yes.** `pi install <source>`, `pi list`, `pi config`, `--extension/-e`, `--no-extensions`, `pi.registerTool()` API. |
| Which 3rd-party extension provides the MCP consumer path? | Two public candidates (from prior read-only research, restated — nothing installed or fetched today): **(a) `pi-mcp-extension` v1.5.1** — config `~/.pi/agent/mcp.json` (global) / `.pi/mcp.json` (project), stdio/streamable-http/sse transports, `/mcp` commands, MCP spec 2025-03-26. **(b) `pi-mcp-adapter`** (pi.dev v5.1.0; also `pi-codemcp` v1.5.2 companion) — proxy `mcp` tool, `.mcp.json` / `~/.config/mcp/mcp.json`, `/mcp reconnect`. Either would be the consumer; neither ships with pi. |
| Is it installed? | **No.** `pi list` → `No packages installed.` No `mcp.json` in any known location. |
| Exact install command (NOT executed)? | `pi install npm:pi-mcp-extension` **or** `pi install npm:pi-mcp-adapter` (project-local variant appends `-l`). **Deliberately not executed**: requires network (npm registry fetch) — out of scope under no-network-install constraint. |
| Built-in MCP on newer pi? | Adapter docs state Pi 0.99+ added own MCP support (`pi mcp add`). **Not applicable**: installed binary is 0.84.4. Upgrade (`pi update self/pi`) requires network — noted, not executed. |

---

## 3. Configuration attempted

**Can EMO be registered as an MCP server without the 3rd-party extension? No.**

No `mcp.json` (global, project, or shared) was written today: with no consumer in pi 0.84.4 to read it, writing one would prove nothing and would touch out-of-scope global config. The exact future config is given in §5 Reproduction Kit instead. `pi --help` exposes no `--mcp-*` flag and no `mcpServers` key, so there is no native registration surface to attempt against.

---

## 4. Delegation matrix — all NOT-EXECUTED (native path absent → blocked, not skipped)

| Step | Result + reason |
|---|---|
| Register EMO stdio (temp config) | NOT-EXECUTED — no `mcp.json` consumer in pi 0.84.4 to read it. |
| Discover (`tools/list`) | NOT-EXECUTED — no host tool bridge. |
| Tool filtering (safe-default 5 vs opt-in 2) | NOT-EXECUTED — nothing to filter through pi. |
| Delegate safe task (e.g. `cyber_status`) | NOT-EXECUTED — no LLM→MCP tool-call path; **never claimed without a live provider round-trip, none occurred.** |
| Progress reporting | NOT-EXECUTED. |
| Result capture | NOT-EXECUTED. |
| Failure case | NOT-EXECUTED. |
| Recovery | NOT-EXECUTED (`/mcp reconnect` / `/reload` exist only under the extension). |
| Reconnect | NOT-EXECUTED. |
| Scope mismatch | NOT-EXECUTED (project vs global scoping semantics defined only by the extension). |
| Capability widening | NOT-EXECUTED. |

### Server-side health (isolates the blocker to the host, not EMO — `PYTHONPATH=src` + MCP stdio contract only)

Direct stdio `initialize` probe succeeds today:

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t21b-probe","version":"0.0.0"}}}' | PYTHONPATH=src .venv/bin/cyber-agent mcp
{"audit_id": "", "duration_ms": 0, "error_category": "", "request_id": "startup", "status": "started", "tool": "server"}
{"id": 1, "jsonrpc": "2.0", "result": {"capabilities": {"tools": {}}, "protocolVersion": "2025-03-26", "serverInfo": {"name": "emo-cyber-agent", "version": "0.2.0"}}}
{"audit_id": "", "duration_ms": 0, "error_category": "", "request_id": "shutdown", "status": "stopped", "tool": "server"}
```

`tools/list` returns all 7 tools (`cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report`, `cyber_status`, `cyber_extensions`, `cyber_threat_intel`). CLI is stdio-only (`cyber-agent mcp --help` → `Start the MCP server over stdio (thin adapter over Core)`, no `--port/--bind/--http` flags). So EMO speaks MCP correctly; pi 0.84.4 simply has no client to talk to it.

### Live-provider probe (second, independent blocker — no bypass)

```
$ pi auth check --provider Cyber-Attac --model hotdogs-cyber
ready
$ pi auth check --provider Cyber-Attac --model hotdogs-cyber --json
{"status":"ready","provider":"Cyber-Attac","authType":"api_key"}
$ PI_OFFLINE=1 pi -p --no-session "say OK"
404 The endpoint reappoint-gray-startle.ngrok-free.dev is offline.

ERR_NGROK_3200
```

Credentials present (`ready`), endpoint unreachable (ngrok offline). Even with an MCP extension, live LLM delegation would need a reachable provider — documented, not worked around.

---

## 5. BLOCKED reason (exact cause with proof)

**ENVIRONMENT-BLOCKED: missing native MCP by design + extension not installed + provider offline.**

1. `pi --version` → `0.84.4` (fresh today); `pi --help` / `pi mcp --help` expose no `mcp` subcommand, flag, tool, or config key.
2. Shipped `docs/usage.md` explicitly states pi omits built-in MCP by design (extension-gated); `docs/extensions.md` has 0 `mcp` mentions.
3. `pi list` → `No packages installed`; no `mcp.json` in global/project/shared locations.
4. The only MCP path is a 3rd-party extension (`pi-mcp-extension` or `pi-mcp-adapter`) via `pi install npm:<pkg>` — a network operation outside this task's sandbox, hence not performed.
5. Secondary: configured default provider (`Cyber-Attac/hotdogs-cyber`) reports `auth check: ready` but its endpoint is ngrok-offline (`ERR_NGROK_3200`), so a future retry also needs provider/quota remediation. No bypass attempted.

Nothing in EMO source was changed; no network install was run; no credentials were touched; only this report file was written.

---

## 6. Reproduction Kit — ONE-STEP retry for a future operator (network + provider available)

**Prerequisites:** (a) network access to npm/pi.dev; (b) reachable LLM provider with quota (fix/replace the offline ngrok endpoint or set `defaultProvider`/`defaultModel` to a live one).

```bash
# 0. Confirm baseline (expect 0.84.4 pre-upgrade, or newer if upgraded)
pi --version && pi list

# 1. Install EXACTLY ONE MCP consumer extension (network; safe to run only in retry env)
pi install npm:pi-mcp-extension
# — or the adapter alternative —
# pi install npm:pi-mcp-adapter
pi list   # expect the package listed, not "No packages installed."

# 2. Register EMO stdio as a TEMP project-scoped config (preferred: project scope, no global pollution)
#    File: <repo>/.pi/mcp.json  (pi-mcp-extension project path; adapter ALSO reads .mcp.json — see note)
cat > .pi/mcp.json <<'EOF'
{
  "mcpServers": {
    "emo-cyber-agent": {
      "command": "/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/.venv/bin/cyber-agent",
      "args": ["mcp"],
      "transport": "stdio",
      "lifecycle": "eager"
    }
  }
}
EOF
# Adapter-alternative path (same content): .mcp.json in repo root.

# 3. Reload so the new server + tool list take effect, then discover
#    interactive: /reload  (or restart pi)
#    headless probe of server health (bypasses pi; proves server, not delegation):
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"retry-probe","version":"0.0.0"}}}' \
  | PYTHONPATH=src /Users/emamabdullaziz/Desktop/EMO-Cyber-Agent/.venv/bin/cyber-agent mcp

# 4. Discover via the extension (interactive session with a live provider):
#    /mcp                 -> status summary; expect emo-cyber-agent connected
#    /mcp:start emo-cyber-agent   (only if lifecycle lazy)
#    /mcp tools  (adapter) -> expect cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status (+ opt-ins)

# 5. Filter: confirm default exposure = 5 safe tools only
#    (cyber_extensions, cyber_threat_intel hidden unless opted in via includeTools/directTools per extension docs)

# 6. Delegate safe task (needs live provider + quota):
pi -p "via the emo-cyber-agent MCP server, run cyber_status and summarize the result"
#    expect: tool call cyber_status -> structured result -> summary; record transcript + session id.

# 7. Progress / result / failure / recovery / reconnect / mismatch battery:
#    - progress: long audit should stream updates (extension requestTimeoutMs default 30000; bump per-server if needed)
#    - failure: stop server mid-call -> expect explicit error, no silent fallback
#    - recovery: /mcp reconnect emo-cyber-agent then re-call
#    - reconnect: restart pi session -> /mcp shows server re-attached (eager) or /mcp:start (lazy)
#    - scope mismatch: project .pi/mcp.json server must NOT appear in an unrelated project; global
#      ~/.pi/agent/mcp.json server must appear everywhere
#    - capability mismatch: request cyber_threat_intel while filtered out -> expect host refusal/unknown-tool, not a hallucinated result

# 8. Cleanup (restore pre-retry state):
rm .pi/mcp.json   # (and/or .mcp.json if adapter path was used)
# pi remove pi-mcp-extension   # or: pi remove pi-mcp-adapter  (only if the retry env must be restored)
```

Expected versions at time of writing: `pi-mcp-extension@1.5.1`, `pi-mcp-adapter@5.1.0`; MCP protocol `2025-03-26`. Pin versions in the retry log.

---

## Evidence log (commands run 2026-10-08, all local, no network installs)

| # | Command | Result |
|---|---|---|
| E1 | `which pi; ls -l "$(which pi)"; pi --version` | `/Users/emamabdullaziz/.local/bin/pi` → `../lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js`; `0.84.4` |
| E2 | `pi --help` | full help captured (§1.3); no MCP surface |
| E3 | `pi mcp --help` | identical top-level help, exit 0 → no native subcommand |
| E4 | `pi list` | `No packages installed.` |
| E5 | `ls ~/.pi/agent/` + `cat settings.json` + mcp.json absence sweep | settings only (key-names/sizes §1.5); all `mcp.json` locations absent |
| E6 | `grep -c -i mcp docs/extensions.md` + `usage.md` quote | `0` hits; built-in MCP explicitly disclaimed (§1.6) |
| E7 | stdio `initialize` + `tools/list` probes via `PYTHONPATH=src .venv/bin/cyber-agent mcp` | `2025-03-26`, `emo-cyber-agent 0.2.0`, 7 tools — server healthy |
| E8 | `pi auth check --provider Cyber-Attac --model hotdogs-cyber [--json]` | `ready` / `{"status":"ready","provider":"Cyber-Attac","authType":"api_key"}` |
| E9 | `PI_OFFLINE=1 pi -p --no-session "say OK"` | `404 … ERR_NGROK_3200` (endpoint offline) |

No files other than this report were written. No network installs, no credential access, no quota use beyond single offline-failing headless probes.
