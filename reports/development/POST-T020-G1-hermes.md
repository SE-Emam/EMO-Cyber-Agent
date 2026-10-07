# POST-T020 G1-Hermes — Real Host Interop Test (Hermes × EMO stdio)

Role: G1-Hermes, real host interop tester. Working directory:
`/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`.
Constraint honored: this report is the only file written; `src/` and `tests/`
untouched. All Hermes mutations went to an isolated home
(`HERMES_HOME=/tmp/hermes-g1-test`); the real `~/.hermes` config was never
modified (`hermes mcp list` on the real home still reports "No MCP servers
configured").

Adapter under test: `src/emo_cyber_agent/subagent/hosts_hermes.py`
(per-server filtering guidance, task allowlists). EMO transport: stdio-only
(`cyber-agent mcp`). Server: `emo-cyber-agent 0.1.0`.

## 1) Binary presence — `hermes --version`

Command: `hermes --version`

Output (exit 0):

```text
Hermes Agent v0.21.4 (2026.9.21) · upstream c0d72947
Install directory: /Users/emamabdullaziz/.hermes/hermes-agent
Install method: git
Python: 3.11.16
OpenAI SDK: 2.24.0
Update available: 9505 commits behind — run 'hermes update'
```

Verdict: **ENVIRONMENT-TESTED** (binary present, version pinned by observation:
v0.21.4).

## 2) Real temp config registering EMO stdio

Isolated home used for every Hermes state change:

Command: `HERMES_HOME=/tmp/hermes-g1-test hermes config path` → `/tmp/hermes-g1-test/config.yaml` (exit 0).

Registration command: `HERMES_HOME=/tmp/hermes-g1-test hermes mcp add emo-cyber-agent --command cyber-agent --args mcp`
(first attempt without stdin stalled at the interactive `Enable all 6 tools?
[Y/n/select]:` prompt and was cancelled with no state written; retried with
piped confirmation).

Command: `printf 'Y\n' | HERMES_HOME=/tmp/hermes-g1-test hermes mcp add emo-cyber-agent --command cyber-agent --args mcp`

Output (exit 0):

```text
Connecting to 'emo-cyber-agent'...
✓ Connected! Found 6 tool(s) from 'emo-cyber-agent':
    cyber_audit       Perform a scoped, read-only security audit of an authorized ...
    cyber_review      Run a focused, read-only security review of a specific asset...
    cyber_verify      Request verification of a specific finding candidate using o...
    cyber_report      Project Core findings into a JSON, JSONL, or Markdown report...
    cyber_status      Return read-only runtime status: version, capabilities, and ...
    cyber_extensions  Inspect the extension catalog as data: list, describe, resol...
Enable all 6 tools? [Y/n/select]:
✓ Saved 'emo-cyber-agent' to /tmp/hermes-g1-test/config.yaml (6/6 tools enabled)
Start a new session to use these tools.
```

Persisted registration (`/tmp/hermes-g1-test/config.yaml`, secrets redacted):

```yaml
mcp_servers:
  emo-cyber-agent:
    command: cyber-agent
    args:
      - mcp
    enabled: true
```

Note: on-disk key is `mcp_servers` (snake_case); the adapter's
`get_stdio_config()` returns `{"mcpServers": ...}` (camelCase) as a
documentation snippet — same server/command/args content, different key
spelling than what this Hermes version persists. Worth aligning in the adapter
docs.

Verdict: **ENVIRONMENT-TESTED** (live discovery of all 6 tools at registration;
config persisted in isolated home only).

## 3) Discovery + per-server filtering (the key Hermes feature)

Discovery command: `HERMES_HOME=/tmp/hermes-g1-test hermes mcp test emo-cyber-agent` (exit 0):

```text
Testing 'emo-cyber-agent'...
Transport: stdio → cyber-agent
Auth: none
✓ Connected (1293ms)
✓ Tools discovered: 6
    cyber_audit / cyber_review / cyber_verify / cyber_report / cyber_status / cyber_extensions
```

`hermes mcp list` (exit 0): `emo-cyber-agent | cyber-agent mcp | all | ✓ enabled`.

Filtering mechanism: `hermes tools disable|enable <server>:<tool>`
(`server:tool` notation per `hermes tools disable --help`). Full vs filtered,
each confirmed via `hermes tools list` (exit 0 in all cases):

| Step | Command | `tools list` MCP line |
|---|---|---|
| Full (baseline) | — (post-add default) | `emo-cyber-agent  all tools enabled` |
| security-review subset (5 safe) | `hermes tools disable emo-cyber-agent:cyber_extensions` → `✓ Disabled: emo-cyber-agent:cyber_extensions` | `emo-cyber-agent  [excluded: cyber_extensions]` |
| verify-only subset (2 tools) | `hermes tools disable emo-cyber-agent:cyber_audit emo-cyber-agent:cyber_review emo-cyber-agent:cyber_report` → `✓ Disabled: ...` | `emo-cyber-agent  [excluded: cyber_extensions, cyber_audit, cyber_review, cyber_report]` (only `cyber_verify` + `cyber_status` remain = `TASK_ALLOWLISTS["verify-only"]`) |
| Effective disable (0 tools) | disable all six `emo-cyber-agent:<tool>` → `✓ Disabled: ... (all 6)` | `emo-cyber-agent  [excluded: cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions]` |
| Restore full | `hermes tools enable emo-cyber-agent:<all six>` → `✓ Enabled: ...` | `emo-cyber-agent  all tools enabled` |

Filtering is host-side: while filtered to verify-only,
`hermes mcp test emo-cyber-agent` still reported `✓ Tools discovered: 6`
(server-side discovery unaffected; the host view is what narrows).

Disabled-server behavior, as observable:

- `hermes tools disable emo-cyber-agent` (bare server name, no `:tool`) →
  `✗ Unknown toolset 'emo-cyber-agent'` (exit 0, no state change). There is no
  whole-server disable path through `tools disable`; per-tool exclusion is the
  only observed mechanism (all-six-excluded = effective disable).
- `hermes mcp test no-such-server` → `✗ Server 'no-such-server' not found in
  config. Available: emo-cyber-agent` (exit 3). Unknown/disabled-server
  references fail closed with a non-zero exit.
- `hermes tools --summary` is not a valid invocation in this version
  (`hermes: error: unrecognized arguments: --summary`); `--summary` belongs to
  bare `hermes tools`, which refuses non-interactive use (`requires an
  interactive terminal`).

Verdict: per-server filtering **ENVIRONMENT-TESTED** (filtered subset vs full
proven live, both directions plus restore); disabled-server behavior
**ENVIRONMENT-TESTED** with the noted scope (fail-closed unknown-server exit 3;
no bare-server disable verb exists).

## 4) Delegate safe task

Attempted: `HERMES_HOME=/tmp/hermes-g1-test hermes -z "Call the emo-cyber-agent
cyber_status tool and report the version."` →

```text
hermes -z: agent failed: Hermes is not connected to any AI provider yet. ...
(Advanced: put an API key such as OPENROUTER_API_KEY in /tmp/hermes-g1-test/.env.)
```

Control probe on the real home (no state change, inference-capable path):
`hermes -z "Reply with exactly the word PONG and nothing else."` →

```text
hermes -z: agent failed: No access token found for Nous Portal login.
```

The default model (`tencent/hy3` via `nous`) has no valid credentials
(`hermes status`: `Nous Portal ✗ not logged in ... Invalid refresh token`).
No API key was copied into the isolated home (by design — no secret movement),
and no inference was triggered, so no agent-driven tool call could be observed.

Server-side substitute (no LLM, proves the delegated tool itself works over the
same stdio path Hermes uses): raw JSON-RPC against `cyber-agent mcp`
(`initialize` with `protocolVersion 2025-06-18` →
`notifications/initialized` → `tools/list` → `tools/call cyber_status`):

- `initialize` → `protocolVersion: 2025-06-18`, `serverInfo:
  {name: emo-cyber-agent, version: 0.1.0}`
- `tools/call cyber_status {}` → `{"status": "ok", "tool": "cyber_status",
  "result": {"version": "0.1.0", "status": "foundation", ...}}`

Verdict: agent-driven delegation **BLOCKED** (no usable provider auth in either
home); underlying `cyber_status` tool execution over stdio
**ENVIRONMENT-TESTED** via direct probe.

## 5) Contract checks (adapter vs live)

Ran against the real adapter source (`PYTHONPATH=src python3`, system python
with pydantic; the repo `.venv` lacks pydantic — environment note, not a code
finding):

- `get_per_task_allowlists()` →
  `security-review`(5 safe) / `verify-only`(`cyber_verify`,`cyber_status`) /
  `report-only`(`cyber_report`,`cyber_status`) / `status-only`(`cyber_status`);
  `cyber_extensions` in none. `get_task_allowlist('bogus-task')` →
  `ValueError: unknown task kind: 'bogus-task'` (no fallback to full set).
  Cross-checked live: the verify-only filtered view (§3) exposes exactly
  `TASK_ALLOWLISTS["verify-only"]`. Verdict: **CONTRACT-TESTED**.
- Negotiation: `PROTOCOL_VERSIONS =
  ('2024-11-05','2025-03-26','2025-06-18')`;
  `negotiate_protocol_version(all)` → `2025-06-18` (latest common);
  `negotiate_protocol_version(['1999-01-01'])` → `None` (abort, no silent
  fallback). Live `initialize` settled on `2025-06-18`, consistent with the
  rule. Verdict: **CONTRACT-TESTED**.
- Troubleshooting data: 6 entries
  (`server-not-found`, `tool-not-visible`, `over-exposed-tools`,
  `protocol-version-mismatch`, `http-connection-refused`,
  `discovery-mismatch`); the `over-exposed-tools` fix (apply
  `get_task_allowlist(task)` via host-side filtering, re-list) is exactly the
  procedure proven in §3. Two entries' symptoms were observed live in
  equivalent form (interactive-cancel → server not persisted; unknown server →
  fail-closed exit 3). Verdict: **CONTRACT-TESTED** (procedure validated;
  entry-by-entry symptom reproduction not attempted).
- Discovery advertisement (`discovery.build_advertisement()`):
  `emo-cyber-agent 0.1.0`, protocols `2024-11-05/2025-03-26/2025-06-18`,
  surface `1.0`, 6 tools with `safe_default=True` except `cyber_extensions`.
  Matches the 6 tools Hermes discovered live. Verdict: **CONTRACT-TESTED**
  (server side), discovery over Hermes **ENVIRONMENT-TESTED** (§3).

## Verdicts

| Area | Verdict |
|---|---|
| Binary presence/version (v0.21.4) | ENVIRONMENT-TESTED |
| Stdio registration + discovery (6/6 tools) | ENVIRONMENT-TESTED |
| Per-server filtering (subset vs full) | ENVIRONMENT-TESTED |
| Disabled-server behavior (fail-closed; no bare-server disable verb) | ENVIRONMENT-TESTED |
| Safe-task delegation via Hermes agent | BLOCKED (no provider auth) |
| `cyber_status` over stdio (direct probe) | ENVIRONMENT-TESTED |
| Task allowlists (incl. unknown-task abort) | CONTRACT-TESTED |
| Protocol negotiation | CONTRACT-TESTED |
| Troubleshooting data + discovery advertisement | CONTRACT-TESTED |

Top limitation: no end-to-end LLM-driven delegation was possible (Nous Portal
unauthenticated, isolated home credential-free by design), so per-server
filtering is proven at the host config/CLI layer (`tools list` excluded-sets,
both directions plus restore) rather than by observing the model actually
calling — or being denied — a filtered tool. Re-running §4 with a funded,
authenticated provider would close that gap; everything else the adapter claims
about Hermes registration, filtering, allowlists, and negotiation held up
against the live host.

Cleanup: isolated state left at `/tmp/hermes-g1-test` (outside the repo);
real `~/.hermes` untouched; final live state of the isolated home is full
exposure restored (`all tools enabled`).
