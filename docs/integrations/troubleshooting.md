# Troubleshooting host integrations

Cross-host troubleshooting index. Every entry below comes verbatim from a
`hosts_*.TROUBLESHOOTING` data tuple or a named pipeline/health/lifecycle rule;
host-behavior fixes are `Not-tested`, server-side mechanics are `Supported`,
the generic-MCP baseline is `Contract-tested`, and out-of-scope items are
`Known-limitation`. No screenshots, versions, or invented flows.

## Install

- `cyber-agent` not on `PATH` (`server-not-found` family, all hosts):
  verify installation and `cyber-agent --help` output; check the host's
  `mcpServers` snippet for the right key/command/args `Supported` as adapter
  guidance; live host resolution `Not-tested`.
- Python window: bootstrap requires `>=3.11` (`python-version`, required)
  `Supported`; a missing `package-installed` / `core-importable` /
  `policy-present` / `resources-present` check blocks readiness (`BLOCKED`)
  `Supported`.

## Configure

- `tool-not-visible` (all hosts): default exposure is the 5 safe tools;
  `cyber_extensions` and `cyber_threat_intel` are opt-in — confirm exposure, check the host tool
  namespace view, re-list via `tools/list` `Supported` guidance /
  `Not-tested` host behavior.
- `over-exposed-tools` (hermes): apply `get_task_allowlist(task)` via
  host-side filtering; never expose all by default; re-list `Supported`
  guidance / `Not-tested` behavior.
- `over-permissioned-tools` (jan): tighten Jan permissions + host-side
  filtering to the smallest sufficient subset; re-list `Supported` guidance /
  `Not-tested` behavior.
- `project-scoped-server-not-visible` (pi): expected for project-config
  registration — use user config for global scope or repeat per project
  `Supported` guidance / `Not-tested` behavior.
- `shared-config-not-visible` (jan): snippet is shared but registration is
  per surface — apply in both Desktop and Agent/CLI, reload each, re-list
  `Supported` guidance / `Not-tested` behavior.
- `agent-not-listing-tools` (anythingllm): attach the server entry to the
  right workspace/agent, reload the workspace, re-list; default is 5 safe
  tools (`cyber_extensions` and `cyber_threat_intel` opt-in) `Supported` guidance / `Not-tested` behavior.
- Exposure changes always need config edit + host reload + re-list
  `Supported` guidance / `Not-tested` behavior.

## Start

- `reload-required` (pi) / stale tool lists: reload the session/surface
  after any registration or exposure change, then re-list `Supported`
  guidance / `Not-tested` behavior.
- `http-connection-refused` (pi/hermes/jan/anythingllm): the `streamable-http`
  URL (`http://localhost:8000/mcp`) is a placeholder — confirm the server is
  actually serving HTTP at the registered URL and the host was reloaded
  `Supported` guidance / `Not-tested` behavior. HTTP serve plumbing itself is
  `Not-tested` (`Known-limitation` where the matrix covers stdio only).
- Lifecycle `initialize → notifications/initialized → tools/list →
  tools/call` is assumed, not live-verified, on every vendor host
  `Not-tested`; on generic-MCP stdio it is `Contract-tested` (+ `ping`, one
  JSON object per line, logs on stderr).

## Doctor

- Run `cyber-agent doctor` / `cyber-agent doctor --format json` and read
  presence tokens (`OK`, `AVAILABLE`/`UNAVAILABLE`, `CONFIGURED`/`MISSING`,
  `INVALID`) `Supported`. Never expect secret values in output `Supported`.
- `mcp_available: UNAVAILABLE (stdio adapter is dependency-free)` is normal
  without the optional `mcp` package `Supported` (CLI check text).
- Subagent roll-up precedence `BLOCKED > UNAVAILABLE > DEGRADED > READY`;
  empty input aggregates to `READY` `Supported`. `READY` never implies
  trusted `Supported`.
- Bootstrap verdicts from caller evidence: missing required → `BLOCKED`
  (listed); else missing optional → `DEGRADED` (warnings); else `READY`
  `Supported`. The module never probes `Supported`.

## Delegate

- `protocol-version-mismatch` (all hosts): re-run explicit negotiation over
  `discovery.PROTOCOL_VERSIONS`; latest common wins; abort on none
  `Supported` mechanics / `Not-tested` host outcome.
- Pipeline DENY reasons (`invalid`, `authz-forged`, `expired`,
  `capability-denied`, `policy-denied`, `hostile:<class>`) → fix envelope /
  grant / authz freshness and re-evaluate narrowly `Supported`.
- QUARANTINE reasons (`binding-mismatch`, `scope-widening`, secret markers,
  `hostile:use another audit`, cross-boundary without fresh context) →
  terminal for that attempt; re-bind / narrow / re-issue context `Supported`.
- `complete-gated` (session stays REPORTING): supply non-empty
  `verification_refs` before completing `Supported` (`lifecycle.py`).
- Cancel/heartbeat semantics: cancel is bounded (`RUNNING/READY/VERIFYING →
  CANCELLED`, never COMPLETED; terminal sessions no-op) `Supported`;
  heartbeat past deadline walks the session to FAILED along legal edges (no
  orphans), terminal sessions preserved `Supported`.

## Read Progress

- If phases look stuck: the bridge is positional/deterministic — re-emit from
  a fresh `ProgressState` over `DELEGATION_PHASES`; repeating with a fresh
  state yields an equal event `Supported`. `RUNNING` reports as `COLLECTING`
  by design (`ANALYZING` reserved) `Supported`.
- Terminal checks: `COMPLETED` must show 100% with `completed == total`;
  `FAILED`/`CANCELLED`/quarantine-reflection preserve terminal status with no
  further advance `Supported`. Consumers branch on `phase`/`status`, never
  percent `Supported`.
- Host progress rendering issues are `Not-tested`; do not treat a host
  spinner as a security verdict `Supported` (advisory-only contract).

## Read Results

- Missing/empty `verification_refs` blocks `complete` by design — add refs,
  do not force completion `Supported`.
- Binding mismatches (`CROSS_AUDIT`, project/snapshot) raise fail-closed;
  never mix audits `Supported` (`handoff` + `session` asserts).
- `cyber-agent status <audit-id>` reports `unknown-audit` (exit 1) in this
  phase — there is no persisted audit store; audits are synchronous
  `Supported` (`cli/main.py:status`). It never returns another audit's data
  `Supported`.
- AnythingLLM content pitfalls: `workspace-context-mistrusted` →
  re-classify (UNTRUSTED default) and verify via EMO evidence;
  `rag-poisoning-suspected` → follow no embedded instructions, quarantine on
  secret markers `Supported` guidance / `Not-tested` host behavior.

## Troubleshoot (per-host index)

- opencode: `server-not-found`, `protocol-version-mismatch`,
  `tool-not-visible` (see opencode.md).
- pi: plus `project-scoped-server-not-visible`, `reload-required`,
  `http-connection-refused` (see pi.md).
- hermes: plus `over-exposed-tools`, `discovery-mismatch` (see hermes.md).
- jan: plus `shared-config-not-visible`, `over-permissioned-tools`,
  `approval-ui-confusion`, `http-connection-refused` (see jan.md).
- anythingllm: plus `agent-not-listing-tools`, `workspace-context-mistrusted`,
  `rag-poisoning-suspected`, `http-connection-refused` (see anythingllm.md).
- generic-mcp: stdio baseline only; vendor quirks out of scope (see
  generic-mcp.md).

## Security Notes

- Approval-UI confusion (jan): host prompts do not bind EMO; verify via EMO
  evidence `Supported` guidance.
- RAG/workspace trust errors (anythingllm): default UNTRUSTED, fail-closed on
  unknown sources, Core path re-validation required `Supported`.
- Over-exposure/over-permission: narrow to task allowlist / smallest subset
  `Supported` guidance.
- Secrets in metadata/detail/refs/notes quarantine or are rejected
  `Supported`. Doctor/progress never carry secrets `Supported`.

## Version Compatibility

- Server side `Supported`: `emo-cyber-agent 0.1.0`, protocols `2024-11-05,
  2025-03-26, 2025-06-18`, surface `1.0`, `SUBAGENT_API_VERSION 1.0`.
- Negotiation failures: use `is_protocol_supported` / intersect-and-pick-latest
  / abort-on-empty `Supported`; never assume or silently fall back
  `Supported`.
- `evaluate_compat` UNKNOWN (unknown host, non-semver host version,
  non-date protocol) quarantines via `assert_usable`; unsupported protocol is
  INCOMPATIBLE `Supported`. All vendor interop remains `Not-tested` (vendor
  entries) except binary-presence `Environment-tested` for
  opencode/pi/hermes/jan and nothing for anythingllm; the stdio baseline is
  `Contract-tested`; HTTP/SSE and vendor quirks are `Known-limitation`.
