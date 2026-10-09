# OpenCode integration

Honesty labels used on every claim: `Supported` = implemented in this repo ·
`Contract-tested` = exercised by in-repo contract tests · `Environment-tested` =
observed in a live environment · `Not-tested` = claimed, not demonstrated ·
`Known-limitation` = explicitly out of scope. No screenshots, no host version
numbers, no host-vendor install flows are stated here.

Compat status for this host: **Not-tested** `Not-tested` —
source `src/emo_cyber_agent/subagent/compat_matrix.py` `HOST_MATRIX["opencode"]`
(`support_evidence`: "No contract or environment test names this host").
Single exception: host binary presence via `--version` is `Environment-tested`
(presence only; no version value pinned, no behavior verified).

## Install

- EMO requires Python `>=3.11` `Supported` — source
  `src/emo_cyber_agent/subagent/bootstrap.py` `PYTHON_VERSION_WINDOW`.
- Install the `emo-cyber-agent` package so `cyber-agent` is on `PATH`
  `Supported` — bootstrap checklist item `package-installed` (required,
  presence). No vendor-host install command is stated `Not-tested`.
- Host binary presence check only: running `<host> --version` succeeding
  proves presence, nothing else `Environment-tested` (presence only).

## Configure

- Registration snippet (data only, from `hosts_opencode.get_registration_config()`)
  `Supported`, live shape observed against opencode `1.18.34`
  `Environment-tested` (evidence:
  `docs/evidence/POST-T021-final-review.md` §§2, 8):
  ```json
  {"mcp": {"emo-cyber-agent": {"type": "local", "command": ["cyber-agent", "mcp"], "enabled": true}}}
  ```
  Legacy note: the pre-T020 `mcpServers` + `{command: str, args: []}` form
  is ignored by opencode `1.18.34` ("No MCP servers configured")
  `Environment-tested` (same report, control check) — do not use it.
- Constants: `MCP_SERVER_KEY="emo-cyber-agent"` `Supported`,
  `SERVER_COMMAND="cyber-agent"` `Supported`, `SERVER_ARGS=("mcp",)` `Supported`
  — source `src/emo_cyber_agent/subagent/hosts_opencode.py`.
- Tool naming is `kebab-case`, session behavior is `server-managed`
  `Supported` (adapter constants `TOOL_NAMING`, `SESSION_BEHAVIOR`).
  That OpenCode honors them in practice is `Not-tested`.
- Default exposure is exactly the 5 safe tools
  (`cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report`, `cyber_status`);
  `cyber_extensions` and `cyber_threat_intel` are opt-in `Supported`
  (`SAFE_DEFAULT_TOOLS`, `OPT_IN_TOOLS`). That OpenCode displays exactly
  this set is `Not-tested`.
- Server-side tool names pass through with an `emo-cyber-agent_<tool>`
  host prefix (e.g. `emo-cyber-agent_cyber_status`), observed against
  opencode `1.18.34` `Environment-tested` (evidence:
  `docs/evidence/POST-T021-final-review.md` §§2, 8); server-side `cyber_*`
  names are unchanged, the host adds the prefix at invocation `Supported`
  (`TOOL_NAME_MAPPING`, `OPENCODE_TOOL_NAMESPACE_NOTE`). End-to-end
  visibility beyond the observed `cyber_status` delegation is `Not-tested`.

## Start

- Start the server over stdio with `cyber-agent mcp` `Supported` — source
  `src/emo_cyber_agent/cli/main.py` `mcp()` → `mcp/server.py:run_stdio()`.
- MCP lifecycle assumed by the matrix entry: `initialize` →
  `notifications/initialized` → `tools/list` → `tools/call`
  `Not-tested` (`lifecycle_notes`: "Assumed ... not verified against a live host").
- Transports: compat matrix entry lists `("stdio",)` `Supported`
  (`HOST_MATRIX["opencode"].transports`); the adapter module likewise
  declares `TRANSPORTS=("stdio",)` `Supported`. Any other transport is
  `Known-limitation` for this host entry.

## Doctor

- Run `cyber-agent doctor` (human) or `cyber-agent doctor --format json`
  `Supported` — source `src/emo_cyber_agent/cli/main.py:doctor()`. It prints
  presence tokens (`OK` / `AVAILABLE` / `CONFIGURED` / `MISSING` /
  `UNAVAILABLE`), never secret values `Supported`.
- Doctor checks include `package`, `python`, `core`, `schemas`,
  `tool_registry`, `tool:<semgrep|trivy|osv-scanner|gitleaks|git>`,
  `github_config`, `supabase_config`, `mcp_available`, `provider` `Supported`.
- Subagent health aggregation (`health.check_subagent`, `health.for_doctor`)
  is `Supported` (precedence `BLOCKED > UNAVAILABLE > DEGRADED > READY`;
  `READY` means technically available only, never trusted) — source
  `src/emo_cyber_agent/subagent/health.py`. That OpenCode surfaces these
  checks is `Not-tested`.
- Bootstrap checklist (`bootstrap.bootstrap_profile`) is host-generic and
  `Supported`: required = `python-version`, `package-installed`,
  `core-importable`, `policy-present`, `resources-present`; optional =
  `mcp-adapter-present`, `progress-recovery-present`, `config-present`.
  Verdicts `READY / DEGRADED / BLOCKED` from caller-supplied evidence only
  (the module never probes) `Supported`. Live-host evaluation is `Not-tested`.

## Delegate

- Delegation is a server-side gate (`DelegationPipeline.evaluate`):
  typed `TaskEnvelope` + server-issued `DelegationContext` + `PolicyEngine`
  check; stages parse → normalize → validate → scope-bind → policy decision
  `Supported` — source `src/emo_cyber_agent/subagent/delegation.py`.
- Delegation metadata never becomes authority; the effective grant is always
  narrowed to `requested ∩ allowed − denied` and to within `outer_scope`
  `Supported`. Hostile-payload hits deny (cross-audit `use another audit`
  quarantines); secret markers quarantine; binding/scope mismatch quarantines
  `Supported`.
- The host path (OpenCode calling `tools/call cyber_audit/...` with a bound
  envelope) is `Not-tested`. Unknown task kinds abort, never silently fall
  back `Supported` (discovery `tools_for_task` raises on unknown kind).

## Read Progress

- Progress vocabulary (`progress_bridge.DELEGATION_PHASES`):
  `DELEGATED, INITIALIZING, COLLECTING, ANALYZING, VERIFYING, REPORTING,
  RECOVERING, COMPLETED, FAILED, CANCELLED` `Supported`.
- Lifecycle→phase mapping is fixed and advisory-only: `STARTING→DELEGATED`,
  `READY→INITIALIZING`, `RUNNING→COLLECTING` (coarse; `ANALYZING` reserved
  for finer emitters), `VERIFYING→VERIFYING`, `REPORTING→REPORTING`,
  `RECOVERING→RECOVERING`, `COMPLETED→COMPLETED` (always 100%,
  `completed == total`), `FAILED→FAILED`, `CANCELLED→CANCELLED`,
  `QUARANTINED→FAILED` (distinct `SUBAGENT_QUARANTINED_ADVISORY` code),
  `UNAVAILABLE→RECOVERING` `Supported` — source
  `src/emo_cyber_agent/subagent/progress_bridge.py`.
- Every event carries an `ADVISORY` message code, carries no authorization /
  capability / trust fields, and never transitions or quarantines the session
  `Supported`. That OpenCode renders these phases is `Not-tested`.

## Read Results

- Results arrive as `AuditHandoff` (audit/project/snapshot-bound; structured
  `finding_refs` / `evidence_refs` / `verification_refs`, `report_ref`,
  `limitations`, `recovery_state`, `provenance` chain) wrapped in a
  `ResultEnvelope` (`status` ∈ `completed|failed|cancelled|quarantined`)
  `Supported` — source `src/emo_cyber_agent/subagent/handoff.py`.
- References only: no chain-of-thought, no secrets, no raw model output
  `Supported` (validators reject secret markers / empty refs).
- Report rendering via `cyber-agent report --findings <file> --audit-id <id>
  --format json|jsonl|markdown` is `Supported` (Core `ReportService`
  projection only). That OpenCode displays handoff refs correctly is
  `Not-tested`.
- `complete` (REPORTING→COMPLETED) is gated on non-empty `verification_refs`;
  missing refs keep the session in REPORTING `Supported` — source
  `src/emo_cyber_agent/subagent/lifecycle.py:LifecycleCoordinator.complete`.

## Troubleshoot

From `hosts_opencode.TROUBLESHOOTING` (data only; host behavior `Not-tested`):

| issue | symptom | fix |
|---|---|---|
| `server-not-found` | OpenCode reports the `emo-cyber-agent` MCP server is missing or the command fails to start. | Verify `cyber-agent` is installed and on `PATH` (`cyber-agent --help`); check the `mcp` registration snippet from `get_registration_config()` (live shape for opencode `1.18.34`; the legacy `mcpServers` form registers zero servers). |
| `protocol-version-mismatch` | `initialize` fails or the host reports an unsupported protocol version. | Re-run explicit negotiation via `negotiate_protocol_version()`; use the latest common version from discovery output; abort if none exists. |
| `tool-not-visible` | `cyber_*` tools do not appear, or `cyber_extensions` is unexpectedly present/absent. | Confirm default exposure is the 5 safe tools only; `cyber_extensions` and `cyber_threat_intel` are opt-in. Check the host tool namespace view and re-list via `tools/list`. |

- Protocol helpers `is_protocol_supported()` / `negotiate_protocol_version()`
  test membership against live `discovery.PROTOCOL_VERSIONS` at call time
  (no hardcoded version) and return `None` on no overlap — caller must abort,
  never silently fall back `Supported`.
- Known limits for this host `Known-limitation`: "No live-host verification
  performed; interoperability is claimed, not demonstrated." / "Host-side
  tool-name mapping is unverified."

## Security Notes

- Envelope text/capabilities/scope are untrusted input: they narrow a grant,
  never widen or mint one `Supported` (`delegation.py` invariants).
- `READY` health never means trusted/safe/authorized `Supported`
  (`health.py`, `session.py` contracts).
- Progress events are coordination data only and must never drive
  security-state decisions `Supported` (`progress_bridge.py` contract).
- Trust-boundary gate: nested delegation depth-bounded at
  `MAX_DELEGATION_DEPTH=3`; audience must match each hop's receiver;
  validity window must cover `now`; scope may only narrow; cross-audit /
  cross-project hops without fresh server-issued context quarantine
  `Supported` — source `src/emo_cyber_agent/subagent/trust_boundary.py`.
  Enforcement of these checks on the OpenCode path is `Not-tested`.

## Version Compatibility

- Server advertisement (data): `server_name="emo-cyber-agent"`,
  `server_version="0.1.0"`, `protocol_versions=("2024-11-05", "2025-03-26",
  "2025-06-18")`, `surface_version="1.0"` `Supported` — source
  `src/emo_cyber_agent/subagent/discovery.py`.
- Matrix entry `opencode`: `protocol_min`/`protocol_max` equal the first/last
  server-supported versions; `host_version_min`/`host_version_max` are empty
  (no pinned host version window) `Supported`.
- `evaluate_compat(host_id, host_version, protocol_version)` is pure and
  deterministic: unknown host / non-semver host version / non-`YYYY-MM-DD`
  protocol → `UNKNOWN` (quarantines via `assert_usable`); unsupported
  protocol → `INCOMPATIBLE`; otherwise host-window check via
  `hosts.check_compatibility` plus a `Not-tested` provisional note
  `Supported`.
- Live observation (not a compat assertion): opencode `1.18.34` observed
  `Environment-tested` (evidence:
  `docs/evidence/POST-T021-final-review.md` §§2, 8 — real `mcp list` shows
  `emo-cyber-agent connected`, `cyber_status` delegated as
  `emo-cyber-agent_cyber_status`). No OpenCode version is asserted
  compatible here `Not-tested`. The only other environment observation is
  binary presence (`--version` exits), not any behavior
  `Environment-tested` (presence only).
