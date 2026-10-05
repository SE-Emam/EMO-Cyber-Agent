# Pi integration

Honesty labels on every claim: `Supported` = in-repo code · `Contract-tested` =
in-repo contract tests · `Environment-tested` = live-environment observation ·
`Not-tested` = claimed, not demonstrated · `Known-limitation` = explicit scope
boundary. No screenshots, no host version numbers, no vendor install flows.

Compat status: **Not-tested** `Not-tested` — source
`compat_matrix.HOST_MATRIX["pi"]` ("No contract or environment test names this
host"). Exception: host binary presence via `--version` is `Environment-tested`
(presence only; no version value pinned, no behavior verified). Note the matrix
key `pi` maps to decision id `pi-host` (`DECISION_HOST_IDS`) because
`hosts.py` ids require ≥3 chars `Supported`.

## Install

- EMO requires Python `>=3.11` `Supported` (`bootstrap.PYTHON_VERSION_WINDOW`).
- Install the package so `cyber-agent` is on `PATH` `Supported` (bootstrap
  `package-installed`, required). No Pi-vendor install command stated
  `Not-tested`.
- Presence only: `<host> --version` success proves presence, nothing else
  `Environment-tested` (presence only).

## Configure

- Registration snippets are data-only helpers `Supported` — source
  `src/emo_cyber_agent/subagent/hosts_pi.py`:
  - `get_user_config_stdio()` / `get_project_config_stdio()` return
    `{"mcpServers": {"emo-cyber-agent": {"command": "cyber-agent", "args": ["mcp"]}}}`.
  - `get_user_config_http()` / `get_project_config_http()` return
    `{"mcpServers": {"emo-cyber-agent": {"url": "http://localhost:8000/mcp", "transport": "streamable-http"}}}` where the URL is a placeholder (server must be started separately with an HTTP transport) `Supported` (module comment).
  - `get_registration_config(scope, transport)`: `scope` ∈ `user|project`,
    `transport` ∈ `stdio|streamable-http`; unknown values raise `ValueError`,
    no silent fallback `Supported`.
- Project-scope note: servers registered in project config stay scoped to
  that project and do not leak into others; user config is global; prefer
  project config for project-bound audits `Supported` (`PROJECT_SCOPE_NOTE`).
  Live Pi enforcement is `Not-tested`.
- Reload note: after registering or editing config, reload the Pi session so
  the new server/tool list takes effect `Supported` (`RELOAD_NOTE` as adapter
  guidance). Observed effect is `Not-tested`.
- Exposure-change note: opting `cyber_extensions` in/out requires config edit
  + Pi reload + re-list; default is the 5 safe tools only `Supported`
  (`EXPOSURE_CHANGE_NOTE`). Observed effect is `Not-tested`.
- Tool naming `kebab-case`, session `server-managed` `Supported`; honored by
  Pi in practice `Not-tested`. Server names pass through as-is under Pi's own
  tool namespace `Supported` (`PI_TOOL_NAMESPACE_NOTE`, identity
  `TOOL_NAME_MAPPING`).

## Start

- stdio: `cyber-agent mcp` `Supported` (`cli/main.py:mcp()` → `run_stdio()`).
- HTTP variant: start an EMO server with an HTTP transport first, then use
  the `streamable-http` snippet `Supported` as adapter data-shape only; the
  actual serve command for HTTP is not defined in the adapter `Not-tested`
  (do not invent one).
- Assumed lifecycle `initialize → notifications/initialized → tools/list →
  tools/call` `Not-tested` (matrix `lifecycle_notes`).
- Transports discrepancy stated honestly: matrix entry records `("stdio",)`
  `Supported`, while the adapter module declares
  `TRANSPORTS=("stdio", "streamable-http")` `Supported`. stdio interop and
  HTTP interop are both `Not-tested`.

## Doctor

- `cyber-agent doctor` / `cyber-agent doctor --format json` `Supported` (see
  opencode.md Doctor for the check list; same CLI source). Prints presence
  only, never secrets `Supported`.
- `health.check_subagent` / `for_doctor` aggregation and
  `bootstrap.bootstrap_profile` / `evaluate` checklist are `Supported` (same
  semantics as opencode.md). Pi-side surfacing is `Not-tested`.

## Delegate

- Same server-side gate as opencode.md (`DelegationPipeline.evaluate`,
  narrowing-only grant, fail-closed screens) `Supported`. Pi-side delegation
  UX is `Not-tested`.
- Protocol negotiation: intersect host-offered versions with
  `discovery.PROTOCOL_VERSIONS`, take latest common, abort on empty
  (`negotiate_protocol_version` / `is_protocol_supported`) `Supported`.
  Negotiation against a live Pi host is `Not-tested`.

## Read Progress

- Same `progress_bridge` vocabulary, lifecycle→phase table, and
  advisory-only contract as opencode.md `Supported`. Rendering inside Pi is
  `Not-tested`.

## Read Results

- Same `AuditHandoff` / `ResultEnvelope` refs-only contract and
  `cyber-agent report` projection as opencode.md `Supported`. Display inside
  Pi is `Not-tested`. `complete` stays gated on `verification_refs`
  `Supported`.

## Troubleshoot

From `hosts_pi.TROUBLESHOOTING` (data only; behavior `Not-tested`):

| issue | symptom | fix |
|---|---|---|
| `server-not-found` | Pi reports the server missing / command fails to start. | Verify `cyber-agent` on `PATH` (`cyber-agent --help`); check the `mcpServers` snippet. |
| `project-scoped-server-not-visible` | Works in one project, absent in another. | Expected for project-config registration; use user config for global use or repeat per-project registration. |
| `reload-required` | Old server/tool list after config edit. | Reload the Pi session, then re-list via `tools/list`. |
| `tool-not-visible` | `cyber_*` missing or `cyber_extensions` unexpected. | Default is 5 safe tools; `cyber_extensions` opt-in; re-list via `tools/list`. |
| `protocol-version-mismatch` | `initialize` fails / unsupported version. | Re-run `negotiate_protocol_version()`; abort if no overlap. |
| `http-connection-refused` | Streamable HTTP URL unreachable. | Confirm the server is serving HTTP at the registered URL and Pi was reloaded. |

- Known limit `Known-limitation`: "No live-host verification performed;
  interoperability is claimed, not demonstrated."

## Security Notes

- Same core invariants as opencode.md (metadata never authority,
  `READY` ≠ trusted, progress never drives security, trust-boundary gate
  `MAX_DELEGATION_DEPTH=3` with narrowing-only scope) `Supported`; Pi-path
  enforcement `Not-tested`.
- Capability map is metadata only (`cyber_audit/review→repo.read,
  codeintel.read, evidence.read`; `cyber_verify→verification.safe,
  evidence.read`; `cyber_report→report.generate, evidence.read`;
  `cyber_status→()`; `cyber_extensions→evidence.read`) `Supported`.

## Version Compatibility

- Same server advertisement (`emo-cyber-agent 0.1.0`,
  `2024-11-05, 2025-03-26, 2025-06-18`, surface `1.0`) `Supported`.
- Matrix `pi`: protocol window = first/last server versions; no host version
  bounds `Supported`. `evaluate_compat` semantics as in opencode.md
  `Supported`, with the alias note `pi` → `pi-host` appended to reasons
  `Supported`.
- No Pi version pinned or asserted compatible `Not-tested`; only binary
  presence observed `Environment-tested` (presence only).
