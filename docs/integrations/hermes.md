# Hermes integration

Labels: `Supported` in-repo code · `Contract-tested` in-repo contract tests ·
`Environment-tested` live observation · `Not-tested` claimed, not demonstrated
· `Known-limitation` explicit scope boundary. No screenshots, host versions, or
vendor install flows stated.

Compat: **Not-tested** `Not-tested` (`compat_matrix.HOST_MATRIX["hermes"]`).
Exception: host binary presence via `--version` is `Environment-tested`
(presence only; no value pinned, no behavior verified).

## Install

- Python `>=3.11` `Supported` (`bootstrap.PYTHON_VERSION_WINDOW`).
- Package installed with `cyber-agent` on `PATH` `Supported` (bootstrap
  `package-installed`, required). No Hermes-vendor install stated `Not-tested`.
- Presence only (`--version` exits) `Environment-tested` (presence only).

## Configure

- Snippets from `hosts_hermes` (data only) `Supported`:
  - stdio `get_stdio_config()`: `{"mcpServers": {"emo-cyber-agent":
    {"command": "cyber-agent", "args": ["mcp"]}}}` (camelCase input form).
    Live persistence note: Hermes `v0.21.4` persists the same entry under
    snake_case `mcp_servers` in     `config.yaml` `Environment-tested` (evidence:
    `docs/evidence/POST-T021-final-review.md` §§2, 8; see
    `HERMES_PERSISTED_CONFIG_KEY_NOTE`).
  - HTTP `get_http_config()`: `{"mcpServers": {"emo-cyber-agent":
    {"url": "http://localhost:8000/mcp", "transport": "streamable-http"}}}`;
    the URL is a placeholder — the server must be started separately with an
    HTTP transport `Supported` (module comment).
  - `get_registration_config(transport)` with `stdio|streamable-http`; unknown
    raises `ValueError` `Supported`.
- `MCP_SERVER_KEY="emo-cyber-agent"`, `TOOL_NAMING="kebab-case"`,
  `SESSION_BEHAVIOR="server-managed"` `Supported`; live Hermes honor
  `Not-tested`. Names pass through as-is under the Hermes tool namespace
  `Supported` (`HERMES_TOOL_NAMESPACE_NOTE`, identity mapping).
- Default exposure 5 safe tools; `cyber_extensions` and `cyber_threat_intel`
  opt-in, excluded from every recommended allowlist `Supported`
  (`SAFE_DEFAULT_TOOLS`, `OPT_IN_TOOLS`).
- Per-task allowlists (`get_task_allowlist`, `get_per_task_allowlists`)
  `Supported`: `security-review`→5 safe tools; `verify-only`→
  `cyber_verify, cyber_status`; `report-only`→`cyber_report, cyber_status`;
  `status-only`→`cyber_status`. Unknown/empty task raises `ValueError`, never
  falls back to the full set `Supported`.
- Filtering guidance: register one Hermes server per task, apply the
  task allowlist via host-side filtering, confirm with `tools/list`
  `Supported` (`FILTERING_GUIDANCE` as adapter guidance); observed Hermes
  behavior `Not-tested`.
- Discovery note: after registering, list tools and compare against
  `discovery.KNOWN_TOOL_NAMES` filtered by the task allowlist; anything
  outside stays hidden; re-run discovery after exposure changes `Supported`
  (`SERVER_DISCOVERY_NOTE` guidance); live result `Not-tested`.

## Start

- stdio: `cyber-agent mcp` `Supported`. HTTP: serve EMO over HTTP first, then
  use the HTTP snippet; the HTTP serve command itself is not defined in the
  adapter `Not-tested` (not invented here).
- Assumed lifecycle `initialize → notifications/initialized → tools/list →
  tools/call` `Not-tested` (matrix note).
- Transports: matrix records `("stdio",)` `Supported`; adapter declares
  `("stdio", "streamable-http")` `Supported`. Both interops `Not-tested`.

## Doctor

- `cyber-agent doctor` / `--format json`, presence-only output `Supported`
  (same CLI source as opencode.md). `health.*` / `bootstrap.*` semantics
  `Supported`; Hermes-side surfacing `Not-tested`.

## Delegate

- Server gate (`DelegationPipeline.evaluate`, narrowing-only, fail-closed)
  `Supported` (see opencode.md). Hermes path `Not-tested`.
- Route each task to the smallest sufficient subset; unknown/unscoped tasks
  abort, never use the full set `Supported` as adapter guidance; live routing
  `Not-tested`. `negotiate_protocol_version` latest-common-or-abort
  `Supported`; against live Hermes `Not-tested`.

## Read Progress

- `progress_bridge` vocabulary, mapping table, advisory-only contract
  `Supported` (see opencode.md). Hermes rendering `Not-tested`.

## Read Results

- `AuditHandoff` / `ResultEnvelope` refs-only + `cyber-agent report`
  projection + `complete` gated on `verification_refs` `Supported` (see
  opencode.md). Hermes display `Not-tested`.

## Troubleshoot

From `hosts_hermes.TROUBLESHOOTING` (data only; behavior `Not-tested`):

| issue | symptom | fix |
|---|---|---|
| `server-not-found` | Hermes reports server missing / start fails. | Verify `cyber-agent` on `PATH` (`cyber-agent --help`); check stdio snippet from `get_stdio_config()`. |
| `tool-not-visible` | `cyber_*` missing or `cyber_extensions` unexpected. | Default is 5 safe tools, opt-in for extensions and threat-intel; re-list via `tools/list`. |
| `over-exposed-tools` | More tools visible than the task needs. | Apply `get_task_allowlist(task)` via host-side filtering; never expose all by default; re-list. |
| `protocol-version-mismatch` | `initialize` fails / unsupported version. | `negotiate_protocol_version()`; latest common or abort. |
| `http-connection-refused` | HTTP URL unreachable. | Confirm server serves HTTP at the registered URL; reload Hermes. |
| `discovery-mismatch` | Host list ≠ `build_advertisement()` filtered by allowlist. | Re-run discovery (`initialize → tools/list`), compare with `KNOWN_TOOL_NAMES` + allowlist, tighten filtering. |

- Known limit `Known-limitation`: no live-host verification; interop claimed,
  not demonstrated.

## Security Notes

- Core invariants (metadata never authority, `READY` ≠ trusted, progress
  advisory-only, trust-boundary depth 3 + narrowing + quarantine on
  cross-boundary) `Supported`; Hermes-path enforcement `Not-tested`.
- Never expose all tools by default; `cyber_extensions` and
  `cyber_threat_intel` stay excluded unless explicitly opted in via config
  edit + reload + re-list `Supported` (adapter guidance).

## Version Compatibility

- Server advertisement `emo-cyber-agent 0.1.0`, protocols `2024-11-05,
  2025-03-26, 2025-06-18`, surface `1.0` `Supported` (`discovery.py`).
- Matrix `hermes`: protocol window = first/last server versions; no host
  version bounds `Supported`. `evaluate_compat` pure/deterministic semantics
  as in opencode.md `Supported`.
- No Hermes version pinned or asserted compatible `Not-tested`; only binary
  presence `Environment-tested` (presence only). Live observation (not a
  compat assertion): Hermes `v0.21.4` observed `Environment-tested` (evidence:
  `docs/evidence/POST-T021-final-review.md` §§2, 8 — stdio registration,
  6/6 tool discovery, per-server filtering proven at the CLI layer).
