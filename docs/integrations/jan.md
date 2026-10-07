# Jan integration

Labels: `Supported` in-repo code · `Contract-tested` in-repo contract tests ·
`Environment-tested` live observation · `Not-tested` claimed, not demonstrated
· `Known-limitation` explicit scope boundary. No screenshots, host versions, or
vendor install flows stated.

Compat: **Not-tested** `Not-tested` (`compat_matrix.HOST_MATRIX["jan"]`).
Exception: host binary presence via `--version` is `Environment-tested`
(presence only; no value pinned, no behavior verified).

## Install

- Python `>=3.11` `Supported`. Package installed with `cyber-agent` on `PATH`
  `Supported` (bootstrap required checks). No Jan-vendor install stated
  `Not-tested`. Presence only (`--version`) `Environment-tested` (presence).

## Configure

- Shared snippet valid in both Jan Desktop and Jan Agent/CLI; register once
  per surface `Supported` (`SHARED_CONFIG_NOTE`, `hosts_jan.py`).
  - stdio (`get_shared_config_stdio()` / `get_desktop_config_stdio()` /
    `get_agent_config_stdio()` / `get_stdio_config()`): `{"mcpServers":
    {"emo-cyber-agent": {"command": "cyber-agent", "args": ["mcp"]}}}`
    `Supported`.
  - HTTP (`get_shared_config_http()` and Desktop/Agent aliases):
    `{"mcpServers": {"emo-cyber-agent": {"url":
    "http://localhost:8000/mcp", "transport": "streamable-http"}}}`;
    placeholder URL, server must be started separately with HTTP transport
    `Supported`.
  - `get_registration_config(surface, transport)`: `surface` ∈
    `desktop|agent|agent-cli|cli|shared`, `transport` ∈ `stdio|streamable-http`
    (`http` alias accepted); Desktop and Agent/CLI share content; unknown
    raises `ValueError` `Supported`.
- Default 5 safe tools; `cyber_extensions` and `cyber_threat_intel` opt-in
  and filtered out by default `Supported`. Identity pass-through under Jan's
  tool namespace `Supported` (`JAN_TOOL_NAMESPACE_NOTE`). Live Jan display
  `Not-tested`.
- Tool permissions (host-side metadata only): grant each `cyber_*` tool the
  minimum the task needs; keep `cyber_extensions` and `cyber_threat_intel`
  denied unless opted in;
  Jan-side grants never widen EMO enforcement `Supported`
  (`TOOL_PERMISSION_NOTE` guidance); live effect `Not-tested`.
- Tool filtering: expose only the task's subset via host-side filtering,
  confirm with `tools/list` `Supported` (`TOOL_FILTERING_NOTE`); live result
  `Not-tested`.
- Tool routing: smallest sufficient subset (e.g. status-only→`cyber_status`;
  verify→`cyber_verify`+`cyber_status`; full review→5 safe tools);
  unknown/unscoped tasks abort, never full set; re-run discovery after changes
  `Supported` (`TOOL_ROUTING_NOTE` guidance); live routing `Not-tested`.
- Approval-UI boundary: Jan approval prompts/allowlists/click-throughs do
  NOT substitute for EMO enforcement; EMO applies its own trust boundary,
  tool filter, and capability checks regardless `Supported`
  (`APPROVAL_UI_BOUNDARY_NOTE`); live Jan UI behavior `Not-tested`.

## Start

- stdio: `cyber-agent mcp` `Supported`. HTTP: serve EMO over HTTP first; the
  HTTP serve command is not defined in the adapter `Not-tested` (not invented).
- Reload the surface after registration/exposure change, then re-list tools
  `Supported` (adapter guidance); observed Jan behavior `Not-tested`.
- Assumed lifecycle `initialize → notifications/initialized → tools/list →
  tools/call` `Not-tested`. Matrix `("stdio",)` vs adapter `("stdio",
  "streamable-http")` both `Supported` as code facts; both interops
  `Not-tested`.

## Doctor

- `cyber-agent doctor` / `--format json`, presence-only `Supported` (same CLI
  source as opencode.md). `health.*` / `bootstrap.*` `Supported`; Jan-side
  surfacing `Not-tested`.

## Delegate

- Server gate (`DelegationPipeline.evaluate`, narrowing-only, fail-closed)
  `Supported` (see opencode.md). Jan path `Not-tested`. Explicit version
  negotiation (latest common or abort) `Supported`; against live Jan
  `Not-tested`.

## Read Progress

- `progress_bridge` vocabulary/mapping/advisory-only `Supported` (see
  opencode.md). Jan rendering `Not-tested`.

## Read Results

- `AuditHandoff` / `ResultEnvelope` refs-only + `cyber-agent report`
  projection + `complete` gated on `verification_refs` `Supported`. Jan
  display `Not-tested`. Verify Jan outcomes via EMO evidence, not the host
  prompt state `Supported` (adapter troubleshooting guidance).

## Troubleshoot

From `hosts_jan.TROUBLESHOOTING` (data only; behavior `Not-tested`):

| issue | symptom | fix |
|---|---|---|
| `server-not-found` | Jan reports server missing / start fails. | Verify `cyber-agent` on `PATH` (`cyber-agent --help`); check shared stdio snippet. |
| `shared-config-not-visible` | Works in Desktop but not Agent/CLI or vice versa. | Registration is per surface though the snippet is shared; apply in both configs, reload each, re-list. |
| `tool-not-visible` | `cyber_*` missing or extensions unexpected. | Default 5 safe tools, opt-in for extensions and threat-intel; re-list via `tools/list`. |
| `over-permissioned-tools` | Broader grants than needed. | Tighten to smallest subset per permission/filtering notes; re-list. |
| `approval-ui-confusion` | Operator assumes EMO follows a Jan approval prompt. | Approval UI is NOT the EMO boundary; verify via EMO evidence. |
| `protocol-version-mismatch` | `initialize` fails / unsupported version. | `negotiate_protocol_version()`; latest common or abort. |
| `http-connection-refused` | HTTP URL unreachable. | Confirm server serves HTTP at the registered URL; reload Jan. |

- Known limit `Known-limitation`: no live-host verification; claimed, not
  demonstrated.

## Security Notes

- Core invariants as in opencode.md `Supported`; Jan-path enforcement
  `Not-tested`. Additionally: Jan-side permission grants and approval UI never
  widen or substitute for EMO enforcement `Supported` (adapter notes).

## Version Compatibility

- Server advertisement `emo-cyber-agent 0.1.0`, protocols `2024-11-05,
  2025-03-26, 2025-06-18`, surface `1.0` `Supported`. Matrix `jan`: protocol
  window = first/last server versions; no host bounds `Supported`.
  `evaluate_compat` semantics as in opencode.md `Supported`.
- No Jan version pinned or asserted compatible `Not-tested`; only binary
  presence `Environment-tested` (presence only).
