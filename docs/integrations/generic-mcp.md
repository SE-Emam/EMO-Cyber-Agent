# Generic MCP integration (tested baseline)

Labels: `Supported` in-repo code · `Contract-tested` in-repo contract tests ·
`Environment-tested` live observation · `Not-tested` claimed, not demonstrated
· `Known-limitation` explicit scope boundary. No screenshots, host versions, or
vendor install flows stated.

Compat: **Contract-tested** `Contract-tested` — the only matrix entry with
test evidence (`compat_matrix.HOST_MATRIX["generic-mcp"]`,
`support_evidence`: "Exercised by in-repo contract tests
(`tests/unit/subagent/test_contracts.py`, `test_mcp_security.py`) over the
stdio transport"). Per-vendor quirks are explicitly not covered by this entry
`Known-limitation`.

## Install

- Python `>=3.11` `Supported` (`bootstrap.PYTHON_VERSION_WINDOW`).
- Package installed with `cyber-agent` on `PATH` `Supported` (bootstrap
  `package-installed`, required). Generic-MCP needs no vendor binary beyond an
  MCP-capable stdio client `Supported` as scope statement; any specific client
  choice is `Not-tested`.

## Configure

- Registration shape (same stdio data-shape as the per-host adapters)
  `Supported`:
  ```json
  {"mcpServers": {"emo-cyber-agent": {"command": "cyber-agent", "args": ["mcp"]}}}
  ```
  Key `emo-cyber-agent`, command `cyber-agent`, args `["mcp"]` are `Supported`
  (adapter constants + `discovery.SERVER_NAME`).
- Tool table from `discovery` (advertised via `build_advertisement()`)
  `Supported`: `cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report`,
  `cyber_status` (`safe_default=True`), `cyber_extensions`,
  `cyber_threat_intel` (`safe_default=False`, advertised in the full set
  but withheld from per-task default subsets). `list_tools()` order is
  stable `Supported`.
- Per-task subset: only `security-review` is defined in
  `TASK_TOOL_SUBSETS` (the 5 safe tools) `Supported`; `tools_for_task()`
  rejects unknown kinds `Supported`. `build_advertisement(task_kind, only)`
  narrows only, never widens; empty selection raises `Supported`.
- Tool naming `kebab-case`, session `server-managed`, transports `("stdio",)`
  `Supported` (`HOST_MATRIX["generic-mcp"]`).

## Start

- `cyber-agent mcp` starts the server over stdio `Supported`
  (`cli/main.py:mcp()` → `run_stdio()`).
- Lifecycle covered by the baseline `Contract-tested`: `initialize →
  notifications/initialized → tools/list → tools/call (+ ping)`; one JSON
  object per line, logs on stderr `Contract-tested` (matrix `lifecycle_notes`
  for `generic-mcp`).
- HTTP/SSE transports are out of scope for this baseline `Known-limitation`.

## Doctor

- `cyber-agent doctor` / `--format json`, presence-only output `Supported`.
  Checks: `package`, `python`, `core`, `schemas`, `tool_registry`,
  `tool:<semgrep|trivy|osv-scanner|gitleaks|git>`, `github_config`,
  `supabase_config`, `mcp_available`, `provider` `Supported`.
- `health.check_subagent` / `for_doctor` (precedence `BLOCKED > UNAVAILABLE >
  DEGRADED > READY`; `READY` = technically available only) `Supported`.
- `bootstrap.bootstrap_profile` / `evaluate` (required: `python-version`,
  `package-installed`, `core-importable`, `policy-present`,
  `resources-present`; optional: `mcp-adapter-present`,
  `progress-recovery-present`, `config-present`; verdicts
  `READY/DEGRADED/BLOCKED` from caller evidence, never probes) `Supported`.

## Delegate

- `DelegationPipeline.evaluate(envelope, context, now, audit_id, project_id,
  snapshot_id)` gate `Supported` (see delegation.md for stages and
  fail-closed rules). Over generic MCP the delegation travels as `tools/call`
  arguments after `tools/list` discovery `Contract-tested` as transport only;
  policy semantics remain server-side `Supported`.
- `delegation_target()`: first `scope.included`, else first asset, else task
  text or host id `Supported`. Read-only profile `read_only` is used for the
  engine check `Supported`.

## Read Progress

- `progress_bridge` vocabulary/mapping/advisory-only contract `Supported`
  (see delegation.md). Emission reuses `ProgressState.advance` and optional
  `ProgressReporter.report`; no second event system `Supported`.
- Terminal rule: `COMPLETED` always `percent == 100.0` with
  `completed == total`; `FAILED`/`CANCELLED` (and `QUARANTINED`-as-`FAILED`)
  preserve terminal status `Supported`.

## Read Results

- `AuditHandoff` / `ResultEnvelope` refs-only contract `Supported` (see
  delegation.md). `cyber-agent report --findings <file> --audit-id <id>
  --format json|jsonl|markdown` projection `Supported`. `complete` gated on
  non-empty `verification_refs` `Supported`.

## Troubleshoot

Generic baseline issues only (all from in-repo contracts, `Supported` unless
noted):

| symptom | fix |
|---|---|
| `initialize` fails / unsupported protocol version | Intersect offered versions with `discovery.PROTOCOL_VERSIONS` (`2024-11-05, 2025-03-26, 2025-06-18`); use latest common; abort on none (`negotiate_protocol_version` pattern) `Supported`. |
| `tools/list` shows unexpected set | Compare with `build_advertisement()` / `KNOWN_TOOL_NAMES`; apply `only` narrowing or task subset; `cyber_extensions` and `cyber_threat_intel` are opt-in `Supported`. |
| Empty tool filter selection | `build_advertisement(only=...)` raises on empty set; widen the allow-list within the task subset `Supported`. |
| Unknown task kind | `tools_for_task` raises (`COMPAT_UNKNOWN`); use `security-review` or full set `Supported`. |
| Vendor-specific quirk (naming, HTTP wrapping, approval UI) | Out of scope for this baseline; see the per-host doc, all `Not-tested` `Known-limitation`. |

## Security Notes

- Delegation metadata never authority; narrowing-only grant; hostile-payload
  deny/quarantine; secret-marker quarantine; binding/scope-mismatch
  quarantine `Supported` (see security-model.md).
- `detail` / `note` / reference fields reject secret markers `Supported`
  (`health.ComponentReport`, `handoff` validators).
- Capability computation is server-side (`EffectiveCapabilitySet.compute(...
  server=True)` in the pipeline) `Supported`; host filtering never widens EMO
  enforcement `Supported` as architecture statement.

## Version Compatibility

- Server advertisement `emo-cyber-agent 0.1.0`, protocols `2024-11-05,
  2025-03-26, 2025-06-18`, surface `1.0` `Supported`.
- Matrix `generic-mcp`: protocol window = first/last server versions; no host
  version bounds `Supported`. `evaluate_compat` pure/deterministic rules
  (UNKNOWN quarantines; INCOMPATIBLE on unsupported protocol; otherwise
  host-window + status note) `Supported`.
- No host version is pinned for the baseline `Supported` (empty bounds by
  design); client protocol support is decided by explicit negotiation, never
  assumption `Supported`.
