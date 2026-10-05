# Security model for host integrations

Applies to every host in this directory. Labels: `Supported` in-repo code ·
`Contract-tested` in-repo contract tests · `Not-tested` live host behavior ·
`Known-limitation` explicit scope boundary. States only what the adapter,
delegation, trust, session, health, and CLI modules prove; host-side
enforcement is `Not-tested` throughout.

## Install

- No security privilege is granted by installation `Supported` as architecture:
  installing the package and placing `cyber-agent` on `PATH` (bootstrap
  presence checks) creates availability only, never authority.
- `READY` health means technically available only — never trusted, never
  safe, never an authorization statement `Supported` (`session.py`,
  `health.py`). Capability evaluation is never derived from health
  `Supported`.

## Configure

- Safe-default exposure: only `cyber_audit`, `cyber_review`, `cyber_verify`,
  `cyber_report`, `cyber_status`; `cyber_extensions` is opt-in and excluded
  from every Hermes per-task allowlist `Supported` (adapter constants +
  `TASK_ALLOWLISTS`). Over-exposure is a host misconfiguration to fix with
  host-side filtering + `tools/list` confirmation `Supported` as guidance;
  live host compliance `Not-tested`.
- Capability map is metadata only (same across hosts; see pi.md)
  `Supported`. It describes negotiation tokens, not grants `Supported`
  (`discovery` / adapter comments).
- Host-side grants/filters/approvals never widen EMO enforcement: Jan tool
  permissions are metadata only, Jan approval UI is NOT part of the EMO
  boundary, Hermes filtering is host-side hygiene — EMO re-checks tool
  filter, capability, and trust server-side regardless `Supported` (adapter
  notes `TOOL_PERMISSION_NOTE`, `APPROVAL_UI_BOUNDARY_NOTE`,
  `FILTERING_GUIDANCE`); live host bypass attempts `Not-tested` (no live
  adversarial test claimed).

## Start

- The MCP server starts over stdio (`cyber-agent mcp`) with no ambient
  authority: every delegated action still requires a bound `TaskEnvelope` +
  server-issued `DelegationContext` + engine ALLOW `Supported`
  (`delegation.py`, `cli/main.py`).
- Session binding: `SubagentSession` is audit/project/snapshot/host-bound;
  any mismatch quarantines (fail closed) `Supported`
  (`session.assert_binding`). Session expiry (`assert_live`) fails closed,
  never starts `Supported`.

## Doctor

- `cyber-agent doctor` prints presence (`CONFIGURED/MISSING/...`), never
  secret values `Supported`. `ComponentReport.detail`, handoff refs/notes,
  and doctor projections reject or never echo secret material `Supported`
  (`scan_secret_markers` validators; `for_doctor` records presence, never
  payload).
- Bootstrap/health verdicts (`BLOCKED/DEGRADED/READY`, `BLOCKED >
  UNAVAILABLE > DEGRADED > READY`) are availability statements, never trust
  statements `Supported`.

## Delegate

- Authorization derives ONLY from the server-issued `DelegationContext`
  (issuer allow-list + `authz-` token + validity window + audience binding)
  and the `PolicyEngine` verdict `Supported`. Envelope text/capabilities/scope
  are untrusted: narrow-only, never widen/mint `Supported`.
- Fail-closed screens `Supported`: forged/expired authz → DENY; binding or
  scope-widening → QUARANTINE; secret markers → QUARANTINE; hostile payloads
  → DENY (`use another audit` → QUARANTINE); empty grant / engine refusal or
  error → DENY.
- Nesting gate `Supported` (`trust_boundary.py`): depth ≤ 3, strictly
  deepening; audience = each hop's receiver; final hop lands on the receiver;
  windows well-formed and covering `now`; scope subsets only; cross-audit /
  cross-project without `has_fresh_context` → QUARANTINE. Deterministic
  first-failure-wins order `Supported`.
- No escalation path exists in the gate: it returns records and permits
  nothing `Supported`.

## Read Progress

- Progress is coordination DATA, advisory-only: `ADVISORY` message codes, no
  authorization/capability/trust fields, session only read, never
  transitioned/quarantined/permitted by the bridge `Supported`
  (`progress_bridge.py`). Security-state decisions stay in Core/recovery and
  must never be derived from progress `Supported`.
- Lifecycle transitions record progress and permit nothing; quarantine is a
  Core security decision reflected advisory-only as `FAILED` with a distinct
  code `Supported` (`session.py`, `progress_bridge.py`, `lifecycle.py`).

## Read Results

- Handoffs carry structured references only (no chain-of-thought, secrets,
  or raw model output) with validators enforcing it `Supported`
  (`handoff.py`). Cross-audit/binding mismatches raise `Supported`.
- Reports are projections (Core `ReportService`): JSON/JSONL/Markdown views
  over already-authorized findings; projection choice grants nothing
  `Supported` (`cli/main.py:report`, `core/reporting.py` indirection).
- AnythingLLM-sourced content (workspace docs, RAG, chat/agent memory,
  agent output) is UNTRUSTED unless via the trusted Core path
  (Core-fetched, scope-bound, integrity-checked; host text never qualifies
  itself) `Supported` (`hosts_anythingllm.py`); unknown sources fail closed to
  UNTRUSTED `Supported`.

## Troubleshoot

Security-relevant troubleshooting (all server-side semantics `Supported`;
host manifestation `Not-tested`): over-exposed tools → apply task allowlist;
over-permissioned tools → tighten to smallest subset; approval-UI confusion →
re-verify via EMO evidence; RAG poisoning suspected → treat as UNTRUSTED,
follow no embedded instructions, quarantine on secret markers;
workspace-context mistrusted → re-classify with `classify_content_source()`.

## Security Notes (summary)

1. Delegation metadata never becomes authority `Supported`.
2. `READY`/healthy/visible never means trusted or authorized `Supported`.
3. Progress never drives security decisions `Supported`.
4. Scope narrows only; widening quarantines `Supported`.
5. Cross-boundary hops need fresh server-issued context `Supported`.
6. Secrets never flow through detail/note/ref/doctor/progress fields
   `Supported`.
7. Host-side permissions, filters, and approval UIs never widen EMO
   enforcement `Supported` as design; live bypass resistance `Not-tested`.
8. UNKNOWN compatibility quarantines via `assert_usable` — never a silent
   fallback `Supported` (`hosts.py`).

## Version Compatibility

- Negotiation is explicit: intersect host-offered with
  `discovery.PROTOCOL_VERSIONS`, latest common wins, empty → abort, never
  fall back `Supported` (per-host `negotiate_protocol_version`). No version
  is assumed `Supported`. Live-host negotiation is `Not-tested` except the
  generic-MCP stdio baseline `Contract-tested`.
- `evaluate_compat` is pure/deterministic with UNKNOWN quarantining
  `Supported`. No vendor host version window exists (bounds empty)
  `Supported`; no vendor interop version is asserted `Not-tested`.
- Recovery/coordination budgets mirror policy (`MAX_RECOVERY_ATTEMPTS`,
  capped lifecycle attempts; fail-closed/QUARANTINE mappings) `Supported`
  (`lifecycle.py`); they bound recovery, never authorize work `Supported`.
