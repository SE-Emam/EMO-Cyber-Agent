# Delegation across hosts

Host-agnostic delegation contract. Labels: `Supported` in-repo code ·
`Contract-tested` in-repo contract tests · `Not-tested` live host behavior ·
`Known-limitation` explicit scope boundary. No host-specific UX, screenshots,
or versions stated; per-host rendering differences are `Not-tested`.

## Install

- Same EMO prerequisites as the host docs: Python `>=3.11`, installed package
  with `cyber-agent` on `PATH` `Supported` (`bootstrap.py`). No additional
  delegation dependency is declared in the pipeline module `Supported`.

## Configure

- Pipeline bounds are server-provided: `allowed_capabilities`,
  `denied_capabilities`, `outer_scope`, `policy_version` (semver, default
  `1.0.0`; non-semver raises) `Supported` (`DelegationPipeline.__init__`).
- Effective grant is always `requested ∩ allowed − denied` and within
  `outer_scope` (narrowing-only) `Supported` (`capabilities` +
  `delegation.py`).
- Discovery advertisement behind delegation: full seven-tool set by default;
  `task_kind="security-review"` selects the 5 safe tools; `only=[...]`
  narrows further (unknown tool rejected; empty result raises); both set =
  intersection `Supported` (`discovery.build_advertisement`).

## Start

- The server side starts with `cyber-agent mcp` (stdio) `Supported`. No
  separate delegation daemon exists `Supported` (the pipeline is a pure
  function call, no I/O/process/spawn) — the module "never spawns processes,
  never evaluates code, and never mutates the engine" `Supported` (module
  docstring).
- Lifecycle coordination (`LifecycleCoordinator.start`: `STARTING→READY`,
  requires non-empty `delegation_id` and a live session; scope summary is a
  data-only fingerprint) `Supported`. Host-side session start flows are
  `Not-tested`.

## Doctor

- Pre-delegation readiness uses the same `bootstrap` checklist and `doctor`
  presence checks as the host docs `Supported`. The pipeline itself adds no
  doctor surface `Supported` (no such function in `delegation.py`).
- `health.check_subagent` precedence and `for_doctor` projection `Supported`;
  host wiring `Not-tested`.

## Delegate

- `DelegationPipeline.evaluate(envelope, context, *, now, audit_id,
  project_id, snapshot_id)` stages `Supported`:
  1. parse — typed `TaskEnvelope` + `DelegationContext` only; anything else is
     fail-closed DENY `Supported`;
  2. normalize — NFKC → lowercase → whitespace-collapse via the shared
     sanitizer normalizer when importable (inline NFKC fallback otherwise)
     `Supported`;
  3. validate — `assert_authorization_independent` (authz ref must be
     independent of envelope text); secret markers → QUARANTINE;
     `context.assert_authorized_for` (expired → DENY, other authz failures →
     DENY) `Supported`;
  4. scope-bind — `envelope.assert_binding` mismatch → QUARANTINE;
     `assert_scope_within(outer_scope)` widening → QUARANTINE `Supported`;
  5. hostile screen — `scan_hostile` classes (`ignore policy`, `grant write`,
     `disable verification`, `hide finding`, `use another audit` →
     QUARANTINE, `fake approval`, `system message`, `role confusion`) deny
     with `hostile:<label>` reasons `Supported`;
  6. policy decision — server-computed `EffectiveCapabilitySet` (empty grant
     → DENY), then `PolicyEngine.evaluate_policy(audit, host,
     delegation_target, "read_only", effective)`; engine error or refusal →
     DENY; pass → ALLOW with `narrow-delegation-authorized` `Supported`.
- `evaluate_raw(data, context, ...)` parses then evaluates; parse failure →
  DENY `Supported`.
- Trust-boundary nesting (`trust_boundary.evaluate_edge` / `evaluate_chain`):
  depth ≤ 3, audience/recipient match, window covers `now`, scope narrows,
  cross-audit/project without fresh context → QUARANTINE `Supported`. Raising
  variants `assert_edge` / `assert_chain` raise `TrustBoundaryError`
  `Supported`.

## Read Progress

- Map session lifecycle to `DELEGATION_PHASES` via `progress_bridge.bridge`
  `Supported`. Table: `starting→DELEGATED`, `ready→INITIALIZING`,
  `running→COLLECTING`, `verifying→VERIFYING`, `reporting→REPORTING`,
  `recovering→RECOVERING`, `completed→COMPLETED` (100%),
  `failed→FAILED`, `cancelled→CANCELLED`, `quarantined→FAILED` (advisory),
  `unavailable→RECOVERING` `Supported`.
- Events are advisory-only (`*_ADVISORY` codes, no auth/capability/trust
  fields; session only read, never mutated; security decisions never derived
  from events) `Supported`. Consumers must branch on `phase`/`status`, never
  percent alone (`TERMINAL_PROGRESS_PHASES`) `Supported`.
- Host-specific progress rendering is `Not-tested`.

## Read Results

- `AuditHandoff` fields (`audit_id/project_id/snapshot_id` binding;
  `finding_refs/evidence_refs/verification_refs/report_ref/limitations/
  recovery_state/provenance`) with secret-marker and empty-ref rejection
  `Supported`. `ResultEnvelope` wraps `status + handoff + compat + health
  snapshot` `Supported` (`handoff.py`).
- `complete` gates `REPORTING→COMPLETED` on non-empty `verification_refs`
  `Supported` (`lifecycle.py`). Report projection via
  `cyber-agent report --findings <file> --audit-id <id> --format
  json|jsonl|markdown` `Supported` (Core `ReportService`).
- Host-specific result rendering is `Not-tested`.

## Troubleshoot

| failure reason (pipeline) | meaning | operator action (server-side, `Supported`) |
|---|---|---|
| `invalid: ...` / `capability-denied: ...` / `policy-denied: ...` | Parse, empty grant, or engine refusal → DENY | Fix the envelope/grant and re-evaluate; never retry with wider scope. |
| `authz-forged: ...` / `expired: ...` | Authz ref not independent of text, or context not authorized / expired → DENY | Re-issue a fresh server-side `DelegationContext`; do not paste authz text into the envelope. |
| `binding-mismatch` / `scope-widening` | Audit/project/snapshot or outer-scope violation → QUARANTINE | Re-bind to the correct ids / narrow the scope; quarantine is terminal for that attempt. |
| `secret markers observed` | Secret-like material in metadata → QUARANTINE | Remove secrets; re-evaluate with refs only. |
| `hostile:<class>` (DENY) / `hostile:use another audit` (QUARANTINE) | Hostile payload in untrusted metadata | Strip the payload; cross-audit attempts quarantine — do not re-delegate across audits without fresh context. |

- Unknown host/task/tool inputs raise instead of falling back `Supported`
  (`evaluate_compat` UNKNOWN, `tools_for_task` reject, `get_task_allowlist`
  raise, negotiation returns `None` → abort). Any host doc claiming a silent
  fallback would contradict this `Supported`.

## Security Notes

See security-model.md for the full model. Delegation-specific restatements,
all `Supported`: metadata never authority; server-issued context + engine
verdict are the only authorization; no execution/shell/policy-mutation in the
pipeline; fail-closed on engine errors; `MAX_DELEGATION_DEPTH=3`.

## Version Compatibility

- Advertisement identity `emo-cyber-agent 0.1.0`, protocols `2024-11-05,
  2025-03-26, 2025-06-18`, surface `1.0` `Supported`.
- `SUBAGENT_API_VERSION="1.0"` (`hosts.py`) `Supported`; advertisement shape
  versioning is independent of the server release `Supported`.
- `evaluate_compat` rules as in the host docs `Supported`. Per-host support
  statuses: `generic-mcp` `Contract-tested`; `opencode/pi/hermes/jan`
  `Not-tested` with presence-only `Environment-tested` exception;
  `anythingllm` `Not-tested`. No host versions pinned `Supported` (bounds
  empty by design) / `Not-tested` (interop unproven).
