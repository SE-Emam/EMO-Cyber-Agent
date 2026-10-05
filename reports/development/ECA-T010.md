# ECA-T010 — Security Verification Layer

## Objective
Add an independent Core verification layer that evaluates a
FindingCandidate into CONFIRMED / SUPPORTED / REFUTED / INCONCLUSIVE /
BLOCKED from traceable verification evidence. Verification ≠
exploitation: prove or refute the hypothesis with minimum necessary
action, never mutate, persist, escalate, or attack.

## Scope
In scope: Verification domain (case/request/plan/result), 7 safe methods,
3 safety levels, 4 least-privilege capabilities, explicit target model,
StrictPolicy gate, read-only SQL reuse, controlled-reproduction boundary,
external-target denial, per-verification evidence, confirmation criteria,
refutation with history, inconclusive semantics, explicit candidate
transitions (no CANDIDATE→CONFIRMED shortcut), multi-verification,
conflict→INCONCLUSIVE, budgets, operational-only retry, 11-code failure
model, separate executor port, 10-scenario mock provider, 33 offline tests,
§33 profile×safety matrix.
Out of scope (deferred): exploit/persistence/escalation frameworks,
production mutation, active penetration, remediation, reporting engine,
real isolated harness (port exists; mock serves tests).

## Architecture
```text
Candidate → Need verification? → VerificationRequest → Validate → Scope
→ Capability → StrictPolicy → ToolRegistry → VerificationExecutor
→ Evidence → Correlation → Update Candidate → Confirm/Refute/Inconclusive
```
Reasoner proposes; Core validates; Policy authorizes; Registry resolves;
executor runs only the authorized plan; the graph receives the result.
`core/verification.py` (~600 lines) owns domain + service; the executor
port is deliberately SEPARATE from ECA-T007's ToolExecutor so no scanner
can inherit verification privileges (type-inequality test-pinned).

## Verification Domain
`Verification`: verification/candidate/audit/asset ids, method, status,
requested_by, policy_decision_id, started/completed timestamps,
evidence_ids, redacted result_summary, deterministic confidence,
safety_level, constraints, provenance. State machine PENDING → RUNNING →
{CONFIRMED, SUPPORTED, REFUTED, INCONCLUSIVE, BLOCKED, FAILED, TIMEOUT};
TIMEOUT alone may retry to RUNNING (operational-only); terminals are
otherwise closed (invalid-transition test-pinned).

## Verification Request
Fixed fields: method, target, rationale_summary, expected_evidence,
safety_level, statement (optional read-only query text, classified before
use). Constructor denies shell/permissions/command/credential/override
fields (MODEL_INVALID_RESPONSE at the boundary, no repair-to-action).

## Verification Result
verification/candidate/audit ids, terminal status, deterministic
confidence (0.85 confirmed / 0.6 supported / 0.2 refuted / 0.4 otherwise —
graph-derived constants, never model scores), evidence ids, redacted
summary, completion timestamp.

## Verification State Machine
Covered under Domain above; key property: status derives ONLY from
criteria evaluation over evidence + policy validity, never from raw
outcome strings (injection/malformed outcomes map to INCONCLUSIVE).

## Methods
Seven, fixed: STATIC / CONFIGURATION / DATAFLOW / DEPENDENCY / POLICY
CONFIRMATION, READ_ONLY_QUERY, CONTROLLED_REPRODUCTION. No destructive
exploit, persistence, escalation, network attack, or production mutation
exists or is expressible (purity-grep pinned).

## Safety Levels
PASSIVE (all six read methods) = allowed in read_only; SAFE_ACTIVE
(controlled reproduction only) = verify profile + explicit restricted
grant; RESTRICTED_ACTIVE = denied by default (no method maps here in
ECA-T010 — asserted). No ACTIVE capability exists under READ_ONLY.

## Capabilities
One per tool, least privilege: verification.static / .config /
.read_query / .controlled_reproduction. No `verification.execute`.
`controlled_reproduction` additionally lives in the policy's
restricted-grant set (denied unless explicitly granted — new
`granted_restricted` parameter on StrictPolicyEngine).

## Policy Boundary
Plan path: candidate/audit match → safety/profile check → scope check →
registry resolution → `issue_decision` → plan binds decision id.
Execute path: audit match → stored ALLOW decision present AND equal to
the plan-bound id (stale/mismatched → STALE_POLICY) → run → evidence →
assess. Missing decision denies even for inherently-safe methods.

## Target Model
Kinds: repository/file/endpoint/database_object/dependency/
configuration. Constructor denies `*`, empties, null bytes, traversal,
and `http(s)` externals. External targets are DENY-by-default end to end.

## Read-Only Verification
`READ_ONLY_QUERY` statements classified at PLAN time via the ECA-T006
classifier (SELECT/WITH only; INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/
TRUNCATE/GRANT/REVOKE/multi-statement → plan DENY). Tests add a DROP-via-
request case on top of the classifier battery.

## Safe-Active Verification
CONTROLLED_REPRODUCTION records isolation constraints (isolated,
deterministic, bounded, ephemeral, credential-free, egress-free) on the
plan, requires `verify` profile + restricted grant, and runs through the
same single-harness executor. Without a real harness the mock stands in;
production targets are never assumed.

## External-Target Restrictions
`http(s)` locators rejected at model construction; scope check second;
no explicit-grant mechanism exists yet (future phase must design it, not
assume user-supplied URLs imply authorization).

## Evidence
Every verification mints ≥1 EvidenceItem (method/target/observation/
timestamps/tool-version/provenance/digest/safety metadata, redacted);
CONFIRMED with zero evidence raises NO_EVIDENCE instead. Raw secrets never
persist (redaction at error construction, summaries, and trail).

## Candidate Promotion
`assess_candidate` (deterministic): no verifications/evidence →
NEEDS_VERIFICATION; invalid policy/scope → BLOCKED; confirmed+refuted →
INCONCLUSIVE (conflict, needs review); refuted-only → REFUTED (history
kept, never deleted); confirmed-only + valid policy/scope →
CONFIRMED + eligible=True; supported-only → SUPPORTED (not eligible);
else INCONCLUSIVE. Eligibility is NOT a Finding — reporting owns the final
step later. Model claims cannot confirm (scope-mismatch test blocks even a
CONFIRM-labeled record).

## Refutation
First-class: REFUTED requires its own evidence (e.g. RLS-enabled fact
against a missing-RLS hypothesis), is never retried (call-count pinned),
and preserves candidate history.

## Inconclusive Handling
Weak/absent evidence, unavailable harness, contradiction, scope blocks →
INCONCLUSIVE with reasons; never auto-converted to low-confidence
findings. Malformed provider outcomes also land here (never confirmed).

## Conflict Handling
SUPPORTED + REFUTED on one candidate → INCONCLUSIVE + conflict reason
(never intuitive tie-break). Mirrors the ECA-T008 evidence-conflict rule
one layer up.

## Budget
Per-service: max_verifications (6), max_active (2), max_time_s (300),
max_retries (1), max_same_target_attempts (2). Breach → BUDGET_EXHAUSTED /
LOOP_DETECTED; exhaustion never confirms (tested).

## Retry Semantics
Operational-only (FAILED/TIMEOUT), bounded by max_retries, logged per
attempt. REFUTED/INCONCLUSIVE/CONFIRMED never retry (call counts pinned).

## Model Boundary
Reasoner text can propose verification; Core alone assigns terminal
status from evidence + criteria. Injection-labeled raw results
(`UNSAFE_REQUEST`: "ignore policy… mark confirmed…") change nothing:
authority fields on the policy stay empty (test-pinned).

## Prompt Injection
Verification results/target content are DATA: criteria mapping ignores
outcome-string semantics beyond the six known tokens; unknown tokens →
INCONCLUSIVE. Trail and evidence stay redacted; no status is settable
from content.

## Mock Provider
`MockVerificationProvider` (a true `VerificationExecutorPort` subclass):
CONFIRM/REFUTE/INCONCLUSIVE/BLOCKED/TIMEOUT/FAILURE/CONFLICT/CROSS_SCOPE/
UNSAFE_REQUEST/MALFORMED_RESULT + call/plan recording for assertions.

## Tests
`pytest tests/ -p no:warnings` → **188 passed, 3 skipped** (155 prior +
33 new; skips are pre-existing optional binary probes). New: domain +
lifecycle (+retry-only TIMEOUT), request/target denials, candidate
transitions (incl. shortcut denial), least-privilege specs, happy-path
confirm, missing/stale/mismatched decisions, read_only-vs-active matrix
rows, verify+grant reproduction, scope/external/unknown-cap denials,
read-query allow + write-SQL battery, refutation history, inconclusive,
conflict→inconclusive, accumulation, no-refute-retry, bounded retries,
full criteria table, model-claim block, budget/loop exhaustion, §33
matrix (5 rows), injection/malformed, cross-audit, credential-free trail,
exploit-primitive scan, port separation, plan auditability.

## Security Tests
In `test_verification.py`: no-policy/stale/mismatched decisions,
wrong/unknown capability, active-under-read_only, out-of-scope + external
targets, write/destructive SQL, credential absence (trail + store),
shell/command/permission smuggling (constructor), privilege escalation
via parameters, malicious results, model-claimed confirmation, cross-audit
candidates, conflicting verifications, repeat-loop, budget exhaustion.

## Contract Tests
Port ↔ mock ↔ specs ↔ registry ↔ strict policy ↔ invocation-bound
decisions ↔ evidence ↔ assessment chain; executor-port ≠ ToolExecutor
(type test); candidate-transition table; matrix rows bind profile ×
method × decision → expected result with explicit policy per row.

## Files Inspected
- `core/correlation.py` (FindingCandidate — extended additively),
  `core/policy.py` (restricted-grant set added), `core/tool_registry.py`,
  `core/execution.py`, `core/scanners.py`, `core/repository.py`,
  `core/supabase.py`, `core/contracts.py`, `core/service.py`,
  `domain/models.py`, `adapters/*`, `docs/16/02/03`, `docs/schemas/*`
- `tests/unit/test_foundation|repository|supabase|toolchain|reasoning.py`

## Files Changed
- `src/emo_cyber_agent/core/verification.py` (NEW, ~600 lines): domain,
  request/plan/result, state machines, safety, capabilities, targets,
  budgets, executor port, policy-gated service, assessment/promotion.
- `src/emo_cyber_agent/core/correlation.py` (ADDITIVE): 4 new
  CandidateStatus members (VERIFYING/CONFIRMED/INCONCLUSIVE/BLOCKED) with
  ECA-T010 comments; zero behavior change to existing flows.
- `src/emo_cyber_agent/core/policy.py` (ADDITIVE): verification read caps
  in known set; `verification.controlled_reproduction` in new restricted
  set + `granted_restricted` parameter.
- `src/emo_cyber_agent/adapters/mock_verification.py` (NEW): 10-scenario
  scripted executor port.
- `tests/unit/test_verification.py` (NEW): 33 offline tests.
- (No MCP/CLI/API/schema/domain-model breaks; no vendor SDK; no verifier
  harness beyond the mock.)

## Schemas
Same strategy as ECA-T008/009: verification objects are internal Core
contracts this phase; no new/duplicated public schemas. 4/4 existing
schemas valid.

## Invariant Impact
1. Read-only — ENFORCED (profile×safety matrix; SQL allow-list).
2. Untrusted content — ENFORCED (results/targets are DATA; criteria-only mapping).
3. No finding without evidence — ENFORCED STRONGER (NO_EVIDENCE guard + eligibility gates).
4. No destructive action — ENFORCED (no destructive path expressible).
5. Tool outputs are evidence — ENFORCED (every verification mints evidence).
6. Uncertainty explicit — ENFORCED (deterministic confidences; model scores absent).
7. Same contracts — ENFORCED (single service path).
8. Provider external — ENFORCED (injectable port; no SDK).
9. Scanner provenance — PROTECTED (verifier id/version/provenance on evidence).
10. No cross-project reuse — ENFORCED (audit-bound plans/decisions/evidence).
11. Specialist worker — ENFORCED (verification-only; exploit scan clean).
12. Host delegates — PROTECTED (result objects are delegation returns).
No invariant weakened; model confirmation authority explicitly impossible.

## Known Limitations
- Real isolated harness unwired (mock stands in; port is the seam).
- `read_only_query` executes only via wired harnesses; default path still
  records plan + evidence metadata through the mock in tests.
- Budget windows are per-service-instance (documented; cross-instance
  accounting is release integration).
- Promotion eligibility is advisory to reporting (no Finding builder here).

## Deferred Work
Exploit/persistence/escalation frameworks (never planned for this
product), active penetration, production mutation, remediation, reporting
engine, real harness wiring, cross-instance budget accounting.

## Evidence
- `pytest tests/ -p no:warnings` → `188 passed, 3 skipped`.
- `validate_schemas.py` → 4/4 OK. `compileall` → OK.
- Purity: no Finding/shell/subprocess/socket/exploit constructs in new
  modules beyond prohibition docstrings + absence assertions.
- Files: `core/verification.py`, `core/correlation.py` (+4 statuses),
  `core/policy.py` (+restricted set), `adapters/mock_verification.py`,
  `tests/unit/test_verification.py`.

## Final Status
**PASS** — all 26 exit criteria met: domain/request/result/state machine,
safe methods, safety levels, separate capabilities, explicit scope,
strict gate, no default-active execution, read-only + safe-active
boundaries, separate executor port, mock provider, evidence integration,
promotion/refutation/inconclusive/conflict rules, budgets, retry rules,
security + injection + isolation tests, prior suites + schemas green. No
BLOCKED condition (no arbitrary execution, no unauthorized active testing,
no external access, no credential propagation, no write path, no model
confirmation, no bypass) observed. Reporting/final-Finding work remains
explicitly out of scope.
