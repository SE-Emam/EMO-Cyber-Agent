# POST-RC-012 — Advanced Verification Strategies Assessment

## Objective
Turn security hypotheses into reproducible, budgeted,
policy-checked verifications — a deterministic strategy catalog,
a closed hypothesis-to-oracle matrix, and a Core-owned planner
whose only execution path is a narrow adapter contract — while
the model proposes and the provider observes, but neither decides,
and no verification ever writes a Finding, assigns severity,
escalates its own safety level, or widens its own budget.

## Scope
In scope: `src/emo_cyber_agent/verification/` (15 modules, ~2.9k
lines), 24 official strategies in 3 catalog documents, 3 starter
templates, 4 interop schemas (28 total), 6 new test files (291
tests). Out of scope (deferred): live transport adapters
(MCP/HTTP/CLI bindings), provider SDK integrations, persistent
verification history beyond evidence ids, strategy authoring UI,
auto-tuning of budgets, cross-audit strategy reuse, real
controlled-reproduction sandboxes, coverage-guided strategy
generation.

## Architecture
Host → CLI/MCP/Python API → `VerificationPlanner.plan()` →
deterministic candidate walk over `VerificationMatrix` row
(candidates sorted by safety level then id; first strategy that
passes profile level + evidence + oracle contract + resolvable
adapter wins) → frozen `VerificationStrategyPlan` (id `vplan-<digest>`,
digest excludes `policy_decision_id` for determinism) →
`VerificationPlanner.dispatch()` → policy re-check → binding
re-check → scope → health → budget → `VerificationAdapter.execute()`
→ Core-side typed oracle evaluation → `StrategyVerificationResult`
(closed statuses) + `VerificationEvidence` (redacted, digested) →
downstream Finding evaluation happens elsewhere, under its own
contract. The planner never imports a transport; adapters never
import policy.

## Boundaries (enforced, tested)
No public execute/run surface: the only execution entry is
`VerificationPlanner.dispatch(plan, adapter=...)`, which re-validates
policy, binding, scope, health, and budget — a plan alone never
grants execution and a fabricated `policy_decision_id` fails with
`STALE_POLICY`. No Finding/severity authority: `StrategyVerificationResult`
is `extra="forbid"` with no `severity`/`finding_id` fields, and
`eligibility()["severity"]` is always `None` (handoff only).
No safety escalation: category ceilings (`CATEGORY_SAFETY_CEILING`)
refuse `RESTRICTED_ACTIVE` for every default category, `SAFE_ACTIVE`
requires the `verify` profile plus a granted
`verification.controlled_reproduction` capability, and
`RESTRICTED_ACTIVE` at dispatch fails `UNSAFE_LEVEL` by default.
No scope widening: targets must be explicit — `*`, `all`, `any`,
external URLs, traversal segments, null bytes, and forbidden tokens
are rejected at `StrategyTarget`, at the adapter request validator,
and again in dispatch scope checks. No self-widened budgets:
`effective_budget()` is a pointwise minimum across strategy ⊕
runtime, `ResourceBudget` bounds are field-enumerated, and
`used()` raises `BUDGET_EXCEEDED` on violation. No operational-to-
verdict laundering: operational results map only to
`INCONCLUSIVE/BLOCKED/NOT_RUN` with `OPERATIONAL_RETRY` or
`SECURITY_RETRY` classes (`policy-denied` is never retryable as an
operational fault). No provider authority: adapter output is data —
authority language in `normalized_output`/observations becomes
`data_flags`, never a status; `status` is a closed enum that
refuses `CONFIRMED/VULNERABLE/PROMOTED/CRITICAL`. No transport in
Core: a static scan asserts the layer contains no `requests`,
`socket`, `subprocess`, `urllib`, `shell=True`, `os.system(`, or
`requests.get(` outside string literals. No network, no process,
no filesystem writes anywhere in the layer or its tests.

## Contracts
Frozen, extra-forbidden, digest-carrying models: `VerificationStrategy`
(24 official, provenance `official`, verdict-free criteria,
resource budget, safety ceiling), `StrategyTarget`, `MatrixRow`
(20 hypothesis kinds × closed oracle/target/safety vocabularies),
`VerificationOracle` (11 kinds, 8 operators, deny-by-default
`AUTHZ_DECISION=deny`, code-token and assertion allowlist guards),
`VerificationStrategyPlan` (plan digest + selection notes + policy
binding), `StrategyVerificationResult` (5 statuses, 3 retry classes,
coverage, evidence id, limitations, data flags),
`VerificationAdapterRequest/Response` (forbidden request-field
blocklist, provenance binding with `policy_decision_id` +
`tool_invocation_id`), `AdapterBinding` (frozen at planning; swap
detected as `ADAPTER_VERSION_MISMATCH`), `ResourceBudget`/
`BudgetUsage`, `CoverageAssessment` (ceiling pinned to
`context-only`), `VerificationEvidence` (credential redaction,
sensitive-output flag). 26 closed `StrategyErrorCode` values;
verdict vocabulary (`vulnerable/confirmed/critical/severity/exploit/
fixed/safe/...`) is rejected inside strategy semantics and inert
everywhere else. 71 package exports.

## Strategy Catalog & Matrix
24 official strategies across 3 documents
(`official/{authorization,boundary,assurance}-strategies.yaml`,
loaded via `strategies:` lists with shared document provenance;
the official loader refuses any non-official source with
`PROVENANCE_MISSING`). Catalog ↔ matrix consistency is bidirectional
and asserted: every strategy is referenced by a matrix row or one
of the change/pack/threat/agent maps, and every referenced id
exists in the catalog. 20 hypothesis rows each declare required
evidence, required capabilities, safety level, target kind, oracle
kind, and refutation criteria; each row's capabilities are a subset
of its candidate strategies' capabilities. Selection is fully
deterministic: the same inputs (plan digest excludes the per-run
policy uuid) produce the same plan, and the model's `model_suggestion`
is recorded as a note (`matches-deterministic-selection` /
`recorded-selection-remains-deterministic` /
`ignored-outside-candidates`) without ever affecting the choice.

## Planner, Oracle, Evidence
`plan()` validates audit/project/snapshot identity, walks
candidates, builds the oracle from the row (HTTP kinds demand an
explicit `expected`; others fall back to deny-by-default constants),
issues a scoped policy decision, tightens budgets, and freezes the
plan. `dispatch()` re-checks everything (a plan is necessary, never
sufficient), builds a request that must match the frozen binding
exactly, and interprets only bound, provenance-verified responses:
MALFORMED output raises `ADAPTER_INVALID_REQUEST`, identity drift
raises `ADAPTER_VERSION_MISMATCH`, forged policy binding raises
`STALE_POLICY`. Oracle evaluation is pure comparison — missing
observations are `INCONCLUSIVE`, never `REFUTED`. Evidence is built
from the response with credential redaction and a coverage
assessment whose `conclusion_ceiling` is structurally pinned to
`context-only`; controls that are absent cap coverage at `LIMITED`,
and `NOT_APPLICABLE` controls cap it at `PARTIAL`.

## Adapters
Five reference adapters (`mock-passive`, `mock-http`, `mock-authz`,
`mock-config`, `mock-graph`) implement the contract behind nine
scripted scenarios (`SUPPORTED, REFUTED, INCONCLUSIVE, BLOCKED,
TIMEOUT, MALFORMED_OUTPUT, TARGET_CHANGED, POLICY_DENIED,
RESOURCE_LIMITED`). The registry validates capabilities against a
closed vocabulary with escalation tokens refused
(`ADAPTER_ESCALATION`) before unknown-capability handling, requires
provider provenance and an execution contract version, and refuses
duplicates while remaining idempotent for the same instance. The
resolver picks the lowest-id healthy adapter that supports the
strategy, target kind, and every required capability, then freezes
an `AdapterBinding`; the resolver's own binding is re-derived from
plan fields at dispatch so a swapped adapter cannot redefine it.

## Adversarial Results
Battery (all contained): verdict vocabulary rejected in strategy
criteria and documents; safety ceilings beat adversarial level
requests (including empty-level `CONTROLLED_REPRODUCTION`); matrix
rows cannot smuggle unknown hypothesis/safety/oracle vocabularies;
hostile targets (wildcard, `all`, `any`, external URL, traversal,
null byte) refused at `StrategyTarget` and at adapter-request level;
forbidden request fields (`policy_override`, `finding_severity`,
...) rejected by the contract; hostile oracle subjects (`lambda: 1`)
and unknown custom assertions refused; hostile strategy documents
(path-traversal ids, non-mapping bodies) refused as
`CATALOG_INVALID`; the official loader refuses untrusted provenance;
conflicting catalog identity refused; providers without oracle
observations yield `INCONCLUSIVE`, authority words become
`data_flags`, banned status enum values raise `ValidationError`, a
forged `policy_decision_id` fails `STALE_POLICY`, and escalation or
shell capabilities are refused at registration; hostile statements
and out-of-candidate model suggestions cannot change selection; a
fabricated plan cannot execute (`STALE_POLICY`); budgets cannot be
widened; result models refuse Finding-style fields; coverage cannot
claim a security conclusion; a static scan proves no live attack
surface (no network/process imports or calls outside string
literals).

## Tests
`test_verification_strategies.py` (51) +
`test_verification_adapters.py` (34) +
`test_verification_security.py` (25) +
`test_verification_regression.py` (15) +
`test_verification_adversarial.py` (31) +
`test_verification_adapter_contract.py` (135) — 291/291 new:
strategy contracts and catalog loading (starter + official,
provenance, conflicting ids, document hostility), adapter contract
suite parameterized over all 5 reference adapters (registration,
health, provenance, interop schema, hostile-request rejection,
bound deterministic execution, closed capability vocabulary),
strategy contract suite parameterized over all 24 official
strategies (interop schema, verdict freedom, category ceiling,
matrix/map referencability, adapter resolvability), the full
matrix end-to-end over all 20 hypothesis rows under SUPPORTED /
REFUTED / TIMEOUT (60 dispatches), dispatch security boundaries
(policy re-check, stale decisions, scope, binding swap, health,
budget, safety ceilings, malformed/forged responses, closed
result vocabulary), regression semantics (baseline/drift/timeout/
policy-denial/historical labels + digest stability), and the
adversarial battery above — plus the five contract E2E scenarios:
PASSIVE configuration check → `SUPPORTED` (with controls →
`COMPLETE`, without → capped `PARTIAL`), authorization matrix →
`SUPPORTED`/`REFUTED` with deny-by-default, timeout →
`INCONCLUSIVE` with `OPERATIONAL_RETRY`, policy denial → `BLOCKED`
and `not_run()` → `NOT_RUN` (both `SECURITY_RETRY`, never eligible),
model suggestion ignored without changing selection. Plan, result,
strategy, and adapter documents validate against their JSON
schemas. Full suite: **1063 passed, 3 skipped**. Schemas 28/28
valid. Testing caught real defects: dispatch derived the binding
from the passed adapter instead of the frozen plan fields (a swap
could redefine its own binding), `model_copy` did not re-run
`model_post_init` so `data_flags` had to be re-derived in the
planner, registry capability validation reported unknown
capabilities before escalation tokens, the loader accepted single
`strategy:` only (added `strategies:` lists with document-level
provenance), the official loader checked provenance after
construction, HTTP oracle kinds silently accepted empty
expectations (now `ORACLE_REJECTED`), `policy_decision_id` leaked
into result digests breaking determinism, evidence coverage was
capped incorrectly when controls were `NOT_APPLICABLE`, and the
plan digest had to exclude the per-run policy uuid to keep plans
reproducible.

## Files Inspected
- `core/policy.py` (`StrictPolicyEngine` scope/decision contracts),
  `core/findings.py` (Finding lifecycle kept inviolate),
  `core/verification.py` (pre-existing Core verification contract),
  `core/tool_registry.py` (capability vocabulary precedent),
  `core/repository.py` (`redact_credentials`, `canonical_digest`),
  `threat_modeling/spec.py` (digest/stable-id helpers),
  `scripts/validate_schemas.py` + `docs/schemas/*.json`
  (schema conventions), `templates/*/official/*` (provenance
  conventions), `tests/unit/test_verification.py` (ECA-T010
  baseline must stay green — 33 passed).

## Files Changed
- `src/emo_cyber_agent/verification/{__init__,errors,budget,
  oracles,strategy,adapter_contracts,adapter_registry,
  adapter_resolver,adapter_provenance,adapters,matrix,evidence,
  coverage,planner}.py` (layer complete; planner/strategy/loader/
  registry/adapters/evidence refined this session)
- `docs/schemas/verification-{strategy,plan,result,adapter}.
  schema.json` (4 NEW; 28 total)
- `templates/verification/{VERIFICATION-STRATEGY,VERIFICATION-PLAN,
  VERIFICATION-ADAPTER-TEMPLATE}.yaml` +
  `official/{authorization,boundary,assurance}-strategies.yaml`
  (24 strategies)
- `tests/unit/test_verification_{strategies,adapters,security,
  regression,adversarial,adapter_contract}.py` (6 files, 291 tests)
- `tests/fixtures/verification/regression_cases.json`
- (No Core, MCP, CLI, reporting, or policy changes.)

## Invariant Impact
All 12 PASS: 1 read-only (zero network/process/fs surface,
static-scanned), 2 untrusted content (model suggestion and provider
output are data — recorded as notes/flags, never decisions),
3 evidence-gated (oracle evaluation requires declared expectations
and evidence ids; missing observation → `INCONCLUSIVE`), 4 no
destructive transition (no Finding/severity/trust mutation; results
carry `severity: None`), 5 tool outputs as evidence (adapter
responses become redacted digested evidence with provenance),
6 explicit uncertainty (5 statuses, coverage states, limitations,
`context-only` ceiling everywhere), 7 shared contracts (frozen
models, closed vocabularies, 4 schemas, redaction/digest helpers
reused from Core), 8 external provider choice (provider is an
injected adapter behind a contract; provenance bound to policy
decision), 9 scanners authoritative (scanner output enters as
observations, judged by the Core-side typed oracle), 10 human
review (verification only produces eligibility handoff — Finding
evaluation stays with FindingService), 11 specialist worker
(planner owns selection; model may only suggest and be recorded),
12 host delegates (transport stays outside Core; adapters are
injected).

## Known Limitations
- Reference adapters are deterministic mocks: no real HTTP,
  filesystem, or MCP execution exists yet (by design, offline).
- `RESTRICTED_ACTIVE` / controlled reproduction is structurally
  refused by default; enabling it needs a real sandbox story.
- Budgets are enforced per dispatch call, not across a session of
  many dispatches (a session-level accumulator lives with the
  future execution host).
- Strategy selection is single-best, not optimal: no scoring
  across candidates beyond safety level then id.
- Coverage of `PARTIAL` under `NOT_APPLICABLE` controls means a
  bare plan never reports `COMPLETE`; callers must declare controls.
- Evidence ids are digest prefixes without a store — durability
  belongs to the future verification history service.

## Deferred Work
Live MCP/HTTP/CLI adapter implementations against this contract,
provider SDK bindings with real provenance (trace ids), session-
level budget accounting, verification history store keyed by
evidence id, strategy authoring/authoring-time linter, coverage-
guided candidate scoring, controlled-reproduction sandbox profile,
and cross-audit strategy version pinning — each in its dedicated
stage.

## Evidence
- `python3 -m pytest tests/unit/test_verification_strategies.py
  tests/unit/test_verification_adapters.py
  tests/unit/test_verification_security.py
  tests/unit/test_verification_regression.py
  tests/unit/test_verification_adversarial.py
  tests/unit/test_verification_adapter_contract.py` → 291 passed.
- Full suite → **1063 passed, 3 skipped**. Schemas 28/28 valid
  (`python3 scripts/validate_schemas.py`).
- `uvx ruff check src/emo_cyber_agent/verification
  tests/unit/test_verification_*.py` → All checks passed.
- All 20 matrix rows plan and dispatch under SUPPORTED / REFUTED /
  TIMEOUT; all 24 official strategies validate against the
  strategy schema and resolve to a reference adapter.
- Five contract E2E scenarios green with zero Findings and
  `severity: None` everywhere.
- Static scan asserts no live attack surface in the layer.
- Files listed above.

## Status: PASS
