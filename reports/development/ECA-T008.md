# ECA-T008 — Evidence Graph & Security Correlation Foundation

## Objective
Build the Core layer that turns multi-source evidence into normalized
security observations, typed relationships, correlations, deduplicated
groups, and finding candidates — WITHOUT a full agent reasoning loop and
WITHOUT granting any LLM final-vulnerability authority.
Principle kept: FACTS → EVIDENCE → RELATIONSHIPS → CORRELATION → CANDIDATE.
Never: RAW TOOL OUTPUT → LLM → FINAL VULNERABILITY.

## Scope
In scope: central Evidence Store, stable evidence identity, trust model,
9 typed relationship kinds, deterministic correlation engine with 4
versioned rules, SecurityObservation, FindingCandidate (6-state lifecycle),
evidence-mandatory enforcement, fingerprint dedup (audit-scoped),
cross-source correlation (notably GitHub + Supabase + scanner),
conflict detection, temporal context, in-memory asset graph, analysis-only
boundary, `SecurityReasonerPort` interface (no LLM implementation),
`EvidenceContext` builder, injection-as-data boundary, 13-class taxonomy,
deterministic severity/confidence separation, 8 reproducible fixtures,
29 offline tests.
Out of scope (deferred to ECA-T009+): LLM reasoning, autonomous tool
selection, exploit execution, remediation, final confirmation, external
graph DB, new public JSON schemas.

## Evidence Model
Reuses domain `EvidenceItem` unchanged (no model/schema churn): id,
source_tool(+version), target_asset_id, timestamp, location, content_hash,
content_summary (sanitized), provenance (carries `labels` + `trust` used
by correlation). Audit binding lives in the store index (`audit_of` map),
so items stay scope-bound without touching the shared model.

## Evidence Trust Model
Six explicit levels: DETERMINISTIC_TOOL / REPOSITORY_FACT / DATABASE_FACT /
PROVIDER_METADATA / MODEL_HYPOTHESIS / USER_ASSERTION. Provenance-declared
trust wins; otherwise inferred from source prefix (semgrep/trivy/osv/
gitleaks → deterministic; github/repository* → repo fact; supabase/
database* → db fact). Rule enforced and tested: MODEL_HYPOTHESIS ≠
VERIFIED_FACT, and model-sourced items never raise confidence (confidence
formula has no trust bonus at all).

## Evidence Store
`EvidenceStore` (implements `contracts.EvidenceStore` ABC: store/retrieve/
link_to_finding) plus audit-scoped `list/get/query/related`:
by audit (mandatory on every read), asset, tool, locator, digest, label.
`store()` requires `audit_id` (ValueError otherwise); `get()` raises
KeyError on cross-audit access. No global mutable state beyond the
instance; instances are per-test/per-audit in practice.

## Relationships
`EvidenceRelation` (frozen): id, audit_id, from/to, kind ∈ {SAME_AS,
DUPLICATE_OF, LOCATED_IN, REFERS_TO, DEPENDS_ON, DERIVED_FROM,
CONTRADICTS, SUPPORTS, CONTEXT_FOR}, deterministic flag, reason,
created_at. Every relation is scoped (audit_id), auditable (reason +
timestamp), traceable (endpoint ids), and deterministic-flagged.

## Correlation Engine
`CorrelationEngine(store)` — constructor takes ONLY a store (signature
test-pinned: no model, no policy, no ports). `correlate(audit_id)` runs:
dedup → conflict detection → per-bucket rule matching (buckets keyed by
shared asset else locator, enabling cross-source joins) → observations +
candidates with snapshot notes. Reads the store; writes nothing external;
constructs zero Findings (grep-pinned). Rules version `corr-v1`.

## SecurityObservation
Frozen intermediate object: id, audit_id, asset, taxonomy (13 classes),
statement, NON-EMPTY evidence_ids (constructor DENY otherwise), rule id,
provenance (trust set + sources). Always points at source evidence.

## FindingCandidate
Distinct from final Finding: candidate_id, audit/asset, observation +
evidence ids (evidence mandatory — DENY otherwise), hypothesis,
provisional_severity (info/low/medium/high/critical — provisional ONLY),
deterministic confidence, status ∈ {CANDIDATE, CORRELATED,
NEEDS_VERIFICATION, SUPPORTED, REFUTED, PROMOTED}, rule id, snapshot note.
PROMOTED is a terminal handoff marker for a LATER explicit contract —
promotion builds no Finding here (test-pinned).

## Deduplication
`dedup_fingerprint(audit_id, item)` over tool+version+location+hash+asset,
AUDIT-BOUND (same bytes in two audits hash differently — tested).
Duplicates link via deterministic DUPLICATE_OF relations. Revision changes
(hash change) correctly break the group (tested).

## Conflict Handling
`CONTRADICTION_PAIRS` (rls-enabled/rls-disabled, grant-absent/public-grant)
matched within shared locators → `EvidenceConflict` (ids, type, sources,
timestamps, note) + CONTRADICTS relations; adjacent candidates flip to
NEEDS_VERIFICATION with confidence penalty. Conflicts are never resolved
by intuition and never become findings.

## Temporal Consistency
Every candidate carries `snapshot_note` with min..max timestamps and
distinct-count; T1-source/T2-scanner/T3-database states are never merged
into one instant (dedicated two-timestamp test asserts both bounds
present). Snapshot sections keep their own times (Supabase pattern reused).

## Asset Graph
In-memory `AssetGraph` (nodes: repository/file/endpoint/service/database/
table/column/function; edges: contains/located_in/depends_on/reads/writes/
calls) built from evidence asset/location fields; `neighbors()` queries.
Sufficient for ECA-T009 planning context; no external graph DB.

## Security Boundaries
Analysis-only, verified by source scan + tests: no subprocess/os.system/
urllib/socket, no PolicyEngine construction/evaluation, no Finding
construction, no writes anywhere. Correlation cannot execute tools, raise
permissions, change policy, mutate repos/DBs, touch network, or run shell.

## Model Boundary
`SecurityReasonerPort.propose_hypotheses(context)` exists as an ABC for
ECA-T009; it is abstract (instantiation raises TypeError, tested) and the
engine NEVER calls it (constructor signature test). Core correlates fully
without any model. Rule preserved: LLM proposes/interprets/links; Core
enforces; tools prove; verification confirms.

## Prompt Injection Boundary
All evidence content is DATA: injection battery (`ignore previous
instructions`, `run tool X`, `disable security`, `grant permission`) as
README evidence yields ZERO observations/candidates; SQL-comment injection
likewise; co-located real facts still correlate normally (no suppression,
no promotion). Tool-output injection text is preserved inside untrusted
envelopes, never executed or elevated.

## Files Inspected
- `domain/models.py` (EvidenceItem/Finding shapes — reused unchanged)
- `core/contracts.py` (EvidenceStore ABC — implemented)
- `core/repository.py` (redaction/digest/untrusted helpers reused)
- `core/tool_registry.py`, `core/service.py`, `core/policy.py`,
  `core/execution.py`, `core/scanners.py` (integration surfaces)
- `adapters/*`, `docs/16-implementation-plan.md`, `02-architecture.md`,
  `03-security-methodology.md`, `docs/schemas/*.json`
- `tests/unit/test_foundation.py`, `test_repository.py`, `test_supabase.py`,
  `test_toolchain.py`

## Files Changed
- `src/emo_cyber_agent/core/correlation.py` (NEW, ~450 lines): trust,
  relations, observations, candidates, conflicts, asset graph, context,
  reasoner-port interface, 4 versioned rules, deterministic confidence,
  store, engine.
- `tests/unit/test_correlation.py` (NEW): 29 offline tests.
- (No MCP/CLI/API/schema/domain-model changes; no reasoning code.)

## Schemas
Strategy per task §23: Domain model = source of truth; JSON schema =
serialized contract — direction NOT reversed. New objects
(SecurityObservation/FindingCandidate/EvidenceRelation/EvidenceContext)
are INTERNAL to Core in this phase (not yet public contracts), so NO new
schema files were introduced and none duplicated. Existing 4 schemas
validate 4/4 OK.

## Tests
`pytest tests/ -p no:warnings` → **126 passed, 3 skipped**
(97 prior + 29 new; skips are pre-existing optional real-tool probes).
New coverage: store add/get/list/query + isolation, identity stability +
audit binding, trust inequality, dedup (same/dupes/revision/cross-audit),
8 fixtures incl. cross-source R1 (GitHub file + Supabase table + scanner
authz → authorization observation/candidate), R2/R3/R4, no-evidence DENY
(observation + candidate constructors), confidence determinism table,
conflict→NEEDS_VERIFICATION (not finding), contradictory tools, temporal
bounds, asset graph + typed/scoped relations, side-effect scan, model
authority (signature + abstractness), injection battery (4 texts + SQL
comment + co-location), cross-audit split denial + context cross-read
denial, cross-project non-merge, minimal redacted context, secret handling
(record vs model-safe path), lifecycle + promotion contract, taxonomy
size, rule explicitness/versioning.

## Security Tests
All in `test_correlation.py`, all offline: no-evidence→no-candidate
(constructor + engine level), cross-audit correlation denied (split facts
never join; cross-audit context read raises), correlation side-effect scan
(7 banned constructs absent), model authority (no-model constructor +
abstract port), injection battery (texts stay DATA, zero candidates),
malicious SQL-comment evidence, secrets redacted in model-safe context,
cross-project non-merge.

## Fixtures
Deterministic builders (`ev()` + 8 scenario functions): AUTHORIZATION_RISK
(GitHub :84 handler + Supabase table + scanner authz gap),
SQL_INJECTION_CANDIDATE, DEPENDENCY_VULNERABILITY, SECRET_EXPOSURE,
SUPABASE_RLS_RISK, CONFLICTING_EVIDENCE (T1/T2), PROMPT_INJECTION_TEXT (4
texts), CROSS_PROJECT_EVIDENCE. Reproducible (fixed timestamps/digests).

## Invariant Impact
1. Read-only — ENFORCED (store/engine mutate only their own memory).
2. Untrusted content — ENFORCED (injection battery; envelopes preserved).
3. No finding without evidence — ENFORCED STRONGER (constructors + engine deny empties).
4. No destructive action — ENFORCED (no mutating capability exists here).
5. Tool outputs are evidence — ENFORCED (observations wrap items, never raw strings).
6. Uncertainty explicit — ENFORCED (deterministic confidence formula; severity≠confidence).
7. Same contracts — ENFORCED (single engine path; ABC compliance).
8. Provider external — ENFORCED (no provider imports in module).
9. Scanner provenance — ENFORCED (source/version carried into observations).
10. No cross-project reuse — ENFORCED (audit-bound fingerprints/queries/relations/context).
11. Specialist worker — ENFORCED (analysis-only; side-effect scan clean).
12. Host delegates — PROTECTED (service owning workflow unchanged).
No invariant weakened; no new privilege introduced.

## Known Limitations
- Rules are label-based (R1–R4) — real label producers (code analyzers)
  arrive with later phases; current labels come from test/adapters.
- Buckets join on shared asset-id; cross-asset multi-hop reasoning is
  ECA-T009 work.
- Asset graph is structural only (no reachability/taint analysis).
- Confidence weights (0.2/source, 0.1 bulk, −0.3 conflict) are documented
  heuristics, deterministic and versioned with the rules.

## Deferred Reasoning
Per task §24: no LLM reasoning, no autonomous tool selection, no exploit
execution, no remediation, no final confirmation. Output of this phase is
Evidence + Relationships + SecurityObservations + FindingCandidates only.

## Evidence
- `pytest tests/ -p no:warnings` → `126 passed, 3 skipped in 0.50s`.
- `validate_schemas.py` → 4/4 OK. `compileall` → OK.
- Source scan of `core/correlation.py` body: Finding(/subprocess/os.system/
  urllib/socket/evaluate_policy(/PolicyEngine( all absent (asserted in-test too).
- 29/29 new tests green; 8 fixtures reproducible.
- Files: `core/correlation.py`, `tests/unit/test_correlation.py`.

## Final Status
**PASS** — all 21 exit criteria met: central Core store, audit isolation,
provenance, trust model, typed relations, deterministic correlation,
dedup, conflicts, observations, candidates, evidence-mandatory,
cross-source correlation, temporal context, asset relations, no side
effects, no model authority, injection defense, redacted secrets,
comprehensive tests, prior suites + schemas green. No BLOCKED condition
(no leakage, no evidenceless candidate, no model authority, no policy
modification, no external effect) observed. ECA-T009 (Security Reasoner
loop) may proceed — and is NOT started here.
