# ECA-T011 — Finding Lifecycle & Security Classification

## Objective
Finalize the Finding domain lifecycle inside Core: a FindingCandidate
becomes a report-eligible Security Finding ONLY through evidence,
verification, eligibility, and explicit lifecycle transitions — with
auditable severity/confidence classification. The full chain holds:
Evidence → Observation → Hypothesis → FindingCandidate → Verification →
Finding. No shortcut exists in code.

## Scope
In scope: SecurityFinding domain (22 fields), 11-state lifecycle,
deterministic eligibility (ELIGIBLE/NOT_ELIGIBLE/NEEDS_REVIEW),
severity+confidence models (independent), 16-class taxonomy, sparse
CWE/OWASP maps (unknown→null), CVSS pass-through only, deterministic
fingerprints + regression keys, audit-scoped dedup store, root-cause/
impact separation, structured remediation (data only), suppression
(non-model actors only), DUPLICATE/REFUTED/RESOLVED/SUPPRESSED
distinctions, provenance chain, 6-point material-finding invariant,
model-suggestion sandbox, classification engine + conflicts,
reportability contract, snapshots, 10 fixtures, 27 offline tests.
Out of scope (deferred): report rendering (ECA-T012), remediation
execution, exploit expansion, final-Finding builders beyond promotion.

## Finding Model
`SecurityFinding` (frozen): finding/audit/asset ids, title, description,
category, severity, confidence, status, CWE/OWASP (nullable), affected
locations, evidence/observation/candidate/verification id sets, first/last
seen, provenance, structured remediation, references, suppression record,
observed_issue/root_cause/impact (`UNASSESSED` default — never invented)/
attack_precondition, fingerprint, regression_key. No field bypasses the
lifecycle (status changes only via `transition_to`).

## Lifecycle
CANDIDATE → TRIAGED → VERIFIED → CONFIRMED → REPORTED → RESOLVED, plus
DISPUTED (↔TRIAGED/VERIFIED/INCONCLUSIVE), REFUTED/DUPLICATE/INCONCLUSIVE
(terminals with defined re-entry), SUPPRESSED (↔TRIAGED). Denied paths
test-pinned: CANDIDATE→CONFIRMED, CANDIDATE→REPORTED, RESOLVED→REFUTED.
REFUTED (claim disproved) ≠ RESOLVED (real issue fixed + proven).

## Eligibility
`evaluate_finding_eligibility` (deterministic, no LLM): checks evidence
count, provenance validity, scope match, verification state
(confirmed/supported only), contradiction state, candidate pre-state,
policy allowance → ELIGIBLE / NOT_ELIGIBLE / NEEDS_REVIEW (review only
for the lone unverified-candidate case) with reason codes.

## Severity
INFO/LOW/MEDIUM/HIGH/CRITICAL via `SeverityAssessment{severity, basis,
source, rule_version, assessed_at}`. Model can never force severity:
`apply_model_suggestion` rejects severity/status/evidence/scope/fingerprint
keys. Downgrade rule (unanimous-lower scanner + supported-only →
one level, reasoned) and conflict rule (kept, needs review) are explicit.

## Confidence
Float 0–1, independent of severity (HIGH severity + LOW confidence is
representable and tested). Inputs: evidence quality/count, provenance,
independent sources, verification strength, contradiction — via the
ECA-T008 formula + confirmation boost, capped. Never model self-scores.

## Taxonomy
16 classes (AUTHENTICATION … SESSION, INPUT_VALIDATION, OTHER). Labels
classify; they never prove (test asserts mapping ≠ verdict).

## CWE
Sparse static map (`cls-v1` provenance): R1→CWE-639, R3→CWE-798, all
else null. Unknown is null/unspecified — never invented to complete a
report (test-pinned). Derived mappings record their source.

## OWASP
Sparse map (R1→A01:2021, R3→A07:2021, else null). Labels are not proof
(the CWE-639/authorization example from the task is honored as mapping
only).

## CVSS
Pass-through metadata only (`cvss_vector/score/source` from trusted
scanner input); never required here; never model-computed; never moves
final severity (test-pinned: 9.1 CVSS beside HIGH stays HIGH by rule).

## Identity
`finding_fingerprint` over audit+asset+category+location+vuln-identity+
rule (description text alone never suffices). `regression_key` omits the
audit for cross-audit history comparison — links history, merges nothing,
carries no evidence.

## Deduplication
`FindingStore.add`: same fingerprint + same audit → original stays
canonical, newcomer recorded DUPLICATE with `duplicate_of` pointer (never
merged). Different locations/root causes naturally fingerprint apart.
Different audits never merge (audit-bound fingerprint + scoped store).

## Root Cause
`observed_issue` vs `root_cause` vs `impact` vs `attack_precondition` are
separate fields; impact defaults UNASSESSED and is never invented.

## Impact
Covered above; unknown stays UNASSESSED/UNKNOWN by construction.

## Remediation
Structured DATA only (`recommendation/affected_component/
remediation_type/validation_guidance`); zero execution surface in the
module (subprocess-free, test-pinned).

## Suppression
`SuppressionRecord(reason/actor/timestamp/scope/expiry)`; actor allow-list
excludes model/llm/reasoner/ai (constructor-denied, test-pinned).

## Provenance
Every finding carries candidate/observation/evidence/verification ids,
assessment sources, and classification/policy/schema versions — a full
Finding → Verification → Evidence → Invocation → Source walk.

## Model Boundary
Reasoner may suggest title/description/remediation/references/CWE/OWASP
(only when Core hasn't set the latter); everything lands as
`model_suggestion: unverified` annotations. Severity/status/evidence/
scope/fingerprint/CWE-override are immutable through this path
(all rejection branches tested).

## Classification
`classify_candidate` (rules `cls-v1`): taxonomy map, provisional-based
severity with documented downgrade, graph-grounded confidence, sparse
CWE/OWASP, CVSS pass-through, full `explained` string (severity + basis +
evidence + verification + rule). No shell/network; deterministic inputs
only; a future reasoner/specialized-model backend can sit behind the
same contract without touching Core.

## Conflicts
Scanner-vs-scanner severity splits → `ClassificationConflict` (assessments
kept) + provisional retained + NEEDS_REVIEW posture; verification-level
SUPPORTED+REFUTED → INCONCLUSIVE via ECA-T010 assessment (reused, not
reimplemented).

## Reportability
`is_reportable` denies: missing evidence, empty provenance, missing scope,
non-CONFIRMED/REPORTED status, empty fingerprint — with reason lists for
the future reporting engine to consume.

## Schemas
Deliberate decision, recorded: `docs/schemas/finding.schema.json`
UNCHANGED. Rationale: the new `SecurityFinding` is an internal Core
contract in this phase; the existing schema still describes the legacy
`Finding` model, and nothing validates models against schemas at runtime
today. Export contracts (which shape ships in JSON/Markdown) are exactly
ECA-T012's job — inventing a competing schema now would violate the
domain-truths-first rule (§27/§34). Schemas 4/4 valid.

## Tests
`pytest tests/ -p no:warnings` → **215 passed, 3 skipped** (188 prior +
27 new; skips pre-existing optional binary probes). New groups: lifecycle
(skip-denial, full chain, alternative terminals, resolved-vs-refuted),
evidence gates (constructor/store/cross-audit/provenance/matrix),
classification (independence, CWE present/absent, OWASP, CVSS, downgrade,
conflict, explanation), identity/dedup/regression, root-cause/remediation/
suppression, provenance/reportability/snapshot, model boundary (5
rejection classes + foreign-evidence + CWE-override + unverified marking).

## Security Tests
In `test_findings.py`: evidenceless construction/storage/promotion denial,
cross-audit storage + promotion denial, model confirm/suppress/severity/
scope/fingerprint/evidence/CWE-override denials, foreign-evidence
attachment denial. All attacker-reachable shortcuts raise instead of
degrading.

## Fixtures
10 builders: CONFIRMED_AUTHORIZATION, REFUTED_AUTHORIZATION,
UNVERIFIED_SQL_INJECTION, CONFIRMED_DEPENDENCY, RLS_ACCESS_RISK,
SECRET_EXPOSURE, CONFLICTING_CLASSIFICATION, DUPLICATE_SCANNER_RESULTS,
CROSS_AUDIT_ATTEMPT, MODEL_OVERRULE_ATTEMPT. Deterministic (fixed ids/
rules/severities).

## Files Inspected
- `domain/models.py` (legacy Finding — untouched), `core/correlation.py`
  (FindingCandidate — additive statuses only), `core/verification.py`
  (assessment reused), `core/policy.py`, `core/tool_registry.py`,
  `core/execution.py`, `core/scanners.py`, `core/repository.py`,
  `core/supabase.py`, `adapters/*`, `docs/16/02/03`, `docs/schemas/*`
- `tests/unit/test_foundation|repository|supabase|toolchain|reasoning|
  verification.py`

## Files Changed
- `src/emo_cyber_agent/core/findings.py` (NEW, ~470 lines): lifecycle,
  severity/confidence/taxonomy/CWE/OWASP/CVSS, identity/dedup/store,
  eligibility, classification + conflicts, promotion, remediation,
  suppression, provenance, model sandbox, reportability.
- `tests/unit/test_findings.py` (NEW): 27 offline tests.
- (No MCP/CLI/API/schema/legacy-model changes; no remediation execution;
  no exploit code.)

## Invariant Impact
1. Read-only — ENFORCED (no mutating surface).
2. Untrusted content — ENFORCED (no content-to-instruction path).
3. No finding without evidence — ENFORCED STRONGER (3 independent gates).
4. No destructive action — ENFORCED (inexpressible).
5. Tool outputs are evidence — PROTECTED (chain preserved end-to-end).
6. Uncertainty explicit — ENFORCED (severity⊥confidence, both explained).
7. Same contracts — ENFORCED (single promotion path).
8. Provider external — ENFORCED (no provider imports).
9. Scanner provenance — ENFORCED (classification records sources).
10. No cross-project reuse — ENFORCED (audit-bound identity/store/context).
11. Specialist worker — ENFORCED (classification-only module).
12. Host delegates — PROTECTED (reportability is the delegation contract).
No invariant weakened; model-to-Finding direct path provably absent.

## Known Limitations
- `Impact`/`root_cause` are usually UNASSESSED/empty until later analysis
  fills them with evidence (by design, not a gap).
- CWE/OWASP maps cover 2 rules; growth needs curated provenance per entry.
- CVSS has no computation (pass-through only) — scoring policy belongs to
  a later hardening pass if ever needed.
- Cross-audit regression uses key comparison only (no shared evidence).

## Deferred Work
Report rendering (ECA-T012: JSON/JSONL/Markdown from THESE objects with
provenance intact, no security reinterpretation), remediation execution
(never planned as autonomous), verification expansion, regression
diffing across audits.

## Evidence
- `pytest tests/ -p no:warnings` → `215 passed, 3 skipped`.
- `validate_schemas.py` → 4/4 OK. `compileall` → OK.
- Purity: no Finding-construction shortcuts, no shell/subprocess/socket,
  no severity assignment outside classification, no remediation execution.
- Files: `core/findings.py`, `tests/unit/test_findings.py`.

## Final Status
**PASS** — all 22 exit criteria met: domain model, lifecycle (incl.
shortcut denials), eligibility, confirmed/refuted semantics, severity,
confidence, taxonomy, CWE, OWASP, CVSS-metadata, identity, dedup,
provenance, root-cause/impact separation, remediation structure,
suppression semantics, conflict handling, model boundary, reportability,
tests + security tests, prior suites + schemas green. No BLOCKED
condition (no evidenceless finding, no model confirmation, no cross-audit
merge, no classification bypass, no lifecycle skip, no provenance break)
observed. ECA-T012 (Reporting & Export Contracts) may proceed — and is
NOT started here.
