# POST-RC-009 — Threat Modeling & Attack Surface Security Assessment

## Objective
Give EMO an auditable, snapshot-bound security representation of
a system — model, surface, boundaries, hypotheses, controls,
verification handoffs — built from Code Intelligence facts and
change signals, with zero Finding, severity, confirmation, or
execution authority.

## Scope
In scope: `threat_modeling/` layer (13 modules), multi-method
abstraction (STRIDE + attack-tree + data-centric, extensible),
deterministic STRIDE elicitation, bounded attack paths,
control observation without effectiveness claims, snapshot
delta, allowlisted surface queries, service orchestration, 3
schemas, starter template + 2 trusted official templates, 54
offline tests. Out of scope (deferred): exploit execution, DAST,
ZAP/Burp, daemons, risk scoring, remediation, approval flows,
model confirmation, collaboration storage.

## Architecture
Repository/CodeIntel facts → SystemModel (DFD-like, vendor-free)
→ AttackSurface (independent, queryable) → method elicitation →
ThreatScenarios (hypotheses) → AttackPaths (bounded) →
Controls (observed/expected) → Mitigations (planning info) →
VerificationHandoffs (VerificationService only) → Evidence →
report projection. Change predicates (POST-RC-008) re-trigger
targeted refresh. Every stage is read-only and deterministic.

## Boundaries (enforced, tested)
No tool execution (no executor imports; AST-scanned), no direct
Repository/Git/Supabase adapter contact (graphs and declarations
only), no Findings (no Finding imports; no finding_id anywhere),
no confirmation (verdict vocabulary rejected at builders),
no severity, no permissions/capabilities granted, no PolicyEngine
bypass (no policy calls — planning only), hypotheses never become
vulnerabilities, graph paths never presented as executable
(application code asserts the disclaimer on every path), no
model-specific code, no executable threat DSL (fixed query
dispatch; unknown names rejected).

## Contracts
Frozen, extra-forbidden, audit/project/snapshot-bound models
with deterministic digests (wall-clock excluded from identity):
system actors/components/assets/stores/processes/flows/
boundaries/entries/exits, 11-category surface elements with
evidence/provenance/coverage, 6-kind boundaries with basis +
provenance rules, scenarios with the 14 required fields,
3-class paths, 11-kind controls with 3 statuses, mitigations,
handoffs, assessment, coverage, delta, template configs.
Free-form privilege/execution fields are unrepresentable.

## System Model & DFD
Actor → entry → component/process → flows → stores/services →
exits, derived from codeintel endpoints/symbols/sources/sinks/
relations plus declared assets/actors. Boundaries are OBSERVED
from facts, DECLARED/INFERRED only with provenance, UNKNOWN
otherwise — never guessed from filenames (a route-path
false-positive found during development forced decorator-line
restriction in the reference provider's sibling work; the same
discipline is encoded here as the provenance rule). Cross-audit
graphs rejected; empty models labeled NOT_ANALYZED with
limitations.

## Attack Surface & Completeness
11 categories emitted only with backing evidence (SECRET_ACCESS
omitted without secret evidence, with a written limitation).
Completeness is contractual: no graph → UNKNOWN (never NONE);
truncated graph → PARTIALLY_MAPPED with the explicit rule that
partial mapping is never complete mapping; analyzed-but-empty
with routes capability → NONE_OBSERVED; otherwise FULLY_MAPPED.
An AUTHORIZATION surface element never claims an authorization
vulnerability (asserted).

## Methods & STRIDE
Methods are lenses: STRIDE (6 rules over entries/flows),
ATTACK_TREE (goal decomposition per entry), DATA_CENTRIC
(source→sink tracing). Registry accepts LINDDUN/PASTA/
CAPEC/MITRE/custom through one function; Core holds no
`method == STRIDE` assumption (unknown methods rejected at
build). STRIDE emits per-element candidates with evidence
requirements and limitations — classification never yields
severity, priority, or confirmation.

## Scenarios, Paths, Controls
Scenarios start HYPOTHESIZED, rise to SUPPORTED_BY_EVIDENCE only
with attached evidence, and can never become CONFIRMED/
CRITICAL/EXPLOITABLE/FIXED inside this layer (vocabulary
rejected at construction). Paths are BFS-bounded (count/length
caps, explicit partial flags) over existing call edges to
DB-linked code: POSSIBLE by structure, SUPPORTED with evidence,
VERIFIED only with caller-supplied verification evidence.
Controls observed from boundary facts (presence only) or
expected from category mapping; effectiveness undecided by
design, with threat→controls→evidence/verification tables.

## Delta & Queries
Snapshot deltas use 10 presence kinds; REMOVED_SCENARIO carries
an explicit never-resolved-vulnerability note, and lifecycle
confusion is structurally impossible (no Finding imports, no
RESOLVED state exists here). Ten allowlisted surface queries,
audit-bound, provenance-recorded, deterministic; anything else
rejected — there is no query language to inject into.

## Change & Skill/Tool Integration
RC-008 predicates map deterministically to method refresh
(dependency change → attack-tree; boundary change → STRIDE);
refresh is re-elicitation with a recorded trigger, never a
verdict. Skills select methods without creating models
(authorization → STRIDE+attack-tree). Tool observations attach
as scenario evidence (labels stay data; ERROR never becomes
confirmation). Four end-to-end workflows green: web app via the
reference provider (real routes→entries→STRIDE), Next.js/API/DB
via Supabase facts (disclosure hypotheses, never confirmations),
change-aware refresh with delta, dependency change with
method switch.

## Adversarial Results
Battery (all contained): cross-audit/project/snapshot
rejections; query/method injection rejected; malicious actor/
asset metadata stored inert with zero authority shift; prompt
injection in source never enters the model; skip-verification
suggestions change nothing (handoffs deterministic from
scenarios); fake boundaries/controls rejected or marked
unverified; paths carry non-proof disclaimers; partial/empty
surfaces never read as complete/zero; disappearing scenarios
never resolve findings; scenarios grant no capabilities;
execution surface absent by scan; severity/confirmation
injection rejected at builders; handoffs snapshot-bound with
stale rejection; mitigations contain no apply/commit/deploy;
external URLs rejected as snapshot ids; traversals budget out
explicitly.

## Tests
`test_threat_modeling.py` (19) + `test_attack_surface.py`
(10) + `test_threat_security.py` (25) — 54/54: contracts,
system/DFD, methods registry + custom, STRIDE per-category
elicitation, scenario purity + status promotion rules,
bounded/cross-audit paths, control observation, delta
semantics, determinism (wall-clock excluded from digests),
evidence/handoffs/report, trusted templates, all 3 schemas,
surface linkage/completeness/secrets-gating, query
allowlist/binding/determinism, isolation battery, injection
battery, fake-trust battery, coverage honesty, E2E ×4,
zero-Findings proof. Full suite: 613 passed, 3 skipped.
Schemas 17/17 valid. Testing caught real defects: ID-length
overflows (fixed via length-safe stable IDs), timestamp
leakage into digests, field-order validation gaps, route-path
false positives, over-strict emptiness rules.

## Files Inspected
- `code_intelligence/{spec,graph,service}` + mock/reference
providers (fact substrate, reused unchanged)
- `change_analysis/{diff,predicates,spec}` (predicate vocabulary
and comparison semantics consumed as triggers)
- `skills/packs/*` (skill ids + resolver patterns for method
selection), `core/verification.py` (method vocabulary),
`domain/models.py` (EvidenceItem), `core/repository.py`
(redaction), `docs/schemas/*.json` (conventions)

## Files Changed
- `src/emo_cyber_agent/threat_modeling/{__init__,spec,errors,provenance,system_model,attack_surface,methods,stride,threats,paths,controls,delta,queries,service}.py` (NEW, 14 modules)
- `docs/schemas/threat-model.schema.json`,
`attack-surface.schema.json`, `threat-scenario.schema.json` (NEW)
- `templates/threat-modeling/THREAT-MODEL-TEMPLATE.yaml` +
`official/*.yaml` ×2 (NEW, trusted/schema-checked/digest-stable)
- `tests/unit/test_threat_modeling.py` (19) +
`test_attack_surface.py` (10) + `test_threat_security.py`
(25) + `tests/fixtures/threat_modeling/*` (NEW)
- (No Core/codeintel/change/skills/MCP/CLI/reporting/Finding changes.)

## Invariant Impact
All 12 PASS: 1 read-only (no execution surface), 2 untrusted
content (repo/commit/tool/model text quarantined as data), 3
evidence-gated (scenarios without evidence stay HYPOTHESIZED;
INSUFFICIENT_EVIDENCE expressible), 4 no destructive
transition (no grant/execute/remediate surface), 5 tool
outputs as evidence (labels stay data), 6 explicit
uncertainty (hypothesis/path/coverage states everywhere), 7
shared contracts (schemas + frozen models), 8 external
provider choice (fact suppliers swappable), 9 scanners
authoritative (untouched), 10 human review (handoffs require
confirmation, never auto-confirm), 11 specialist worker
(representations only), 12 host delegates (service owns
workflow).

## Known Limitations
- Reference-provider route discovery bounds entry completeness
(pattern-level frameworks only).
- DOS elicitation is precondition-only (no perf facts exist).
- Data-centric method traces declared flows, not full taint
semantics (taint detail lives in POST-RC-005).
- Delta compares records, not semantic equivalence.
- No MCP/CLI surface by design; no collaboration storage.

## Deferred Work
Exploit/DAST/ZAP-Burp execution, daemons, risk scoring,
remediation, approval workflows, model confirmation,
collaboration storage — each in its dedicated stage.

## Evidence
- `pytest tests/unit/test_threat_modeling.py tests/unit/test_attack_surface.py tests/unit/test_threat_security.py` → 54 passed.
- Full suite → 613 passed, 3 skipped. Schemas 17/17 valid.
- 2/2 official templates trusted, schema-checked, digest-stable.
- Four E2E workflows green with zero Findings.
- Files listed above.

## Final Status
**PASS** — threat modeling complete: snapshot-bound system
models, honest attack surfaces, explicit trust boundaries,
pluggable deterministic methodologies, hypothesis-grade
scenarios, bounded non-proof paths, unevaluated controls,
snapshot deltas, allowlisted queries, snapshot-bound
verification handoffs, redacted evidence, report-safe
projections, adversarial battery contained, all tests green.
EMO represents, hypothesizes, and hands off — authority stays
downstream with proof.
