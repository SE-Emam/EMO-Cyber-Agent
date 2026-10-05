# POST-RC-008 — Change-Aware Review Security Assessment

## Objective
Give EMO change awareness without continuous monitoring: two
trusted snapshots in, deterministic change facts out — what
changed, what it touches through existing code relations, which
predicates fired, and a constrained targeted-review plan. Facts,
never verdicts; planning, never execution.

## Scope
In scope: `change_analysis/` layer (spec/errors/diff/predicates/
impact/planner/service/provenance), snapshot comparison with
region precision, 12 predicates, bounded propagation, impact
model, review planner (3 modes), baseline comparison, evidence
with redacted provenance, report projection, 2 schemas, 47
offline tests. Out of scope (deferred): webhooks, watchers, CI
triggers, daemons, remediation, PR changes, auto-merge, exploit
runners, model prioritization, memory systems.

## Architecture
Previous Snapshot → Change Set → Security Impact → Targeted
Re-analysis plan → Evidence → Correlation → Verification handoff.
The layer consumes normalized snapshots (file maps from
Repository facts, graphs from Code Intelligence) and never shells
git, schedules, or remediates. Authority stays downstream:
Task/Playbook constraints + PolicyEngine + VerificationService.

## Boundaries (enforced, tested)
No capability grants, no git/process execution (source-scanned:
no subprocess/os/sys/shutil/git imports; no checkout/reset/merge/
push/pull/patch tokens), no Findings (no Finding imports; outputs
carry no finding_id), no severity/confirmation (verdict
vocabulary rejected at the evidence builder), no PolicyEngine
bypass (no policy calls at all — planning only), changed code is
never called insecure, unchanged code never called safe (the word
"safe" appears nowhere in outputs), no impact without
provenance/evidence, no model logic.

## Contracts
Frozen, extra-forbidden, audit/project/snapshot-bound:
`ComparisonSnapshot`, `ChangeSet` (with required identity block:
audit/project/base/target ids + revisions + provenance +
digest + coverage + limitations), `ChangedFile/Region/Symbol/
Route/Dependency/DatabaseRelation`, `ChangeClassification`,
`SecurityImpact`, `AffectedSurface`, `VerificationHandoff`
(target-snapshot-bound with compatibility list),
`ChangeReviewPlan`, `BaselineSecurityObservation`,
`ChangeReportView`. Deterministic digests exclude wall-clock
timestamps by construction.

## Snapshot Comparison
Identity-bound (cross-audit → CROSS_AUDIT, cross-project →
CROSS_PROJECT, identical ids → INVALID). Seven distinguishable
states; UNKNOWN for binary/uncomparable content (never
UNChanged); digest-paired RENAMED vs MOVED; region precision via
deterministic hunk grouping with per-file caps (excess →
whole-file region + limitation); generated/vendor flagged.
Content digests participate in the change digest, so same-shape
tampering is evident, never silent.

## Classification & Predicates
Closed 16-class taxonomy from deterministic path/symbol rules
(MODIFIED-defaults to CODE_BEHAVIOR, unmatched add/remove to
UNKNOWN). Twelve predicates evaluated from changeset + graphs —
auth boundaries, state-change additions, external inputs, sinks,
new/modified taint paths, permission changes, dependency
versions, secret handling, file access, database access, config
changes — each returning evidence references. All are signals:
NEW_TAINT_PATH requests injection-pack review, it does not
create a finding.

## Propagation & Impact
BFS over existing call/dataflow/taint relations from changed
symbols, extended to endpoints, boundaries, database objects,
and dependency consumers. Hop/node budgets with explicit
partial-coverage reporting and explainable trails. Impact carries
domains, assets, routes, symbols, tools (derived from real skill
specs), skills, surface, evidence ids, structural-facts-only
context, coverage, limitations, and predicate reason codes —
never verdict vocabulary (scanned).

## Planning & Baselines
`ChangeReviewPlan` is planning-only: real skill/pack/task ids
selected deterministically (packs via skill overlap against the
official RC-006 registry), codeintel caps, tools, evidence
names, snapshot-bound verification handoffs, and an explicit
coverage contract per mode — TARGETED disclaims project-wide
completeness in writing. Baselines compare observation digests
(NEW/PERSISTING/REMOVED/CHANGED/UNRESOLVED/INDETERMINATE);
REMOVED describes snapshot presence and the RESOLVED string is
rejected at construction — baseline states can never be confused
with Finding lifecycle.

## Verification Interaction
Predicates map to handoff methods (database changes →
read_only_query, config → configuration_confirmation, rest →
static_confirmation). Handoffs execute nothing and carry
compatibility lists; `check_handoff` rejects reuse against any
other snapshot (VERIFICATION_STALE). Stale base/target snapshots
rejected at review entry.

## Evidence & Reports
One EvidenceItem per changed file (redacted path/state/
classification summaries) plus one impact record, each with
full audit/project/snapshot/digest/coverage provenance.
Commit messages have no ingestion channel; diff content never
enters summaries (injection payloads proven absent); secret
material redacted. Report projection adds revisions, files,
domains, mode, coverage, limitations, checks, evidence refs,
and handoff ids — Finding/report semantics untouched.

## Adversarial Results
Battery (all contained): cross-audit/project/snapshot
rejections; tamper-evident digests; graph files absent from
snapshots ignored (no phantoms); deterministic rename pairing;
binary/vendor/partial/incomplete handling with labeled gaps;
budget exhaustion flagged; malicious commit/source/diff text
inert (no channel, no echo, no authority shift); fake
"CONFIRMED/fixed/safe" annotations inert; write-operation
surface absent by scan; plan carries no grant fields and only
references registered tasks; targeted-completeness disclaimers
explicit; unchanged≠safe and partial≠complete asserted;
zero Findings produced; error codes stable.

## Skill / Tool Integration
Auth-code change → authentication skill, auth pack, semgrep-class
tooling surface, static_confirmation handoff, evidence — proven
end-to-end on fixtures. Dependency bump → dependency skills +
dependency-supply-chain pack + dependency-audit task, evidence —
proven end-to-end. Tool packs and Code Intelligence consumed
through existing contracts only.

## Tests
`test_change_analysis.py` (25) + `test_change_security.py`
(22) — 47/47: contracts, states, renames, binaries, regions,
symbol/route/dependency/database linking, all predicates,
taint new-vs-modified, bounded propagation, impact honesty,
three plan modes, pack/task selection, baselines, evidence
redaction, report purity, schema validation, determinism,
two realistic workflows, isolation battery, coverage honesty,
surface scans. Full suite: 559 passed, 3 skipped. Schemas
14/14 valid. Testing caught real defects: missing content
digests in the change digest, over-broad token scans, and
docstring self-matches.

## Files Inspected
- `core/repository.py` (normalize_path/redact/RepositoryPort —
reused, never extended with write ops), `core/policy.py`,
`core/execution.py` (boundaries preserved, untouched)
- `code_intelligence/graph.py`, `queries.py`, `service.py`,
`spec.py` (propagation substrate + model shapes)
- `core/verification.py` (method vocabulary),
`domain/models.py` (EvidenceItem), `skills/packs/*`,
`tasks/library.py` (real ids for selection tables)
- `docs/schemas/*.json` (conventions)

## Files Changed
- `src/emo_cyber_agent/change_analysis/{__init__,spec,errors,diff,predicates,impact,planner,service,provenance}.py` (NEW)
- `docs/schemas/change-set.schema.json`,
`docs/schemas/change-review-plan.schema.json` (NEW)
- `tests/unit/test_change_analysis.py` (NEW, 25 tests) +
`tests/unit/test_change_security.py` (NEW, 22 tests) +
`tests/fixtures/change_analysis/*` ×8 (NEW)
- (No Core/repository/codeintel/verification/skills/tasks/MCP/CLI/reporting changes.)

## Invariant Impact
All 12 PASS: 1 read-only (no write surface exists), 2
untrusted content (diff/commit/source quarantined as data),
3 evidence-gated (every fact carries provenance), 4 no
destructive transition (no grant/execute surface), 5 tool
outputs as evidence (normalized + provenanced), 6 explicit
uncertainty (UNKNOWN/PARTIAL/gaps/limitations everywhere), 7
shared contracts (schemas + frozen models), 8 external
provider choice (snapshot/graph suppliers swappable), 9
scanners authoritative (untouched), 10 human review (handoffs
require confirmation, never auto-confirm), 11 specialist
worker (facts only), 12 host delegates (service owns workflow).

## Known Limitations
- Dependency linking needs codeintel dep edges; manifest-only
changes without graphs classify correctly but link nothing
(recorded limitation, not silent).
- Rename pairing is greedy by digest (deterministic; ambiguous
multi-matches documented).
- Region precision is line-hunk based, not AST-aware.
- Baseline comparison is digest-based, not semantic.
- No snapshot store (callers hold snapshots); no MCP/CLI
surface by design.

## Deferred Work
Webhooks, watchers, CI triggers, daemons, remediation, PR
automation, auto-merge, exploit runners, model
prioritization, memory systems — each in its dedicated stage.

## Evidence
- `pytest tests/unit/test_change_analysis.py tests/unit/test_change_security.py` → 47 passed.
- Full suite → 559 passed, 3 skipped. Schemas 14/14 valid.
- Auth + dependency workflows green end-to-end with plans,
handoffs, and evidence.
- Files listed above.

## Final Status
**PASS** — change-aware review complete: immutable
deterministic ChangeSets, identity-bound comparison with
honest UNKNOWN handling, region-precise security-surface
linking, 12 deterministic predicates, bounded propagation
with partial coverage, evidence-bound impact, planning-only
review plans with snapshot-bound verification handoffs,
baseline observation separation, adversarial battery
contained, all tests green. EMO explains what changed and
what to re-examine — verdicts stay downstream with proof.
