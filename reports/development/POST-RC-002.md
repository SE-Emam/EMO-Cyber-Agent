# POST-RC-002 — Task Template System & Task Resolver

## Objective
Make "task type" a formal, verifiable object: a Task describes WHAT
should be done (scope, skills, capabilities requested, tools,
methodology, evidence, verification, stop conditions, acceptance,
report) without ever deciding WHAT IS ALLOWED. Resolution produces an
immutable snapshot; Core Policy alone authorizes anything downstream.

## Scope
In scope: `TaskSpec` + scope model + `ResolvedTask` snapshot, `TaskScope`
narrowing rule, versioned `TaskRegistry` (register/unregister/get/
resolve/list/validate/versions/dependencies/compatible/cycles),
`TaskValidator` (schema/semver/shape/scope/skills/tools/caps/report-
pending/injection/unsafe-language), `TaskResolver` (skill reuse via
POST-RC-001, tool resolution, advisory capabilities, reasons, suggest
NO_MATCH/AMBIGUOUS), `TaskService.plan()` facade,
`docs/schemas/task.schema.json` v1.0, `templates/tasks/TASK-TEMPLATE.yaml`,
22 official YAML tasks + loader (TRUSTED-by-loader, never self-declared),
20 offline tests.
Out of scope (later tasks): execution engine (uses existing Core),
report templates engine (003), playbooks (004), MCP/CLI task commands.

## Task Domain
`TaskSpec`: id (kebab-case), name, semver version, type
(audit/review/verification_support/threat_model), objective, `TaskScope`
(included/excluded/target_types), inputs, required/optional skills,
required + denied capabilities, required/optional tools, methodology
phases/procedures, evidence + provenance/quality rules, verification
requirements/methods/confirmation/refutation/stop, read-only-first
security constraints, stop conditions, acceptance criteria (result-bias
rejected), deliverables, report template ref, optional `extends`,
provenance. Frozen, extra-forbidden.

## Task Schema
`docs/schemas/task.schema.json` (v1.0, `$id`-versioned): flat contract
shape. Direction honored: YAML authoring → normalize → schema
cross-check → `TaskSpec` (canonical). Pydantic enforces at runtime;
jsonschema cross-checks in tests/dev.

## Task Registry
Version-aware; duplicates rejected; `get` defaults to latest with
explicit-version override; `unregister` refuses while extended;
`dependencies` follows `extends`; `compatible_tasks` by shared skills or
extends edges; `check_cycles` returns deterministic cycle paths.
Trust is assigned by the LOADER (official dir → TRUSTED), never by
registration alone (default UNTRUSTED).

## Task Validator
Shape (id/version/objective/criteria/stops/skills/read-only-first),
unknown skills/tools (no substitutes), high-risk capability requests
(warning, not grant), verification-disabled (warning), injection +
unsafe-language scan (quarantine to UNTRUSTED), result-bias in acceptance
(error), report-template refs (shape-checked, pending-flagged until
POST-RC-003), `extends` existence left to resolve-time with cycle check.
12 stable `TaskErrorCode`s.

## Task Resolver
`resolve(spec, files, objective, audit_scope, skill_versions)`:
scope-narrowing enforced (wider-than-audit → SCOPE_INVALID, never
intersection-widening); skills via POST-RC-001 `SkillResolver` (required
must ALL match or SKILL_MISSING — fail-closed, no substitutes; optional
skipped with reasons); tools resolved against the wired registry
(required missing → TOOL_MISSING); capabilities UNIONED as advisory with
an explicit `capabilities-advisory-only` warning; `extends` recorded;
snapshot frozen with task/skill/tool/report/policy versions + timestamp.
`suggest()` over candidates: 0 → NO_MATCH, tie → AMBIGUOUS, else best —
never an undocumented preference.

## Skill Integration
POST-RC-001 consumed, never reimplemented: same resolver instance
pattern, same trigger table, version overrides supported per call.
Proven by the mandated end state below.

## Tool Integration
Tool names resolve against an injected ToolRegistry; versions snapshotted
into the resolution. Unregistered required tools fail; optional ones
skip with reasons. No subprocess/model/shell anywhere in this package
(source-scanned in-test).

## Capability Semantics
`requested ≠ authorized`, enforced structurally: the resolver OUTPUTS
strings; only `PolicyEngine.issue_decision` can ALLOW, and the service
never calls it (planning phase). Denied-capabilities ride along as extra
constraints; Core policy always dominates (documented + tested via strict
engine denial of write/admin caps).

## Scope Semantics
`TaskScope.narrowed_by`: task target_types ⊆ audit target_types AND task
included ⊆ audit included (empty audit lists mean unconstrained, task
lists then stand). Child/extends flows inherit the same check at resolve
time; parent constraints dominate by construction.

## Composition
`extends` chains validated (missing parent → resolve-time error, cycles
→ cycle paths); narrowing-only rule stated and partially enforced
(scope check); full constraint-inheritance auditing arrives with usage.
No child may broaden scope/caps/safety — the resolver has no path that
widens anything (additive-only merges).

## Trust
TRUSTED = loader-assigned official only (self-declared "official"
provenance triggers a warning + UNTRUSTED — tested). UNTRUSTED =
validated but external/injection-flagged/high-risk. INVALID = structural
failure, registration refused. Trust never equals authority.

## Snapshot
`ResolvedTask` frozen with task/skill/tool/report/policy versions +
timestamp; registry mutation after resolution cannot alter in-flight
snapshots (test mutates registry post-resolve and re-asserts equality).

## Versioning
Independent semver everywhere (task, skill, tool, report-template
placeholder, policy). `get` defaults to latest; explicit pins honored
and snapshotted.

## Security
Malicious battery: write/destructive caps (quarantined, policy-denies),
ghost skills/tools (errors), result-bias acceptance (error), injected
objective/methodology (UNTRUSTED, still usable-as-data), scope expansion
(SCOPE_INVALID), forced confirmation (bias error), cross-audit reuse
(independent snapshots, no shared state), prompt-in-text (data only).
No execution surface exists to attack (scan-pinned).

## Prompt Injection
Task text fields are data: injection patterns quarantine trust but never
grant, never execute, never alter policy. The resolver treats matched
signals identically regardless of payload wording.

## Tests
`pytest tests/unit/test_tasks.py` — 20/20: schema/versioning, template
parse+validate, 22-file official library (ids/trust/acyclic/schema-
checked), registry CRUD/guards/cycles/compat, validator batteries,
end-state resolution (mandated skills/caps/evidence/verification/report
all asserted), narrowing + widening denial, composition, snapshot
immutability, suggest NO_MATCH/AMBIGUOUS, malicious battery, injection,
cross-audit isolation, no-execution-surface scan, error-code stability.
Full suite: 370 passed, 3 skipped. Schemas 7/7 valid.

## Fixtures
Official YAML library (22) + inline malicious variants (escalation,
ghosts, bias, injection, expansion, forced confirmation, cycles) +
`templates/tasks/examples/example-quick-review.yaml`. Deterministic.

## Schemas
`docs/schemas/task.schema.json` NEW (v1.0); every official YAML
cross-validated against it in-test. Domain → serialization → schema
direction kept.

## Files Inspected
- `skills/*` (spec/registry/resolver/catalog — reused)
- `core/tool_registry.py`, `core/policy.py`, `core/correlation.py`
  (FindingCandidate statuses referenced)
- `docs/schemas/*.json` (conventions), `templates/` (new),
  `docs/16-implementation-plan.md`
- `tests/unit/test_skills.py` (integration surface)

## Files Changed
- `src/emo_cyber_agent/tasks/{spec,registry,validator,resolver,service,__init__,library}.py` (NEW)
- `docs/schemas/task.schema.json` (NEW)
- `templates/tasks/TASK-TEMPLATE.yaml` + `official/*.yaml` ×22 + `examples/*.yaml` (NEW)
- `tests/unit/test_tasks.py` (NEW, 20 tests)
- (No Core/skills/adapters/CLI/MCP changes; no execution code.)

## Invariant Impact
1, 7, 11, 12 preserved structurally (read-only tasks, same contracts,
no cross-audit state, read-only defaults); 2, 5 enforced via quarantine
as-data; 3, 4, 6, 8, 9, 10 untouched (no evidence/finding/model/provider/
scanner paths added).

## Known Limitations
- Report template refs are shape-checked + pending-flagged (engine in 003).
- `suggest()` scoring is keyword-overlap heuristic, deterministic and
  documented — not a ranking model.
- Composition inheritance auditing (constraint diffing) is minimal;
  narrowing is enforced, full diff reports deferred to usage.
- No task execution yet by design (uses existing Core when wired).

## Deferred Execution
Deliberate: planning only. Execution reuses ReasoningEngine +
ToolExecutor + VerificationService + ReportService unchanged.

## Evidence
- `pytest tests/unit/test_tasks.py -p no:warnings` → 20 passed.
- Full suite → 370 passed, 3 skipped. Schemas 7/7 valid.
- Desired end state reproduced verbatim in-test (task, version, 5+
  skills, 3+ caps, evidence list, verification methods, report ref).
- Files listed above.

## Final Status
**PASS** — contract + resolution complete: TaskSpec, schema, registry,
validator, resolver (skill-integrated), service facade, 22/22 official
tasks trusted and acyclic, malicious battery contained, snapshots
immutable, no execution surface, all tests green. POST-RC-003 (Report
Template Engine) may proceed — consuming `report_template` refs defined here.
