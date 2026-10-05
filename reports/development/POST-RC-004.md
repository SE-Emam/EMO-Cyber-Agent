# POST-RC-004 — Security Playbook System

## Objective
Make "security workflow" a formal, verifiable object: a Playbook
composes Task references + skill/tool requests + evidence and
verification plans + report template ref + stop rules into an ordered,
conditional, budgeted execution plan. It coordinates existing systems
and authorizes nothing — Core Policy alone decides what runs.

## Scope
In scope: `PlaybookSpec` + condition/project-context models,
`PlaybookPlan` + `ResolvedPlaybook` snapshots + lifecycle,
versioned `PlaybookRegistry`, `PlaybookValidator`,
`PlaybookResolver` (delegating to Task/Skill/ReportTemplate resolvers
and ToolRegistry), `PlaybookService.plan()` facade with parent
inheritance, `docs/schemas/playbook.schema.json` v1.0,
`templates/playbooks/PLAYBOOK-TEMPLATE.yaml`, 18 official YAML
playbooks + loader (TRUSTED-by-loader), 26 offline tests.
Out of scope (later tasks): execution engine (uses existing Core),
parallel execution (deferred — no concurrency added for optimization),
MCP/CLI playbook commands (service API only), pack distribution.

## Playbook Architecture
Playbook → Validate → Resolve Tasks (TaskResolver) → Resolve Skills
(SkillResolver) → Resolve Tools (ToolRegistry) → Aggregate
Requirements → Safety Rechecks → Snapshot → Core Policy (downstream) →
Execute Task Workflow → Evidence → Verification → Finding → Report
Template. The playbook never crosses a Core boundary: no permits, no
execution, no findings, no verification runs, no report mutation.

## PlaybookSpec
`playbook_id` (kebab-case, min 3), title, semver version, type,
objective, description, `required_tasks`/`optional_tasks` (refs as
`id` or `id@x.y.z`), required/optional skills and tools, requested +
denied capabilities, `execution_order`, declarative `conditions`,
`max_tasks` (1–64) + `max_iterations` (1–8), evidence plan
(required + provenance flag), verification plan (required flag +
methods), `report_template` ref, `stop_conditions`, `acceptance_criteria`
(result-bias rejected), read-only-first security constraints,
optional `extends` + `dependencies`, provenance. Frozen,
extra-forbidden. Task refs inside a playbook are references only —
definitions are never repeated.

## Schema
`docs/schemas/playbook.schema.json` (v1.0, `$id`-versioned): flat
contract shape including the condition object (allowlisted
`when_field`/`operator`) and semver patterns. Direction honored: YAML
authoring → normalize → schema cross-check → `PlaybookSpec`
(canonical). Pydantic enforces at runtime; jsonschema cross-checks in
tests/dev. Every official YAML cross-validated against it in-test.

## Registry
Version-aware; duplicates rejected; `get` defaults to latest with
explicit-version override; `unregister` refuses while extended or
depended on; `dependencies` follows `extends` + `dependencies`;
`check_cycles` returns deterministic cycle paths. Trust assigned by
the LOADER (official dir → TRUSTED), never by registration alone
(default UNTRUSTED). `trust_of` exposes per-version trust.

## Validator
Shape (id/version/objective/criteria/stops/tasks), duplicate tasks
(incl. required∩optional overlap), `execution_order` membership,
required stops (`policy_violation`, `scope_violation`, `task_failure`;
remaining five recommended as warnings), requested∩denied clash,
result-bias in acceptance (error), injection/unsafe-language scan
(quarantine to UNTRUSTED, still usable as data), condition select
membership, reference existence when registries wired (required →
error, optional → warning + skip), read-only compatibility against
real task capabilities (error), fail-closed gates (evidence
provenance, verification required, external targets `deny` — all
errors; read-only disabled — warning). 17 stable `PlaybookErrorCode`s.

## Resolver
`resolve(spec, files, objective, audit_scope, context,
skill_versions)`: conditions evaluated against `ProjectContext`
(unknown/empty → no selection, fail-closed); task set = required +
condition-activated optionals; ordering = `execution_order` then
declaration order (unlisted → warning); budget exceed → BLOCKED;
per-task resolution via owning `TaskResolver` (scope narrowing
enforced there — expansion surfaces as BLOCKED); skills via owning
`SkillResolver` (required must ALL match or BLOCKED); tools via
`ToolRegistry.get` (required missing → BLOCKED, optional → skip);
capabilities UNIONED as advisory with explicit
`capabilities-advisory-only` warning; denied UNIONED (parent
dominates structurally — removal is unrepresentable); read-only
recheck over the union (covers registry drift past validation);
report template snapshot via owning `ReportTemplateResolver`;
`PlaybookPlan` + frozen `ResolvedPlaybook` with digest. No LLM, no
execution, no subprocess/model/shell (AST-scanned in-test).

## Task Integration
POST-RC-002 consumed, never reimplemented: same `TaskResolver`
instance pattern, same scope-narrowing, same skill/tool wiring,
pinned `task_id@version` per task in the snapshot. Proven by the
mandated end state (deep-security-audit resolves to exactly its
three required tasks in order).

## Skill Integration
POST-RC-001 consumed, never reimplemented: `SkillResolver.resolve`
for matching, `required_capabilities` for the advisory union.
Playbook-level required skills gate the workflow (unmatched →
BLOCKED); optional skills skip with reasons.

## Tool Integration
`ToolRegistry.get` is the sole authority for tool existence;
versions snapshotted per tool. Required missing → BLOCKED; optional
missing → skip with warning. No tool is ever invoked from a
playbook (no execution surface exists).

## Report Template Integration
POST-RC-003 consumed: `ReportTemplateResolver.resolve(template_id=…)`
pins `report_template@version` + `report_template_known`. Unknown →
BLOCKED at resolve (INVALID at service validate). Unwired registry →
warning, never silent. Finding semantics untouched — selection only.

## Execution Graph
SEQUENTIAL by `execution_order` + conditional activation of optional
tasks. Parallel execution deliberately deferred (rejected: no
concurrency for optimization while the State model does not need
it). `PlaybookPlan` carries ordered ids, skipped tasks, evaluated
conditions, constraints, expected evidence, stop rules, template.

## Conditions
Declarative only: `when_field ∈ {technology, asset.type,
evidence.category, candidate.status}`, `operator ∈ {==, !=, in,
not-in}`, `value` data, `select_tasks` from declared tasks. Anything
else fails spec construction. Evaluation is set-membership against
`ProjectContext`; empty context selects nothing. Unknown field at
resolve → no selection (never an invented task). Ambiguous safety
impact (e.g. write-requesting selection under read-only) → BLOCKED.

## Budgets
`max_tasks`/`max_iterations` declared per playbook; exceeding
`max_tasks` → BLOCKED (truncation would silently drop coverage).
Core/Reasoning/Tool budgets remain authoritative downstream —
closest/strictest wins by construction (playbook stops at planning).

## Stop Conditions
All eight canonical stops carried by every official playbook
(`policy_violation`, `scope_violation`,
`evidence_integrity_failure`, `security_boundary_break`,
`task_failure`, `budget_exhausted`, `no_progress`,
`unresolved_critical_conflict`). Resolver enforces budget/task-failure
stops at plan time; the rest ride the snapshot into execution.

## Snapshot
`ResolvedPlaybook` frozen with playbook/task/skill/tool/template
versions + digest + timestamp + policy version; registry mutation
after resolution cannot alter in-flight snapshots (proven by the
version-drift test: old pins and digest byte-identical post-bump).
`PlaybookPlan` embedded in the snapshot.

## Trust
TRUSTED = loader-assigned official only (validated + clean +
official provenance). UNTRUSTED = validated but external or
injection-quarantined. INVALID = structural failure. Self-declared
"official" provenance without loader assignment stays UNTRUSTED.
Trust never equals authority.

## Security
Malicious battery (each: reject or constrain): scope expansion →
BLOCKED via task narrowing; capability grant under read-only →
BLOCKED via union recheck; evidence de-provenancing → INVALID;
verification bypass → INVALID; forced findings (result-bias) →
INVALID; shell tool → INVALID (unknown tool); network targets →
INVALID; parent-constraint removal → structurally impossible
(inheritance unions in service); limitation hiding / finding
suppression → unrepresentable (no such fields; extra keys rejected
by frozen models); cross-audit object refs → no audit binding at
plan time, snapshots carry no foreign state (asserted). No
execution surface exists to attack (AST-pinned: no subprocess,
socket, requests, LLM clients, eval/exec).

## Prompt Injection
Playbook text is DATA: objective/description/acceptance/condition
values scanned; matches quarantine trust but never grant, never
execute, never alter policy or capabilities (asserted: payload runs
resolve clean with zero granted writes). Resolution output
identical in shape with or without payload wording.

## Cross-Audit Isolation
Same playbook resolved under two scopes yields independent
snapshots with zero foreign content; a registry version bump
between resolutions leaves the first snapshot untouched. There is
no shared mutable resolution state (fresh resolver state per
call; registries only read).

## Version Drift
Resolve → bump task version → re-resolve: new snapshot pins the
new version with a changed digest; the old snapshot is unchanged.
`get` defaults to latest; explicit `id@version` pins honored and
snapshotted per task.

## Official Playbooks
18/18 TRUSTED, acyclic, schema-valid: `deep-security-audit`
(reference: recon → attack-surface → auth → authz → deps → secrets
→ verification → report), `web-app-deep-audit`,
`api-security-deep-audit`, `authentication-security`,
`authorization-security`, `supabase-security-audit` (conditional
Supabase branch; RLS never a lone verdict),
`database-security-audit`, `dependency-supply-chain-audit`,
`cloud-security-audit`, `container-security-audit`,
`infrastructure-security-audit`, `business-logic-security`
(threats stay hypotheses), `ai-application-security` (app security
only, EMO-internals out of scope), `agent-security`,
`mcp-security-audit` (auditor gains no target privileges),
`pre-release-security`, `changed-code-security` (change→assets→
tasks→verification mapping; full ChangeAnalyzer deferred),
`regression-security`. None is a prompt: every one is a pinned
workflow contract.

## Tests
`pytest tests/unit/test_playbooks.py` — 26/26: spec
ids/versions/refs/condition-gates, schema normalize + cross-check
+ malformed-YAML, 18-file official library (ids/trust/acyclic/
schema/determinism), registry CRUD/guards/cycles/dependencies,
validator shape/stops/duplicates/order/clash, refs + read-only
compat, fail-closed gates, bias + quarantine, deep-audit end state
(tasks/skills/tools/template/plan/lifecycle/denied), conditions
select/skip, unknown-context behavior, safety BLOCKED paths,
task/skill/tool/template integrations, snapshot freeze,
cross-audit isolation, determinism, budgets + lifecycle, malicious
battery (10 attacks), parent-dominance, injection fields (4
payloads), no-execution-surface AST scan, error-code stability.
Full suite: 408 passed, 3 skipped. Schemas 8/8 valid.

## Security Tests
Dedicated: `test_malicious_battery_reject_or_constrain`,
`test_parent_constraints_dominate`,
`test_prompt_injection_fields_stay_data`,
`test_no_execution_surface`, `test_resolver_safety_blocks`,
`test_task_integration_scope_expansion_blocked`,
`test_cross_audit_isolation`. Validator rejects 6/10 attacks at
plan time; resolver BLOCKEDs 3 more; inheritance absorbs the
remainder — zero attacks resolve clean.

## Files Inspected
- `tasks/*` (spec/registry/resolver/service/library — reused)
- `skills/resolver.py` (trigger table — reused), `skills/builtin/catalog.py`
- `report_templates/resolver.py` (template pinning — reused)
- `core/tool_registry.py`, `core/repository.py`, `core/scanners.py`, `core/supabase.py` (tool authority)
- `docs/schemas/*.json` (conventions), `templates/tasks+reports/` (reference shapes)
- `tests/unit/test_tasks.py`, `test_report_templates.py` (integration surfaces)

## Files Changed
- `src/emo_cyber_agent/playbooks/{spec,registry,validator,resolver,service,library,__init__}.py` (NEW)
- `docs/schemas/playbook.schema.json` (NEW)
- `templates/playbooks/PLAYBOOK-TEMPLATE.yaml` + `official/*.yaml` ×18 (NEW)
- `tests/unit/test_playbooks.py` (NEW, 26 tests)
- (No Core/tasks/skills/templates/adapters/CLI/MCP changes.)

## Schemas
`docs/schemas/playbook.schema.json` NEW (v1.0); every official
YAML cross-validated against it in-test. Domain → serialization →
schema direction kept. Registry total now 8/8 valid.

## Invariant Impact
1, 7, 11, 12 preserved structurally (read-only playbooks, same
contracts, no cross-audit state, read-only defaults); 2, 5
enforced via quarantine as-data; 3, 4, 6, 8, 9, 10 untouched (no
evidence/finding/model/provider/scanner paths added — planning
only, values projected never mutated).

## Known Limitations
- `max_iterations` is declared and snapshotted but not consumed —
no execution loop exists yet by design.
- `suggest()` over candidate playbooks (NO_MATCH/AMBIGUOUS)
deferred — selection today is explicit-id + conditions.
- `extends` merges constraints + required tasks only; methodology
and evidence diffing between parent/child deferred to usage.
- Condition vocabulary is four fields — new subjects need spec +
schema + test extension together.
- No MCP/CLI surface yet by design (service API only).

## Deferred Work
Deliberate: execution (reuses ReasoningEngine + ToolExecutor +
VerificationService unchanged), parallel branches, pack
distribution, CLI `playbook list/inspect`, MCP
`PlaybookService` tool (only behind a Core contract, never direct
to tasks/tools).

## Evidence
- `pytest tests/unit/test_playbooks.py` → 26 passed.
- Full suite → 408 passed, 3 skipped. Schemas 8/8 valid.
- 18/18 official playbooks TRUSTED, acyclic, schema-valid,
deterministic across loader runs.
- Desired end state reproduced verbatim in-test (deep audit:
3 pinned tasks in order, 3+ skills, semgrep, security-audit
template, READY lifecycle, digest).
- Files listed above.

## Final Status
**PASS** — contract + orchestration complete: PlaybookSpec,
schema, registry, validator, resolver (delegating, never
reimplementing), service facade with parent inheritance, 18/18
official playbooks trusted and acyclic, conditional execution
graphs, budgets, snapshots immutable, malicious battery
contained, cross-audit isolated, all tests green. The four
abstractions now stand: Skill = HOW, Task = WHAT, Playbook =
WORKFLOW, Report = PRESENTATION. POST-RC-005 (Code Intelligence)
may proceed — giving these playbooks dataflow/call-graph/
dependency-graph/authorization-path signal under the same
contracts.
