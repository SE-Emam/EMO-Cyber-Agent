# POST-RC-003 — Report Template Engine

## Objective
Make "report shape" a formal, verifiable object: a ReportTemplate
describes HOW to present (sections, order, visibility, finding-field
projection, evidence/verification render mode, redaction profile,
output formats) without ever changing WHAT the report means. Core
`AuditReport` semantics (findings, severity, confidence, status,
evidence, verification, provenance) are frozen; templates project only.

## Scope
In scope: `ReportTemplateSpec` + visibility/ordering/composition models,
versioned `ReportTemplateRegistry`, `ReportTemplateValidator`,
`ReportTemplateResolver` (task/objective → template, deterministic),
`ReportTemplateService.plan()` facade, `docs/schemas/
report-template.schema.json` v1.0, `templates/reports/
REPORT-TEMPLATE.yaml`, 20 official YAML templates + loader
(TRUSTED-by-loader, never self-declared), template-aware renderer in
`core/reporting.py` (`apply_report_template`,
`to_canonical_json_with_template`, `to_markdown_with_template`),
task integration (`TaskResolver`/`TaskService` template_registry wiring
+ `report_template_override`), 12 offline tests.
Out of scope (later tasks): playbooks (004), MCP/CLI template commands,
pack distribution (manifest declared, distribution deferred).

## Template Domain
`ReportTemplateSpec`: id (kebab-case), name, semver version, type
(security default), description, `sections` (name + allowlisted fields +
visibility rules), `finding_fields` (allowlisted, same gate as section
fields — added this task after a test proved the gap), `section_order`,
`show_non_reportable` (default false), `evidence_presentation`
(references/inline — inline stays references-only, never fetches
content), `verification_presentation` (status/detail — detail surfaces
already-projected method/confidence, never new data),
`limitations_sections`, `appendices` (names only, no content
generation), `output_formats` ⊆ {json, jsonl, markdown}, optional
`extends`, `preserve_provenance`/`redact_secrets`/`deterministic`
(all default true, disabling is a hard error), `provenance`. Frozen,
extra-forbidden.

## Template Schema
`docs/schemas/report-template.schema.json` (v1.0, `$id`-versioned):
flat contract shape. Direction honored: YAML authoring → normalize →
schema cross-check → `ReportTemplateSpec` (canonical). Pydantic
enforces at runtime; jsonschema cross-checks in tests/dev. Every
official YAML cross-validated against it in-test.

## Template Registry
Version-aware; duplicates rejected; `get` defaults to latest with
explicit-version override; `unregister` refuses while extended;
`check_cycles` returns deterministic cycle paths. Trust assigned by
the LOADER (official dir → TRUSTED), never by registration alone
(default UNTRUSTED). `trust_of` exposes per-version trust.

## Template Validator
Mandatory-field gate (7 fields for security/executive/developer
types: finding_id, status, severity, confidence, evidence_ids,
verification_ids, provenance), output-format allowlist, unsafe-marker
scan (`javascript:`, `<script`, `exec(`, `eval(`, `__import__`,
`os.system`, `subprocess`, … → error), visibility-operator allowlist,
`preserve_provenance`/`redact_secrets`/`deterministic` must stay true.
Returns (valid, trust, errors, warnings); official provenance +
clean → TRUSTED.

## Template Resolver
`resolve(template_id=…, task_type=…, objective=…)`: explicit id wins
(unknown → NOT_FOUND); else objective-keyword match (19 keywords:
executive, developer, web, api, supabase, dependen, supply, ai, mcp,
threat, release, regress, authent, authoriz, database, business-logic,
cloud, container, agent); else task-type map (audit→security-audit,
review/verification_support→developer-security,
threat_model→threat-model, default security-audit). Deterministic, no
LLM, snapshot frozen with digest + timestamp.

## Template Service
`ReportTemplateService.plan()` facade: validate → resolve → snapshot.
No rendering of security semantics; rendering lives in
`core/reporting.py` and consumes snapshots only.

## Renderer
`core/reporting.py` consumes snapshots duck-typed (no import of
`report_templates` — Core stays dependency-free). `apply_report_template`
projects `AuditReport` into an ordered presentation dict: section order
from template, per-section visibility (no rules → visible; rules →
visible iff any finding satisfies any rule on allowlisted paths only;
unknown path/operator → False), finding projection (requested ∪
mandatory — mandatory can never be dropped), evidence/verification
modes, limitations aliases, non-reportable only when report carries
them AND template allows, appendices as names. Source `AuditReport`
untouched (asserted in-test). `to_canonical_json_with_template` /
`to_markdown_with_template` enforce output-format gating (unlisted
format → REPORT_INVALID) with the same escaping/redaction as the
untemplated serializers. No scores, no rankings, no verdicts (scanned
in-test).

## Task Integration
`TaskResolver` accepts optional `template_registry` + per-call
`report_template_override`: override wins, registry verifies existence
only (presentation choice, never a capability grant); unknown override
→ TEMPLATE_MISSING; unverified refs → warning, never silent. Default
flow resolves the task's own `report_template` ref (closes the
pending-flag left by POST-RC-002). `TaskService.plan()` threads both
through.

## Composition
`extends` chains compose additively in the loader: child may add
sections/fields/appendices and narrow visibility; merged output must
retain all mandatory fields and all three security defaults or
COMPOSITION_INVALID. Verified: add-only merge keeps remediation;
hostile `preserve_provenance=False` child rejected; two minimal
parents missing mandatory rejected.

## Trust
TRUSTED = loader-assigned official only. UNTRUSTED = validated but
external/injection-flagged. INVALID = structural failure. Trust never
equals authority — templates authorize nothing.

## Snapshot
`ResolvedReportTemplate` frozen with id/version/digest/timestamp +
spec; registry mutation post-resolve cannot alter in-flight snapshots
(digest equality asserted across two independent loader runs).

## Versioning
Independent semver everywhere (template, task, skill, tool, policy).
`get` defaults to latest; explicit pins honored.

## Security
Malicious battery: `javascript:`/`<script`/`exec(` descriptions
(error), hostile security-flag children (COMPOSITION_INVALID at load,
validator error standalone, render-time denial via model_copy),
unsupported formats, unknown operators/paths (rule → False, section
hidden — fail-closed), provenance-strip attempts, secret-bearing
titles (redacted in markdown — `ghp_LIVE999` asserted absent),
format-escape attempts (same `md_escape` path as ECA-T012).

## Prompt Injection
Template text fields are data: unsafe markers quarantine at validate
time; visibility conditions evaluate only allowlisted paths with
`==/!=/in/not-in` — no expressions, no calls, no attribute access.
Resolver ignores payload wording (keyword match is presentation
routing, not authorization).

## Tests
`pytest tests/unit/test_report_templates.py` — 12/12: spec
ids/versions/field-gates/operator-gates, registry
duplicate/version/trust/cycle/unregister-guard, validator
mandatory/security negatives, YAML normalize + schema cross-check +
malformed-YAML, 20-file official library (ids/trust/acyclic/schema
+ digest determinism), resolver id/task-type/objective/unknown,
composition add-only + weaken-denied, renderer
mandatory/provenance/order/immutability/determinism +
visibility/redaction/non-reportable/format-gate/hostile-flags +
no-scores, task wiring override/unknown/unwired. Full suite: 382
passed, 3 skipped. Schemas 7/7 valid.

## Fixtures
Official YAML library (20) + inline hostile variants (injection,
flag-stripping, format-escape, minimal-drop parents, ghost template
ids) + malicious finding titles (script/injection/secrets). Deterministic.

## Schemas
`docs/schemas/report-template.schema.json` NEW (v1.0); every official
YAML cross-validated against it in-test. Domain → serialization →
schema direction kept.

## Files Inspected
- `report_templates/*` (spec/registry/validator/resolver/service/library — built this task)
- `core/reporting.py` (renderer host), `core/findings.py` (SecurityFinding shape)
- `tasks/*` (spec/resolver/service — integration surface)
- `docs/schemas/*.json` (conventions), `templates/reports/` (new)
- `tests/unit/test_reporting.py`, `test_tasks.py` (integration surfaces)

## Files Changed
- `src/emo_cyber_agent/report_templates/{spec,registry,validator,resolver,service,library,__init__}.py` (NEW; spec gained `finding_fields` allowlist validator after test gap)
- `src/emo_cyber_agent/core/reporting.py` (template-aware renderer: `apply_report_template`, `to_canonical_json_with_template`, `to_markdown_with_template`, generator/service pass-throughs; existing serializers untouched)
- `src/emo_cyber_agent/tasks/resolver.py` + `service.py` (optional `template_registry` wiring + `report_template_override`)
- `docs/schemas/report-template.schema.json` (NEW)
- `templates/reports/REPORT-TEMPLATE.yaml` + `official/*.yaml` ×20 (NEW; `threat-model.yaml` fixed to include mandatory `finding.verification_ids` after loader rejection)
- `tests/unit/test_report_templates.py` (NEW, 12 tests)

## Invariant Impact
1, 7, 11, 12 preserved structurally (read-only templates, same
contracts, no cross-audit state, read-only defaults); 2, 5 enforced
via quarantine as-data; 3, 4, 6, 8, 9, 10 untouched (renderer adds no
evidence/finding/model/provider/scanner paths; projection copies
values verbatim through the existing `_redact` path).

## Known Limitations
- `evidence_presentation="inline"` currently renders references-only
(never fetches content by design); true inline expansion, if ever
wanted, needs a Core-approved evidence-reader — not this task.
- Objective-keyword routing is deterministic substring match, not a
model — ties fall through to task-type default, documented.
- Pack distribution manifest (`ReportTemplatePack`) declared, wired
nowhere — arrives with a future distribution task.

## Deferred Execution
Deliberate: planning + presentation only. No tool execution, no
verification runs, no finding mutation anywhere in this task.

## Evidence
- `pytest tests/unit/test_report_templates.py` → 12 passed.
- Full suite → 382 passed, 3 skipped. Schemas 7/7 valid.
- 20/20 official templates TRUSTED, acyclic, schema-valid, digest-stable.
- Renderer source-report immutability + determinism asserted in-test.
- Files listed above.

## Final Status
**PASS** — contract + resolution + rendering complete:
ReportTemplateSpec, schema, registry, validator, resolver
(task/objective routing), service facade, 20/20 official templates
trusted and acyclic, composition add-only with weaken-denial,
semantics-preserving renderer, task override wiring, malicious
battery contained, snapshots immutable, all tests green. POST-RC-004
(Playbooks) may proceed — consuming `ResolvedReportTemplate`
snapshots defined here.
