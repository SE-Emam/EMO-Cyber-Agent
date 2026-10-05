# POST-RC-001 — Skill System & Skill Registry

## Objective
Add the official Skill framework: a Skill is an executable security-
methodology declaration (phases, checks, evidence rules), never a bare
prompt. Skills live beside Core, request capabilities they can never
grant, and resolve deterministically from project context. Core Policy
remains the sole authority over everything a skill proposes.

## Scope
In scope: `SkillSpec` (18 fields, semver-versioned), 5-stage validation
pipeline, `SkillRegistry` (register/resolve/get/list/validate/
dependencies/version/compatible + cycle detection + dependency-guarded
unregister), `SkillResolver` (deterministic signal→skill matching with
reasons), 25 built-in official skills (methodology + checks + evidence
rules each), `templates/skills/SKILL-TEMPLATE.yaml` authoring contract,
18 offline tests.
Out of scope (later POST-RC tasks): task templates (002), report
templates (003), playbooks (004), execution wiring of skills into the
reasoning loop (integration point documented, not built).

## Architecture
```text
Project Context → SkillResolver → skill candidates (+reasons)
→ SkillRegistry (contracts) → Core Policy (authority over capabilities)
→ ToolRegistry → Execution → Evidence
```
New package `skills/` (spec/registry/resolver + `builtin/catalog.py`);
zero imports from Core policy/execution/finding modules (source-scanned
in-test). No Core files modified; no adapter changes.

## SkillSpec
skill_id (kebab-case) / name / version (semver X.Y.Z, independent) /
description / domain / triggers / objectives / inputs /
required_capabilities / allowed_tools / methodology / evidence_
requirements / verification_strategy / stop_conditions / output_contract /
dependencies / security_constraints / provenance / tests. Frozen model,
extra-forbidden; malformed id/version rejected at construction.

## Registry
Version-aware store: duplicate (id, version) rejected; `get` defaults to
latest with explicit-version override; `unregister` refuses while
dependents exist (named in the error); `compatible_skills` by shared
domain or dependency edges; `check_cycles` returns deterministic cycle
paths (empty for the builtin set — asserted).

## Resolver
`TRIGGER_TABLE` (signal substring → skill ids) matched against lowercased
filenames + objective text; unknown signals skipped, never invented;
output sorted with per-skill matched-signal reasons; `required_
capabilities` returns the union as policy-review DATA. Reference example
verified: Next.js + TypeScript + Supabase + auth signals resolve exactly
the mandated 8 skills (api-security, authorization, supabase, rls,
authentication, secrets, supply-chain, business-logic).

## Security Model
Request ≠ grant (registry records; `StrictPolicyEngine` still denies
`supabase.admin` — tested end to end). Injection phrases in any free-text
field → `UNTRUSTED` trust + warning (registration still succeeds: data,
not authority). Structural failures (bad schema/version, missing or
self dependency) → invalid, registration refused. Clean skills → TRUSTED.

## Tests
`pytest tests/unit/test_skills.py` — 18/18: schema + versioning, builtin
count/ids/methodology/read-only-ness, registry CRUD + guards + cycles +
compatibility, validation pipeline (high-risk/injection/clean), resolver
(example mapping, unknown-signal silence, capability union without
grants, determinism), no-Core-imports scan, template key presence.
Full suite: 350 passed, 3 skipped (pre-existing optional probes).

## Fixtures
Builtin catalog itself is the fixture (25 versioned declarations);
malicious variants (high-risk caps, injected methodology) constructed
inline per test. Reproducible (fixed data, no randomness, no network).

## Invariants
1, 7, 8, 11, 12 preserved by construction (read-only builtins,
same-contract reuse, external providers untouched, no cross-audit state —
registry holds no audit data at all, read-only default on every skill);
2, 5 enforced via untrusted marking; 3, 4, 6, 9, 10 unaffected (no
evidence/finding/model paths touched).

## Evidence
- `pytest tests/unit/test_skills.py -p no:warnings` → 18 passed.
- Full suite → 350 passed, 3 skipped. Schemas 6/6 valid.
- Files: `skills/{spec,registry,resolver,__init__}.py`,
  `skills/builtin/{catalog,__init__}.py`, `templates/skills/
  SKILL-TEMPLATE.yaml`, `tests/unit/test_skills.py`.

## Known Limitations
- Skills are not yet wired into the reasoning loop (resolver output is
  consumed by future POST-RC-002 planning, not by any executor today).
- Community skills directory exists by convention only (no loader yet —
  deliberate; loading untrusted third-party skills needs its own task).
- Trigger matching is substring-based by design (transparent, auditable);
  ML-based detection is explicitly out of scope.

## Deferred Work
POST-RC-002 (tasks consume skills), POST-RC-004 (playbooks compose
skills), POST-RC-006 (advanced packs), POST-RC-014 (community extension
loading with full validation).

## Final Status
**PASS** — skill framework complete, 25/25 builtins validated trusted
and acyclic, resolver deterministic, malicious content contained as
untrusted data, zero Core/adapter changes, all tests green. POST-RC-002
may proceed.
