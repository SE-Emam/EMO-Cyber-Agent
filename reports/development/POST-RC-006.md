# POST-RC-006 — Advanced Security Skill Packs

## Objective
Turn skills from trigger-matched methodology pointers into reusable,
deterministic security methodology components over Code
Intelligence: 8 official packs (injection, auth/authz, secrets,
SSRF, traversal, XSS, dependency/supply-chain, configuration) with
evidence contracts and verification handoffs — granting nothing,
executing nothing, confirming nothing.

## Scope
In scope: `skills/packs/` framework (pack/errors/validator/
resolver/catalog), `SecuritySkillPack` + `SecurityCheck` domain,
capability allowlist harvested from Policy/Tasks/Playbooks/codeintel,
`PackResolver` (coverage + task chain) + `report_view` projection,
`security-skill-pack.schema.json` v1.0, `SKILL-PACK-TEMPLATE.yaml`,
8 official YAML packs + trusted loader, 6 malicious fixtures, 26
offline tests. Out of scope (deferred): full CPG/Joern/CodeQL,
interprocedural engine, autonomous exploitation/remediation,
model prompts, continuous monitoring, MCP/CLI pack surface.

## Architecture
Task → SkillResolver matches → packs by skill index → per-check
coverage vs provider capabilities → evidence/verification
aggregation → hypotheses (UNVERIFIED) → handoff to Correlation and
VerificationService + PolicyEngine (authority stays downstream).
Packs sit strictly in the methodology lane: Code/Data Facts →
Evidence → Correlation → Hypothesis → Verification → Finding.
Skill = HOW, enforced by construction (no grant/execute/confirm
fields exist; frozen models reject extras).

## Pack Framework
`packs/__init__.py, pack.py, errors.py, validator.py, resolver.py,
catalog.py`. `SecuritySkillPack`: id/version/name/purpose, skills,
`required_code_intelligence`, evidence/verification requirements,
applicable assets, security domains, methodology, `checks`,
stop conditions, limitations, required + denied capabilities,
allowed tools, dependencies, provenance, deterministic
`digest_of`. `SecurityCheck`: id/title/methodology,
evidence_required/_sufficient/_missing, verification_required +
safety, high_risk flag, entry level (OBSERVED/SUSPECTED/HYPOTHESIS/
VERIFICATION_REQUIRED — VERIFIED rejected at construction),
codeintel needs, taxonomy-gated source/sink kinds, hypothesis
template. 17 stable `PackErrorCode`s.

## Capability Allowlist
`build_known_capabilities()`: Policy `KNOWN_READ_CAPABILITIES` ∪
codeintel `code.*.read` requests ∪ official Task caps ∪ official
Playbook caps ∪ skill-declared caps. Pack capabilities outside it
→ `capability-unknown`; any write-ish fragment (write,
destructive, admin, delete, exfiltrate, grant) → `capability-escalation`.
A pack cannot add authority the system does not already know —
and cannot request authority at all.

## Validator
Shape, semver, ≥1 skill + ≥1 check, codeintel needs ⊆ provider
vocabulary, source/sink ⊆ v1.0 taxonomy, verification methods ⊆
`VerificationMethod` vocab, per-check evidence non-empty,
high-risk ⇒ verification required, verdict-authority scan (13
severity/confirmation markers), result-bias scan, injection
quarantine (UNTRUSTED, data-only), skill/tool existence when
registries wired (required → error). Trust: official + clean →
TRUSTED.

## Resolver
`resolve(pack, provider_capabilities)`: per-check COVERED (all
needs met) / PARTIAL (some met + recorded gap) / UNAVAILABLE
(none met, nothing invented); aggregates evidence/verification
plans, limitations, `[UNVERIFIED HYPOTHESIS]` hypotheses;
deterministic digest. `resolve_for_task`: SkillResolver → skill
set → packs by skill overlap (deterministic id order) → coverage
→ single handoff object with digest. `report_view`: projection
metadata only (domain, checks performed = non-unavailable,
evidence/codeintel coverage, verification REQUIRED, limitations,
unverified hypotheses, provenance).

## Evidence Contract
Every check declares required/sufficient/missing evidence plus
verification methods; entry level caps what may be asserted
without verification and can never be VERIFIED. OBSERVED (mapped
routes, inventoried packages) vs SUSPECTED (unencoded flows,
wildcard settings) vs HYPOTHESIS (taint paths, missing checks) vs
VERIFICATION_REQUIRED vs VERIFIED (downstream only) — enforced by
construction + validator, asserted in-test.

## Verification Integration
High-risk checks carry method handoffs (`static_confirmation`,
`dataflow_confirmation`, `read_only_query`,
`configuration_confirmation`, `dependency_confirmation`) with
`passive` safety; packs never execute them. Missing handoff on a
high-risk check is a hard error. VerificationService + PolicyEngine
remain the sole authority — packs produce plan inputs only.

## Code Intelligence Integration
Packs declare needs against the 11 provider capabilities
(injection: dataflow/taint/symbols/db_relationships; auth:
routes/auth_boundaries/call_graph/dataflow; secrets: symbols;
SSRF: dataflow/routes; traversal: dataflow/symbols; XSS:
dataflow/routes; deps: dependencies; config: symbols). Missing
capability ⇒ labeled PARTIAL/UNAVAILABLE with recorded gap, full
checks only on provable subsets, no silent downgrade — proven by
full/partial/empty capability resolutions in-test.

## Official Packs
8/8 TRUSTED, acyclic, schema-valid, digest-stable, zero warnings:
`injection-security` (SQL/process/template/deserialization;
TAINT_PATH_FOUND stays hypothesis), `authentication-authorization`
(route→boundary mapping, object-access, state-change protection),
`secrets-sensitive-data` (digests/locations/provenance only —
raw secret material never evidence), `ssrf-request-forgery`
(URL origins, validation boundaries, redirects, internal
resources), `path-traversal-file-access` (origins, normalization,
archive boundaries, encodings), `xss-output-encoding` (rendering
sinks, encoding boundaries, reflected vs stored),
`dependency-supply-chain` (inventory, provenance, external risk
metadata as evidence — presence ≠ exposure),
`security-configuration` (defaults, debug, transport, CORS-like,
environment separation). None is a prompt: methodology steps +
evidence contracts + verification handoffs.

## Reports
`report_view` gives templates everything displayable (domain,
checks, evidence/codeintel coverage, verification REQUIRED,
limitations, unverified hypotheses, provenance, digest) and
nothing else: serialized views contain no severity, no confirmed,
no finding keys (asserted). No report engine changes were needed.

## MCP / CLI
No new surface — deliberately. Service-level `PackResolver` is
the integration point; `list/resolve` tools deferred to the
stage that needs them. No `execute/grant/confirm` surface will
ever be added (documented as prohibited).

## Security Tests
Dedicated battery: grant-capability fixture → escalation error;
shell-methodology fixture → tool-missing + quarantine; severity
fixture → verdict-authority error; bias fixture → result-bias
error; metadata-as-data assertion; cycle pair → cycle paths;
duplicate identity → DUPLICATE; secrets redaction rule presence;
4 injection payloads stay data with zero granted writes; AST scan
(no subprocess/os/eval/shell across all 6 modules; no
Finding imports); cross-audit/snapshot non-leakage (content-
addressed digests identical across audits — nothing to leak).

## Cross-Audit / Snapshot Isolation
Packs carry no audit binding (no `audit_id` field exists);
resolutions are content-addressed (same inputs ⇒ same digest
across audits); different capability sets ⇒ different coverage,
identical pack digest (pack immutable). Cross-snapshot data
rejected at the codeintel layer below; packs add no channel.

## Tests
`pytest tests/unit/test_security_skill_packs.py` — 26/26: spec
gates, digest determinism, schema round-trip, 8-pack catalog
(valid/trust/checks/evidence/verification/caps/skills/schema/
digests/applicability), registry CRUD/cycles, validator shape/
refs/escalation/taxonomy/vocab/gaps/bias/quarantine, resolver
full/partial/unavailable + never-invents + taint honesty, task
chain (skills, packs, codeintel, evidence, verification,
labeled hypotheses, digest stability, authority stop),
empty-signals behavior, report projection purity, isolation,
malicious battery (8 fixtures/tests), surfaces, error codes.
Full suite: 470 passed, 3 skipped. Schemas 11/11 valid.

## Files Inspected
- `skills/spec.py`, `registry.py`, `resolver.py`,
`builtin/catalog.py` (reused, untouched)
- `tasks/library.py` (22 official task caps/skills harvested)
- `core/policy.py` (`KNOWN_READ_CAPABILITIES`),
`core/verification.py` (`VerificationMethod` vocab),
`core/tool_registry.py` (`ToolSpec`)
- `code_intelligence/{provider,spec}` (capability + taxonomy
sources), `playbooks/library.py` (playbook caps harvested)
- `docs/schemas/*.json`, `templates/skills/SKILL-TEMPLATE.yaml`
(conventions)

## Files Changed
- `src/emo_cyber_agent/skills/packs/{__init__,pack,errors,validator,resolver,catalog}.py` (NEW)
- `docs/schemas/security-skill-pack.schema.json` (NEW)
- `templates/skills/SKILL-PACK-TEMPLATE.yaml` (NEW) +
`templates/skills/packs/official/*.yaml` ×8 (NEW)
- `tests/unit/test_security_skill_packs.py` (NEW, 26 tests) +
`tests/fixtures/security_skill_packs/*.yaml` ×6 (NEW)
- (No Core/skills-core/tasks/playbooks/codeintel/adapters/CLI/MCP/reporting changes.)

## Schemas
`security-skill-pack.schema.json` NEW (v1.0, `$id`-versioned);
every official pack cross-validated in-test. Registry total now
11/11 valid. Direction kept: YAML authoring → normalize →
schema cross-check → frozen spec.

## Invariant Impact
All 12 PASS by construction + suite: 1 read-only (packs request
read-only caps only; write-ish rejected), 2 untrusted content
(pack text is data; injection quarantined), 3 evidence-gated
(every check bound to evidence; observations need evidence ids),
4 no destructive transition (no grant/execute surface), 5 tool
outputs as evidence (packs consume facts, emit methodology), 6
explicit uncertainty (HYPOTHESIS labels, PARTIAL gaps, entry
levels), 7 shared contracts (schema + frozen models), 8 external
provider/model choice (provider-agnostic needs), 9 scanners
authoritative (external risk enters as evidence w/ provenance),
10 human review for high-impact (verification REQUIRED, never
auto-confirmed), 11 specialist worker (methodology only,
AST-scan clean), 12 host delegates (resolution returns plans,
EMO owns workflow downstream).

## Known Limitations
- Pack↔task wiring is skill-overlap based; explicit task↔pack
pins deferred to playbook/task evolution.
- `dependencies` between packs validated for cycles but not
merged at resolve time (no pack inheritance semantics yet).
- No severity/priority ordering between packs — resolution
returns id-ordered sets.
- No MCP/CLI surface by design.
- Secrets redaction enforced at evidence-build time (Code
Intelligence layer); packs enforce the rule declaratively.

## Deferred Work
Full CPG, Joern/CodeQL adapters, interprocedural engine,
autonomous exploitation/remediation, model security prompts,
continuous monitoring — each in its dedicated stage. Next
logical step per program: POST-RC-007 Tool Pack Framework
(external security tools under Registry + Policy + Evidence
contract instead of direct skill binding).

## Evidence
- `pytest tests/unit/test_security_skill_packs.py` → 26 passed.
- Full suite → 470 passed, 3 skipped. Schemas 11/11 valid.
- 8/8 official packs TRUSTED, acyclic, schema-valid,
digest-stable, warning-free.
- End-to-end chain reproduced in-test: deep-security-audit →
6 skills → 6 packs → 7 codeintel needs → evidence +
verification handoff, all hypotheses UNVERIFIED, digest stable.
- Files listed above.

## Final Status
**PASS** — methodology layer complete: pack framework, 8 real
packs, deterministic coverage resolution, verdict-free evidence
contracts, verification handoffs, report-safe projections,
malicious battery contained, isolation proven, all tests green.
Knowledge/methodology is now cleanly separated from execution
and authority. POST-RC-007 (Tool Packs) may proceed.
