# POST-RC-007 — Tool Pack Framework Security Assessment

## Objective
Bring external security tools inside EMO as interchangeable,
policy-bound fact producers: Semgrep, Trivy, Gitleaks, OSV-Scanner
behind one declarative Tool Pack contract, executed only on the
existing path ToolRegistry → StrictPolicyEngine → ToolExecutor →
adapter → normalized result → Evidence. No new authority, no new
execution mechanism, no verdicts.

## Scope
In scope: `tools/packs/` domain (spec/validator/registry/resolver/
executor/provenance/errors/catalog), closed capability taxonomy,
typed input contracts, argv assembly rules, binding checks,
deterministic health, evidence mapping through the existing Core
function, 4 official packs + trusted loader, 42 offline tests.
Out of scope (deferred): remediation/fix commands, remote
execution, container orchestration, exploit runners, sandboxing,
scheduling, shell gateway, model-driven selection, MCP raw proxy.

## Architecture
Request → resolve ToolPack → resolve ToolDefinition → validate
target/input → StrictPolicyEngine → ToolExecutor (existing,
unchanged) → adapter (existing T007, unchanged) → normalized
result → EvidenceItem fields (existing mapping) → Correlation.
Packs contribute declarations only. Adapters fail closed without
a valid policy decision — a property inherited, not reimplemented,
and re-proven by test.

## Boundaries (enforced, tested)
Pack = WHAT EXISTS + HOW INVOKED + WHAT FACTS. It grants no
capability, decides no permission, creates no finding, raises no
confidence, confirms no vulnerability, sets no severity, runs no
remediation, bypasses no policy. Tool output is untrusted external
data until normalized with provenance. The model gets no direct
tool execution (no such surface exists — asserted by signature
and source scans).

## T007 Compatibility
Zero rewrites: `compat_adapters()` re-exports `SCANNER_ADAPTERS`;
pack argv for executable definitions is byte-identical to adapter
argv (asserted per tool); pack parse IS adapter parse (asserted on
realistic stdout). T007 guarantees (argv arrays, confinement, env
allowlist, secret dropping, truncation, policy binding) hold
unchanged — the full pre-existing toolchain suite passes unmodified.

## Official Packs
4/4 TRUSTED, schema-valid, digest-stable, warning-free:
- `semgrep-pack` (ACTIVE): pattern/static scan, offline, scanner
severity kept as verbatim data.
- `trivy-pack` (ACTIVE): executable filesystem scan
(vulnerability + dependency + misconfiguration facts); config,
secret, SBOM modes declared with `executable: false` — resolver
skips them instead of forking adapter logic.
- `gitleaks-pack` (SECURITY_ONLY): directory scan; fingerprint/
rule/path/line only — secret values dropped at parse (T007) with
redaction as second gate; lifecycle recorded as security-only
with an explicit confirm-against-upstream limitation.
- `osv-scanner-pack` (ACTIVE): scan only, `network_required`,
snapshot-bound; no fix operation exists anywhere in the pack
(scanned). Offline runs fail deterministically, never partially.

## Capability Taxonomy
Closed: CODE_PATTERN_SCAN, DEPENDENCY_SCAN,
VULNERABILITY_LOOKUP, MISCONFIGURATION_SCAN, SECRET_DETECTION,
SBOM_SCAN, STATIC_ANALYSIS, LOCAL_REPOSITORY_SCAN. Unknown →
validation error; 18 write-ish fragments (WRITE…PRIVILEGE_
ESCALATION, write…grant) → hard escalation error. Skill packs
request capabilities (e.g. SECRET_DETECTION); the resolver —
never the skill — picks the compatible registered implementation
(proven: SECRET_DETECTION → gitleaks, MISCONFIGURATION_SCAN →
trivy).

## Input Contracts & Argv
Typed fields only (string/integer/boolean/path/ref/enum/
snapshot_id) with ranges, enums, snake_case names; banned names
(argv/command/shell/flags/raw/extra_args/config/script);
undeclared fields rejected; traversal/encoded/null paths rejected;
value flags must name declared scalar inputs. Final argv =
[binary, *fixed_args, *adapter_tail, *flag_values], shell-safe by
construction (validated tokens + validated values + shell=False
port). No API accepts raw argv, env, or commands (signature +
source asserted).

## Bindings
Audit, target, capability, policy-version checks inherited from
ToolExecutor (wrong/forged/stale decisions rejected — tested).
Pack adds snapshot binding (declared snapshot_id must equal the
call's snapshot → else STALE_SNAPSHOT) and audit/project binding
for declared identity fields (else BINDING_MISMATCH). Tool version
binding: registry version vs definition range at resolve
(VERSION_UNSUPPORTED), plus network gating (REQUIRED + unavailable
→ deterministic failure, never partial data).

## Health
AVAILABLE / MISSING / UNSUPPORTED / VERSION_UNSUPPORTED /
BROKEN / POLICY_BLOCKED / NETWORK_UNAVAILABLE from PATH presence
(lookup only, never executes) + range/platform checks. Reports
carry id/status/version/reason/timestamp only — no secrets,
tokens, or env contents (key-set asserted). Optional tools
degrade explicitly (`degraded: true` + reason), required tools
fail closed.

## Evidence Mapping
Observation → `observation_to_evidence_fields` (existing Core
function): digests, locators, redacted summaries, full
provenance (tool/version/adapter/pack/invocation/audit/project/
snapshot/argv/raw digests, policy version, network, coverage).
Tool labels (HIGH/CRITICAL/VULNERABLE/SECRET/CONFIRMED) stay
inside untrusted message data; evidence dicts carry no
finding_id/status/severity keys (asserted). Raw stdout never
persisted — only its digest (plus optional redacted preview in
provenance, capped).

## Adversarial Results
Battery (all contained): shell tokens in packs → rejected;
escalation/remediation fixtures → rejected; metadata injection →
quarantined as data; traversal/symlink/cwd/null/encoded inputs →
rejected at validation or confinement; oversized output →
truncated + labeled; timeouts → errors (no leaks); stderr/env
secrets → never in evidence; network-denied execution → policy
denial; forged/unknown decisions → denial; wrong audit/target →
denial; stale snapshot → rejection; cross-audit evidence →
impossible by construction (audit-bound decisions + invocations);
instruction-bearing tool output → inert data, policy log shows
exactly one legitimate decision; "CONFIRMED" claims → data only;
arbitrary flags/config → rejected; missing/unsupported binaries →
explicit unavailability; no Finding/severity authority introduced
anywhere (source-scanned).

## Skill Integration & End-to-End
Proven per §18 (ScriptedPort doubles, realistic stdout):
Injection→Semgrep (2 observations → evidence with digests),
Dependency→Trivy and →OSV (granted network; CVE/GHSA records),
Secrets→Gitleaks (1 fingerprint observation, secret strings
absent from every record), Configuration→Trivy
(MISCONFIGURATION_SCAN resolves to the executable def).
Terminal state in all four: facts/evidence available for
Correlation; zero Findings created.

## MCP / CLI
Unchanged. Source-asserted absent: run_command,
execute_tool_raw, execute_shell in CLI and MCP surfaces. Future
surfaces limited to list/describe/resolve; execution stays
Core-mediated with full binding enforcement.

## Tests
`test_tool_packs.py` (20) + `test_tool_pack_security.py` (22) —
42/42: contract, taxonomy, ranges, schema round-trip, 4-pack
catalog, compat identity, registry, validator battery,
resolution/health/version/platform/target/network paths,
typed inputs, provenance unforgeability, execution bindings,
adversarial battery, skill integration, 4 end-to-end chains,
surface scans, error codes. Full suite: 512 passed, 3 skipped.
Schemas 12/12 valid.

## Files Inspected
- `core/tool_registry.py` (ToolSpec/ToolRegistry/ToolInvocation),
`core/execution.py` (ToolExecutor/ports/confinement/env),
`core/policy.py` (StrictPolicyEngine/decisions),
`core/scanners.py` (all 4 adapters + normalized models +
evidence mapping), `adapters/mock_scanners.py` (ScriptedPort),
`domain/models.py` (EvidenceItem), `core/repository.py`
(normalize_path/redact), `skills/packs/*` (capability consumer),
`cli/main.py`, `mcp/*` (surface audit)

## Files Changed
- `src/emo_cyber_agent/tools/packs/{__init__,spec,validator,registry,resolver,executor,provenance,errors,catalog}.py` (NEW)
- `docs/schemas/tool-pack.schema.json` (NEW)
- `templates/tools/TOOL-PACK-TEMPLATE.yaml` (NEW; mission draft
name TOL-PACK-TEMPLATE corrected to the repo's TOOL- prefix) +
`templates/tools/packs/official/*.yaml` ×4 (NEW)
- `tests/unit/test_tool_packs.py` (NEW, 20 tests) +
`tests/unit/test_tool_pack_security.py` (NEW, 22 tests) +
`tests/fixtures/tool_packs/*` ×6 (NEW)
- (No Core/scanners/execution/policy/registry/skill/task/playbook/CLI/MCP/reporting changes.)

## Invariant Impact
All 12 PASS: 1 read-only (packs declare read-only; write
rejected), 2 untrusted content (outputs quarantined as data),
3 evidence-gated (mapping requires observations), 4 no
destructive transition (no grant/execute surface), 5 tool
outputs as evidence (normalized + provenanced), 6 explicit
uncertainty (health/coverage/limitation metadata), 7 shared
contracts (schema + frozen models), 8 external provider choice
(interchangeable definitions), 9 scanners authoritative
(adapter output verbatim as data), 10 human review (no
auto-confirmation), 11 specialist worker (facts only), 12 host
delegates (Core owns execution path unchanged).

## Known Limitations
- Deferred trivy modes need adapter variants (declared, skipped).
- Value-flag argv path exercised by synthetic defs (no official
pack uses value flags yet — kept minimal deliberately).
- Version data comes from registry metadata, not live `--version`
probes (no execution for health).
- Gitleaks lifecycle status needs upstream re-confirmation
(recorded as limitation in-pack).
- SBOM inputs accepted as contract; scanner-side SBOM parsing
coverage follows the deferred mode.

## Deferred Work
Remediation/fix commands, remote execution, container
orchestration, exploit runners, sandboxing, scheduling, shell
gateway, model-driven selection, MCP raw proxy — each in its
dedicated stage with its own threat model.

## Evidence
- `pytest tests/unit/test_tool_packs.py tests/unit/test_tool_pack_security.py` → 42 passed.
- Full suite → 512 passed, 3 skipped. Schemas 12/12 valid.
- 4/4 official packs TRUSTED, schema-valid, digest-stable,
warning-free; argv/parse identical to T007 adapters.
- 4 end-to-end skill→tool→evidence chains green with zero
Findings and zero secret leakage.
- Files listed above.

## Final Status
**PASS** — provider-independent, policy-bound Tool Pack layer
complete: frozen contract, trusted catalog, deterministic
resolution with health, declaration-only execution through the
unchanged Core path, forgery-proof provenance, redacted
evidence, adversarial battery contained, T007 intact, all tests
green. External security tools are now interchangeable fact
producers; Core remains the only execution and security-
authority boundary.
