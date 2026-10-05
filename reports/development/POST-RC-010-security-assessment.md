# POST-RC-010 — AI / Agent / MCP Security Assessment

## Objective
Give EMO a first-class security surface for AI/agent/MCP
architectures — system model, identity, delegation, capability
graph, MCP topology, attack surface, threat taxonomy, targeted
analyses, hypotheses, controls, verification handoffs — with
zero Finding, severity, confirmation, execution, or remediation
authority. Analysis only, hypotheses only, handoffs only.

## Scope
In scope: `agent_security/` layer (19 modules), closed
25-category taxonomy with framework mappings as metadata,
deterministic prompt/poisoning/scope/memory/credential
analyses, 6 threat rules, snapshot-bound handoffs, agent delta,
8 allowlisted queries, service orchestration, 4 schemas,
starter template + 2 trusted official templates, 49 offline
tests. Out of scope (deferred): live red teaming, jailbreak
runners, agent runtimes/sandboxes, exploit runners, DAST,
credential harvesting, prompt mutation, behavior scoring,
approval workflows, monitoring, firewalls, remediation,
policy changes.

## Architecture
Declared architecture → AgentSystem (untrusted-by-default
facts) → capability graph (declared/observed/effective edges)
→ attack surface (independent, queryable) → MCP topology
(version-scoped) → analyses (prompt, poisoning, scope,
memory, credential, delegation) → scenarios (hypotheses) →
controls (observed/declared/unverified) → handoffs
(VerificationService only) → evidence → report projection.
Change signals trigger targeted refresh; skill packs supply
methodology; threat-modeling contracts are extended, never
duplicated.

## Boundaries (enforced, tested)
No model hosting/calling/selecting (no provider classes, no
model clients; AST-scanned), no agent permissions granted (no
grant surface; delegation analysis mutates nothing), no MCP
tool execution (no executor imports; no remote/proxy
functions), no direct arbitrary MCP connections (topology
from declared metadata only), no prompts run, no skills
executed, no Findings (no Finding imports; no finding_id
anywhere), no severity, no exploitability confirmation, no
PolicyEngine bypass (no policy calls — planning only), model
output never trustworthy (trust defaults untrusted), tool
descriptions/outputs never instructions (separate trust
surfaces), prompt/document/resource trust never assumed from
MCP origin.

## Contracts
Frozen, extra-forbidden, audit/project/snapshot-bound models
with deterministic digests (wall-clock excluded): agents,
subagents, roles, 5 identity kinds, delegations with
issuer/subject/delegate/scope/audience/validity, abstract
model endpoints (facts only, unknowns stay unknown),
prompt/context sources (default untrusted), skill/tool
bindings, MCP client/server/tool/resource/prompt with
identity/origin/transport/version/capabilities, sessions,
3 boundary kinds, flows, memories, retrieval, credential
sources (digest/locator refs only — raw material rejected
at construction), flows, tool-result parts split by trust.
Authority verbs (grant/approve/confirm/execute/...) rejected
in record prose — except control-kind nouns like approval.

## Identity, Delegation, Capability Graph
Five identity kinds kept separate (acts-as-user vs
acts-for-user vs service vs delegated-subset vs unknown).
Delegation carries scope/audience/validity as data; child
tools outside the parent set raise PRIVILEGE_INHERITANCE
(no automatic inheritance — proven); scope/subset math is
pure set logic; audience-less and validity-less delegations
raise explicit signals; tenant references raise isolation
signals. Capability graph labels DECLARED vs OBSERVED vs
EFFECTIVE edges separately — declaration never equals
permission, and scope widening plus read-only-to-write
agency are deterministic signals, not permission changes.

## MCP Model & Trust
Explicit client/server/tool/resource/prompt entities with
identity, origin, transport, version-scoped protocol facts,
and authorization context. Ten documented relationship kinds
(WRITES allowed only as an architecture fact, never a
permission). Unknown protocol versions yield UNKNOWN
assumptions plus limitations — including 2026-07-28, which
is carried as data, never as hard-coded behavior. Existing
`mcp/` protocol implementation untouched; only metadata
observations added, no generic execution.

## Attack Surface & Taxonomy
22 categories emitted only with backing records;
tool-exists never implies exploitable; emptiness resolves
to UNKNOWN/PARTIALLY_MAPPED/NONE_OBSERVED by contract,
never to zero-by-default. Closed 25-category taxonomy with
framework mappings (OWASP Agentic/MCP/Skills, ATLAS,
CAPEC/CWE) as pure metadata — unknowns stay null, never
invented. Prompt injection modeled as trust-boundary
transitions (surface hypothesis, not hijacking proof);
poisoning (malicious content) analyzed separately from
misuse (wrong tool).

## Memory, Credentials, Controls
Memory/RAG untrusted by default with poisoning, stale-context,
cross-project, cross-audit, and cross-snapshot signals; no
global security memory introduced. Credential flows carry
references only, must stay redacted inside declared
boundaries, and flag log/context/model crossings. Controls
(16 kinds) stay OBSERVED/DECLARED/UNVERIFIED — existence is
never effectiveness. Category→controls→evidence/verification
tables decide nothing.

## Scenarios, Handoffs, Delta, Queries
Scenarios cap at SUPPORTED_BY_EVIDENCE with labeled attack
sequences (declarative, never executable: no payloads,
exploits, live targets, or credential extraction); framework
mappings attached. Handoffs are snapshot/target/evidence
bound, passive by default, policy-gated downstream, with
stale rejection. Deltas describe presence only. Eight queries
allowlisted, audit-bound, provenance-recorded; unknown names,
foreign audits, and control characters rejected.

## Skill, Change, Threat-Model Integration
Agent skills map to existing methodology packs (no pack
duplication); change predicates map to review triggers
(skill/system-prompt/delegation/memory changes included);
threat-modeling helpers (digests, IDs, verdict guards) are
imported, not reimplemented. Tool observations attach as
scenario evidence with labels kept as data. Four end-to-end
workflows green: config→topology→surface→rules→evidence→
handoff, and skill-change→delta→targeted plan — zero Findings.

## Adversarial Results
Battery (all contained): 11 malicious texts inert with
authority intact (3 verb-forms rejected at construction, 8
proven inert in pipeline); tool outputs cannot move policy,
scope, status, or findings (regression family with
before/after equality); scope creep signals without
permission; fake trust yields limitations; severity/
confirmation injection rejected at builders; handoffs stale-
rejected; mitigations contain no apply/commit/deploy;
external-URL snapshots rejected; traversals budget out
explicitly; no live/model execution surface exists by scan.

## Tests
`test_agent_security.py` (20) + `test_mcp_security.py` (7)
+ `test_agent_security_isolation.py` (8) +
`test_agent_security_adversarial.py` (14) — 49/49:
contracts, system/MCP/identity/delegation/graph, taxonomy,
prompt/poisoning/memory/credential analyses, scenarios,
handoffs, delta, queries, determinism, templates, all 4
schemas, skill/change integration, isolation (audit/project/
snapshot/memory/delegation/permissions/Findings/
determinism), adversarial battery, output-isolation
regression, E2E ×2. Full suite: 662 passed, 3 skipped.
Schemas 21/21 valid. Testing caught real defects:
dotted capability names tripping the authority filter
(fixed with identifier-aware matching), timestamp leakage
into digests, session audit binding, and digest-identity
semantics.

## Files Inspected
- `mcp/{protocol,server,tools,delegate}.py` (protocol
versions, capabilities; untouched)
- `skills/builtin/catalog.py`, `skills/packs/*` (skill +
pack ids, resolver patterns; untouched)
- `threat_modeling/*` (helpers, status vocab, handoff
patterns; extended, never duplicated)
- `core/policy.py` (grant model, decision log),
`domain/models.py` (EvidenceItem), `core/repository.py`
(redaction), `docs/schemas/*.json` (conventions)

## Files Changed
- `src/emo_cyber_agent/agent_security/{__init__,spec,errors,provenance,agent_model,identity,delegation,mcp_model,attack_surface,taxonomy,prompt_analysis,tool_poisoning,scope_analysis,memory_analysis,credential_analysis,threat_rules,verification,delta,queries,service}.py` (NEW, 20 modules)
- `docs/schemas/agent-security.schema.json`,
`agent-attack-surface.schema.json`,
`agent-threat-scenario.schema.json`,
`mcp-security-observation.schema.json` (NEW)
- `templates/agent-security/AGENT-SECURITY-TEMPLATE.yaml` +
`official/*.yaml` ×2 (NEW, trusted/schema-checked/
digest-stable)
- `tests/unit/test_agent_security.py` (20) +
`test_mcp_security.py` (7) +
`test_agent_security_isolation.py` (8) +
`test_agent_security_adversarial.py` (14) +
`tests/fixtures/agent_security/*` ×3 (NEW)
- (No mcp/skills/threat-modeling/policy/domain/CLI/reporting changes.)

## Invariant Impact
All 12 PASS: 1 read-only (no execution surface), 2
untrusted content (agent/tool/memory/model text quarantined
as data), 3 evidence-gated (observations require evidence
ids; scenarios without evidence stay hypotheses), 4 no
destructive transition (no grant/execute/remediate surface),
5 tool outputs as evidence (split trust surfaces, labels as
data), 6 explicit uncertainty (hypothesis/path/coverage
states everywhere), 7 shared contracts (schemas + frozen
models), 8 external provider choice (model endpoints
abstract; MCP versions data), 9 scanners authoritative
(untouched), 10 human review (passive handoffs, never
auto-confirm), 11 specialist worker (representations only),
12 host delegates (service owns workflow).

## Known Limitations
- Reference-style code analysis of agent source is out of
scope here; findings come from declared metadata.
- DOS elicitation is precondition-only (no perf facts).
- Delegation scope math is string-set based; semantic scope
understanding deferred.
- No MCP/CLI execution surfaces by design; read-only
analysis entry points deferred to a surface task.
- Secret detection relies on reference patterns + redaction,
not live secret scanning.

## Deferred Work
Live red teaming, jailbreak runners, agent runtimes/
sandboxes, exploit runners, MCP DAST, credential
harvesting, prompt mutation, behavior scoring, approval
workflows, monitoring, firewalls, remediation, policy
changes — each in its dedicated stage, especially the
Evaluation/Benchmark Lab. Per program note: POST-RC-011
(Knowledge & Regression Memory) must be designed against
the cross-audit isolation proven here.

## Evidence
- `pytest tests/unit/test_agent_security.py tests/unit/test_mcp_security.py tests/unit/test_agent_security_isolation.py tests/unit/test_agent_security_adversarial.py` → 49 passed.
- Full suite → 662 passed, 3 skipped. Schemas 21/21 valid.
- 2/2 official templates trusted, schema-checked, digest-stable.
- E2E workflows green with zero Findings.
- Files listed above.

## Final Status
**PASS** — agent/MCP security complete: declared-architecture
facts, separated identity/delegation, labeled capability
graph, version-scoped MCP topology, honest attack surface,
metadata-only framework mappings, trust-transition analyses,
hypothesis-grade scenarios, unevaluated controls,
snapshot-bound handoffs, presence-only deltas, allowlisted
queries, redacted evidence, report-safe projections,
adversarial battery contained, all tests green. EMO analyzes
agent architectures as a first-class surface — authority
stays downstream with proof.
