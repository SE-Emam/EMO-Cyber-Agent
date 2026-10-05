# POST-RC-005 — Code Intelligence Layer

## Objective
Give EMO program-structure facts — syntax, symbols, calls, dataflow,
taint paths, dependencies, routes, authorization boundaries, database
relationships — as a normalized, snapshot-scoped FACT layer feeding
Evidence → Correlation → Reasoning → Verification → Finding. The
layer answers "HOW IS THE PROGRAM STRUCTURED?" and never "IS THIS A
VULNERABILITY?".

## Scope
In scope: `CodeIntelligenceProvider` port, 20 normalized models,
snapshot-scoped in-memory graph with enforced limits, 15-query safe
query port with provenance, service (snapshot → analyze → evidence +
observations), mock + reference-local providers, 3 ToolSpecs,
`code-location` + `code-intelligence` public schemas, 36 offline
tests. Out of scope (deferred, contracts ready): full CPG,
interprocedural analysis, Joern/CodeQL adapters, binary analysis,
MCP/CLI surfaces, threat modeling (POST-RC-009).

## Architecture
Repository → CodeIntelligenceProvider → Normalized bundle →
CodeGraph (one per audit/project/snapshot) → CodeGraphQueryPort →
EvidenceItem + CodeObservation → EvidenceGraph → Correlation (owner
of candidates) → Reasoning → Verification → Finding. Provider output
never reaches security decisions directly; only the service path
(`create_snapshot → analyze → build_evidence →
derive_observations`) produces security-usable records.

## Core Port
`CodeIntelligenceProvider` (ABC): `provider_id`,
`provider_version`, `capabilities()` (subset of the 11 allowed),
`analyze(snapshot, files)`. Read-only only — no execution, mutation,
secrets, network, shell. External analyzers run inside the
Tool/Execution boundary; adapters normalize. Core imports no parser
libraries (stdlib `ast` lives in the reference adapter, not Core).

## Normalized Models
`CodeProject` (audit/asset/repo binding), `CodeSnapshot`
(provider/version/revision/digest + auto-limitation without
revision), `CodeFile`, `CodeSymbol`, `AstNodeReference`,
`CallEdge` (confidence + incomplete flag), `ControlFlowEdge`,
`DataFlowEdge`, `DependencyEdge`, `RouteEndpoint` (method/path/
handler/framework/auth link/downstream/state-changing),
`AuthorizationBoundary` (presence metadata), `DataSource`/`DataSink`
(versioned taxonomy-gated), `TaintPath` (TAINT_PATH_FOUND, never
CONFIRMED), `CodeComponent`, `DatabaseRelationship`,
`CodeObservation` (7 kinds, evidence mandatory), `QueryProvenance`.
Frozen, extra-forbidden. No provider-specific fields. No severity,
verdict, policy, or remediation anywhere (serialized-scan enforced).

## Project Identity
Every snapshot binds audit_id + asset + owner/repo/ref + provider +
provider version + timestamp + source digest. Cross-audit and
cross-project graph reuse denied (audit mismatch → OUT_OF_SCOPE;
independent graph objects per binding).

## Snapshot Model
Immutable instant: canonical file-digest map. Tampered file set →
SNAPSHOT_INVALID. Provider/version mismatch → SNAPSHOT_INVALID.
Missing revision → explicit limitation string (never assumed
reproducible). `check_fresh` rejects revision drift with
STALE_SNAPSHOT. Two analyses at different times are never assumed
the same source state.

## AST
Unified `AstNodeReference` contract (type/location/parent/symbol/
digest). Full ASTs are not stored in evidence — derived queries
are. Reference provider parses Python via stdlib `ast` (functions,
classes, imports, call sites); syntax errors degrade per file,
never crash the analysis.

## Symbols
`find_symbol` (substring, case-insensitive), `find_definitions`
(exact id), `find_references` (AST refs + callers). Audit- and
snapshot-scoped. Unknown languages still yield file nodes with
`language: unknown` — never an invented parser.

## References
Call sites recorded per function (Python) with cross-file
resolution by name: same-file → MEDIUM, cross-file → LOW +
`incomplete: true`. Static resolution is explicitly never claimed
complete.

## Call Graph
`callers`/`callees` BFS with depth cap (default 3, hard max 10 at
the port) and result cap. Cyclic graphs terminate (visited sets;
proven with a mutual-recursion fixture). Every edge carries
confidence, incompleteness, and provider source.

## Control Flow
`ControlFlowEdge` normalized (branch/loop/return/exception/state
kinds open). Structure present for future authorization, business
logic, and race/state analysis. No control-flow verdicts emitted.

## Data Flow
`source → intermediates → sink` edges with confidence, plus
`find_paths` / `find_sources_for_sink` / `find_sinks_for_source` /
`find_reachable_paths` queries. Demonstrated end to end on the SQL
fixture (request parameter → execute). Reference provider honestly
declares NO dataflow capability.

## Taint
`TaintSource`/`TaintSink` taxonomy-gated models + `TaintPath`
(source/sink/node path/locations/confidence/completeness/
provider). Output vocabulary is `TAINT_PATH_FOUND` with PARTIAL
completeness — confirmation stays with Correlation/Verification.
Taxonomy versioned (`v1.0`); unknown kinds rejected at construction.

## Dependencies
`DependencyEdge` (importer/package/version/module/reachability/
manifest). Parsed from `requirements.txt` + `package.json` by the
reference provider; scripted for the mock. Reaches OSV/Trivy
correlation later via (package, version, importer) triples — no
finding here.

## Routes
`RouteEndpoint` normalized across Flask/FastAPI/Express (method,
path, handler, framework, location, auth link, downstream,
state-changing for POST/PUT/PATCH/DELETE). Discovery proven on a
realistic mini-project. Discovered boundary ≠ vulnerability —
encoded as separate observation kinds.

## Authorization Boundaries
Decorator/config checks recorded with kind/location/protected
target/mechanism/confidence. Endpoint → boundary linkage powers
`authorization_paths` (present with mechanism vs absent). Absence
yields `UNRESOLVED_AUTH_BOUNDARY` — a missing-record fact, not a
vulnerability claim. A route-path false positive (`/login`
matching an auth hint) was found and fixed during development by
restricting matches to real decorator lines.

## Database Relationships
`queries_table`, `rls_guarded_by` (and open kinds) linking code
symbols to `public.*` objects with locations — the cross-layer
substrate (endpoint → service → table → RLS) for later
application/database correlation. No finding now.

## Graph Queries
15 allowlisted queries, fixed signatures, validated inputs
(length/control-char/path checks; hostile input → QUERY_REJECTED).
Provider query languages cannot pass through. Wildcards are
literal (no glob). Every query appends full provenance (type,
target, provider/version, snapshot/result digests, timestamp).

## Provider Capabilities
11 declared capabilities; providers claim subsets honestly
(reference: 7, no dataflow/taint; mock: all 11, scripted).
Capability ≠ permission — `PROVIDER_CAPABILITY_TO_REQUESTED` maps
to `code.*.read` requests for Tasks/Skills; PolicyEngine decides.
`supports()` helper for gating.

## Coverage/Confidence
Separated by construction: per-edge `ResolutionConfidence`
(HIGH/MEDIUM/LOW) vs graph `ResultQuality`
(COMPLETE/PARTIAL/INCOMPLETE/UNAVAILABLE) with `truncated` flag.
Provider confidence never equals security confidence — the two
vocabularies do not intersect (scanned).

## Evidence
`build_evidence` emits one `EvidenceItem` per query: source
`code-intel:<provider>`, redacted summary (secret-bearing sources
proven redacted), provenance (provider/version/snapshot/query/
coverage/contract version). Raw graph dumps are never stored.

## Provenance
Per-query records enable full re-investigation; snapshot digests
pin the analyzed file set; evidence provenance chains query →
snapshot → provider version. Forged provider provenance is
structurally impossible (provenance is service-built; bundles
carry no provenance channel — asserted in-test).

## Limits
Node/edge/traversal-depth/result/path-length budgets (defaults
50k/200k/25/1k/64, overridable tighter). Over-limit ingestion
raises `GRAPH_LIMIT_REACHED`; the service returns the partial
graph with `truncated` metadata — never silent truncation.
Oversized files (>200KB) are skipped without file nodes. Proven:
3000-symbol ingestion under tight budgets stays partial and
labeled.

## Security Boundaries
Queries cannot execute code, mutate repo/database, touch secrets,
open network, or run shell (AST-pinned across all 8 new files:
no subprocess/socket/requests/LLM/os/eval). External providers
enter only via `code-intel.*` ToolSpecs through
ToolRegistry → Policy → ToolExecutor → adapter.

## Mock Provider
`MockCodeIntelligenceProvider` with 9 scripted scenarios: simple,
cross-file auth flow, SQL taint flow, dependencies, Supabase
relations, incomplete resolution, malicious text, giant, cyclic.
Deterministic; broad capabilities claimed because bundles are
hand-normalized.

## Initial Provider
`ReferenceLocalProvider` (`reference-local 0.1.0`): stdlib-`ast`
Python analysis + JS/TS route/function patterns + manifest
parsing. Honest 7-capability declaration. Proven on a realistic
Flask mini-project (routes, boundary linkage, state-changing
flags, dependency versions).

## Contract Tests
One suite runs against every provider: capability-subset,
determinism, verdict-vocabulary ban, model validation, audit
isolation. A lying provider (claims taint, raises) → PROVIDER_ERROR;
garbage shapes → PROVIDER_ERROR; malformed locations/traversal in
bundles → rejected. Provider-specific behavior stays adapter-local
by construction (Core sees only normalized models).

## Security Tests
Dedicated: cross-audit/cross-project/stale-snapshot denial,
traversal/absolute/encoded paths, injection comments + evil
symbol names staying data (capabilities unchanged, search works,
authority untouched), forged-bundle rejection, oversized inputs,
cyclic termination, false-capability claims, query escaping +
command-injection-as-data, AST surface scan, secret redaction.
Malicious source alters nothing outside its own data records.

## Schemas
`code-location.schema.json` + `code-intelligence.schema.json`
(NEW, v1.0): location interop (traversal patterns rejected) and
snapshot/observation/provenance interop (7 observation kinds,
evidence mandatory). Real objects validate against both in-test.
Registry total now 10/10 valid. No schemas for internal graph
nodes — intentionally minimal per contract.

## Task/Skill/Playbook Integration
`PROVIDER_CAPABILITY_TO_REQUESTED` publishes the six `code.*.read`
requests Tasks will need (`code.ast.read`, `code.symbols.read`,
`code.callgraph.read`, `code.dataflow.read`, `code.routes.read`,
`code.dependencies.read`); Skills declare them without granting;
Playbooks resolve through existing Skill/Task/Tool resolvers plus
Policy — no independent path built. ToolSpecs register cleanly in
`ToolRegistry`. No task/skill/playbook templates changed (no
references needed yet).

## Known Limitations
- Reference provider: Python-only deep analysis; JS/TS is
pattern-level (LOW confidence); no dataflow/taint/CPG.
- Call resolution is name-based (no type inference, no dynamic
dispatch) — cross-file edges flagged incomplete.
- Manifest coverage: `requirements.txt` + `package.json` only
(lockfiles, poetry, cargo, go.mod deferred).
- Framework route coverage: Flask/FastAPI/Express patterns only.
- SQL content is not parsed (table names come from provider
relations, not query parsing).
- No caching layer yet (`CodeIntelligenceSnapshotStore`
deferred); no MCP/CLI surface by design.

## Deferred Capabilities
Full CPG, interprocedural analysis, language-specific deep
semantics, advanced taint, semantic race analysis, binary
analysis, tree-sitter/Joern/CodeQL adapters, snapshot store,
lockfile/manifest breadth, SQL parsing. Contracts accept all of
them without Core changes (capability-gated, normalized models
already carry the fields).

## Invariant Impact
1, 7, 11, 12 preserved structurally (read-only analysis, same
contracts, no cross-audit state, read-only defaults); 2, 5
enforced via untrusted-data handling (source text never
authority); 3, 4, 6, 8, 9, 10 untouched (no evidence/finding/
model/provider/scanner paths altered — new evidence flows into
existing `EvidenceItem` shape).

## Evidence
- `pytest tests/unit/test_code_intelligence.py` → 36 passed.
- Full suite → 444 passed, 3 skipped. Schemas 10/10 valid.
- Both providers pass the shared contract suite; reference
proven on a realistic mini-project; mini-project
endpoint→boundary→state-changing chain asserted.
- Files listed below.

## Files Inspected
- `core/repository.py` (`normalize_path`, `RepositoryPort`,
`RepositoryIdentity`, `build_evidence_provenance`,
`redact_credentials` — all reused, none duplicated)
- `core/contracts.py` (`EvidenceStore` ABC), `core/correlation.py`
(`EvidenceTrust`, `ObservationTaxonomy`, `SecurityObservation`),
`domain/models.py` (`EvidenceItem`), `core/tool_registry.py`
(`ToolSpec`), `core/execution.py` (boundary pattern)
- `adapters/` (flat-module convention; subpackage added)
- `docs/schemas/*.json` (conventions)

## Files Changed
- `src/emo_cyber_agent/code_intelligence/{__init__,spec,provider,graph,queries,service,errors}.py` (NEW)
- `src/emo_cyber_agent/adapters/code_intelligence/{__init__,mock,reference}.py` (NEW)
- `docs/schemas/code-location.schema.json`, `docs/schemas/code-intelligence.schema.json` (NEW)
- `tests/unit/test_code_intelligence.py` (NEW, 36 tests)
- (No Core/adapters-touched/tasks/skills/playbooks/CLI/MCP/reporting changes.)

## Final Status
**PASS** — fact layer complete: provider port, 20 normalized
models, snapshot identity, AST/symbols/calls, dataflow/taint
paths, dependencies, routes, authorization boundaries, database
relationships, capped graph + safe queries, provenance throughout,
evidence integration with redaction, mock + reference providers
passing one contract suite, malicious battery contained, all
tests green. The pivotal chain is now buildable: Repository →
Code Intelligence (endpoint/auth-boundary/call/dataflow/
dependency/database facts) → Supabase + Scanner facts → Evidence
Graph → Reasoner → Verification → Finding — structure first,
verdicts only downstream with proof.
