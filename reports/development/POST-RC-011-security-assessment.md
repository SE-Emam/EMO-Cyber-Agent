# POST-RC-011 — Security Knowledge & Regression Memory Assessment

## Objective
Give EMO scoped, provenance-preserving memory of security
observations and regression context — persistable knowledge
records, canonical fingerprints, honest before/after comparison,
precedence and staleness — with zero authority: stored memory is
evidence-indexing and context, never current evidence, never
Finding state, never a trust grant.

## Scope
In scope: `security_knowledge/` layer (14 modules), 9 persistable
categories, frozen knowledge/regression/reference contracts,
3 schemas, 15 closed error codes, deterministic fingerprints
(3 identity kinds + 7 regression keys), provenance chains,
memory policy (redact-diff secrets, verdict quarantine), scope
enforcement, store port + in-memory engine, 6 allowlisted
queries with history digests, closed regression state machine
(7 states) and comparator (6 results), precedence/staleness,
starter + 1 official template, 110 offline tests. Out of scope
(deferred): durable storage engines (file/DB/remote), retention
scheduler, deduplication across audits, embeddings/vector
search, trust scoring, knowledge graph reasoning, auto-expiry,
cross-tenant federation, live retrieval from external feeds.

## Architecture
Evidence/layers → memory policy (may this persist?) → atomic
record build (validate → canonicalize → digest → scope check →
persist) → store port (keyed `(audit, project, record)`,
idempotent by digest) → allowlisted query port (history-recorded)
→ regression comparator → precedence/staleness labels → report
projection. Change/Threat/Agent layers feed CONTEXT ONLY through
`remember_from_layer` (category derived from layer, trust pinned
to `untrusted`); the service owns no workflow beyond memory.

## Boundaries (enforced, tested)
No Findings (no Finding creation surface, no `finding_id` written,
no `create_finding`/`resolve`/`approve`/`promote` methods), no
severity/exploitability verdicts (verdict vocabulary quarantines
records to `quarantined`, never rejects them into authority), no
trust elevation (only 4 untrusted-family trust levels exist;
`trusted` is refused at construction with a domain error), no
delete/purge/forget surface (retention is metadata, not an
operation), no PolicyEngine interaction (static scan: no policy
import), no execution/provider surface (static AST scan bans
subprocess/socket/HTTP/eval/openai/anthropic/torch and
`model_weights`), no global namespace (every read and query binds
to caller `(audit, project)` + optional snapshot), no arbitrary
query language (6 names only; unknown names, raw/SQL/exec/delete
names, and forbidden scope markers rejected), no secrets at rest
(redact-diff: any text the redactor changes is denied persistence
and the store stays empty).

## Contracts
Frozen, extra-forbidden, digest-carrying models: `KnowledgeRecord`
(audit/project/snapshot/scope/source/category/evidence/content/
finding-ref/verification-ref/regression-key/trust/provenance/
retention), `KnowledgeReference` (digest handle),
`SecurityRegressionRecord` (7 closed states),
`RegressionComparison` (6 closed results + reason codes +
coverage + limitations), `KnowledgeScope/Access/Provenance/
Retention/Coverage`, `EvidenceFingerprint`/`ObservationFingerprint`
(3 identity kinds), `VerificationOutcomeRecord` (5 closed
results), `ExternalKnowledgeEnvelope` (never trusted on ingest:
only `untrusted-external`/`quarantined`), `KnowledgeTemplateConfig`
(semver + category allowlist). 15 `KnowledgeErrorCode` values;
verdict vocabulary (`resolved/confirmed/vulnerable/fixed/safe/
severity/exploitable/remediated`) is inert data everywhere.

## Identity & Fingerprints
Three identity semantics kept explicitly apart: `SNAPSHOT_IDENTITY`
(one snapshot), `STRUCTURAL_IDENTITY` (snapshot-agnostic,
fact-order independent), `REGRESSION_IDENTITY` (base+target).
Identity digests are built only from stable security-identity
components — no wall-clock, no random ids, no message ordering,
no formatting. Human-stable regression keys
(`regression:<type>:<identity>:<property>`) normalize case and
separators so `/Login/` ≡ `/login`.

## Atomicity & Idempotency
Every write runs validate → canonicalize (credentials redacted
inside content) → digest → scope check → persist. Any violation
raises `KnowledgeError` and leaves zero partial state (proven by
the empty-store assertion after each denied write). Re-ingesting
the same observation yields one record, one id, one digest;
re-storing a conflicting identity (same id, different digest)
raises `DUPLICATE_REGION`.

## Memory Policy
What may persist (9 categories, all else `BANNED_CONTENT`), what
must not (secret-bearing content), and how stored text is judged
(verdict tokens → quarantined, inert, never authority). Repetition
never raises trust: the service stores no trust scores at all.
Retention (`audit-lifetime`, legal hold, expiry) is metadata with
no scheduler and no deletion path.

## Scope Enforcement
Identity equality must be explicit: same fingerprint, same URL,
same key, same text never implies same scope. Cross-audit →
`CROSS_AUDIT`, cross-project → `CROSS_PROJECT`, cross-snapshot →
`CROSS_SNAPSHOT`, caller-less query → `SCOPE_DENIED`, namespace
mismatch → `SCOPE_DENIED`. `bind_query_scope` refuses any
requested identity outside the caller's own (including
empty-vs-set widening) and rejects forbidden markers
(`other_audit_id`, `raw_backend_query`, `path_escape`,
`tenant_scope`, `policy_override`).

## Regression, Precedence, Staleness
Closed before/after state machine: `NEW / PERSISTING / CHANGED /
DISAPPEARED / REINTRODUCED / INDETERMINATE / NOT_COMPARABLE`.
Absence only becomes `DISAPPEARED` under complete coverage;
incomplete coverage yields `INDETERMINATE` (absence is not
disappearance). Comparator results (`IDENTICAL / CHANGED / NEW /
MISSING / INDETERMINATE / INCOMPATIBLE`) carry reason codes and
limitations. Current evidence outranks history
(`SUPERSEDED/STALE` across snapshots, `CONTRADICTED` within one);
history is kept and labeled, never deleted by comparison.
Staleness is deterministic from snapshot + schema + component
versions (`FRESH_FOR_SCOPE / STALE / INCOMPATIBLE / UNKNOWN`).

## Queries, Templates, Integration
Six queries (`get_record`, `find_by_regression_key`,
`find_related_observations`, `compare_with_baseline`,
`list_project_regressions`, `get_prior_verification`) — audit/
project bound, unknown names rejected, every call recorded with a
result digest in query history. Templates are declarative
authoring contracts only (category allowlist + scope rules): the
official directory refuses non-official provenance and duplicate
ids. Change/Threat/Agent integration imports threat-modeling
helpers (`canonical_digest`, `stable_id`) and repository redaction
rather than reimplementing them; layer output attaches as
`CHANGE_REGRESSION_SIGNAL` / `THREAT_MODEL_OBSERVATION` /
`SECURITY_CONTROL_OBSERVATION` with `trust_level=untrusted`.

## Adversarial Results
Battery (all contained): 4 secret patterns denied with an empty
store afterward (also nested-structure variants); 4 clean texts
proven persistable; 4 verdict texts quarantined to `quarantined`
and returned only as inert data by an allowlisted query; 9 banned
categories rejected at both policy and record levels; forged
provenance (empty origin, unofficial official-dir template)
refused; digest tampering detected by digest recomputation;
conflicting identity refused; SQL/path-traversal identifiers
behaved as pure data (found/absent, never executed); 6 forbidden
query names rejected; external envelopes never trusted; static
AST scan proves no execution, network, or model-provider surface
and no authority verbs on the service.

## Tests
`test_security_knowledge.py` (27) +
`test_security_knowledge_isolation.py` (17) +
`test_security_knowledge_regression.py` (28) +
`test_security_knowledge_adversarial.py` (38) — 110/110:
contracts/digests/frozen models, all 9 categories, reference +
record + regression schema validation (fixtures included),
fingerprints (3 identity kinds, key normalization), query
allowlist + history, starter/official template loading and
provenance enforcement, isolation (audit/project/snapshot/
namespace/forbidden markers/store scoping/foreign layer context),
regression state machine ×7, comparator ×7, precedence ×4,
staleness ×5, baseline comparison, history retention, layer
context, adversarial battery, static surface scan, and the six
end-to-end workflows A–F (evidence round-trip; idempotent
re-ingest; baseline→target regression with disappearance;
two audits sharing a key without cross-visibility; hostile
evidence → inert quarantined memory; layer context stays inert
untrusted memory). Full suite: **772 passed, 3 skipped**.
Schemas 24/24 valid. Testing caught real defects: snapshot
filtering in `compare_with_baseline` (records were narrowed to
the baseline side, so every comparison reported `MISSING` instead
of `IDENTICAL`), trust-level validation leaking as a pydantic
error instead of a domain `KnowledgeError`, a secret fixture that
no redactor pattern actually matched (replaced with genuinely
redacted forms plus a proven-clean negative set), a blind
`Exception` assertion on frozen-model mutation (narrowed to
`ValueError`), unused imports in `records`/`regression`, and a
missing package export (`regression_key_for`).

## Files Inspected
- `core/repository.py` (redact-diff, content digests, path
  normalization), `core/contracts.py` (port conventions),
  `threat_modeling/spec.py` (`canonical_digest`, `stable_id`,
  verdict guard), `agent_security/{spec,memory_analysis}.py`
  (memory isolation precedents), `change_analysis/*` (context
  consumer), `core/resources.py` + `scripts/validate_schemas.py`
  (schema inventory), `docs/schemas/*.json` (conventions),
  `templates/{threat-modeling,agent-security,reports}/*`
  (template provenance conventions)

## Files Changed
- `src/emo_cyber_agent/security_knowledge/{__init__,spec,errors,
  fingerprints,provenance,records,memory_policy,scope,store,
  queries,comparator,regression,templates,service}.py` (NEW,
  14 modules)
- `docs/schemas/security-knowledge.schema.json`,
  `security-regression.schema.json`,
  `knowledge-reference.schema.json` (NEW; 24 total)
- `templates/security-knowledge/SECURITY-KNOWLEDGE-TEMPLATE.yaml`
  + `official/audit-default.yaml` (NEW)
- `tests/unit/test_security_knowledge.py` (27) +
  `test_security_knowledge_isolation.py` (17) +
  `test_security_knowledge_regression.py` (28) +
  `test_security_knowledge_adversarial.py` (38) +
  `tests/fixtures/security_knowledge/{knowledge_records,
  regression_pairs}.json` (NEW)
- (No core/change/threat/agent/CLI/reporting/policy changes.)

## Invariant Impact
All 12 PASS: 1 read-only (no execution, network, or deletion
surface; static-scanned), 2 untrusted content (memory text
quarantined/limited as data; layer/model context never trusted),
3 evidence-gated (records carry evidence ids; absent evidence
stays `INDETERMINATE`), 4 no destructive transition (no
Finding/trust/remediation mutation of any kind), 5 tool outputs
as evidence (observations stored with provenance, labels as
data), 6 explicit uncertainty (coverage/precedence/staleness/
comparator states everywhere), 7 shared contracts (frozen models
+ 3 schemas + redaction/digest helpers reused), 8 external
provider choice (no provider imports; external envelopes
untrusted-by-contract), 9 scanners authoritative (scanner
observations land as `TOOL_OBSERVATION` context only), 10 human
review (memory never auto-confirms; prior verification is
context), 11 specialist worker (memory serves, never decides),
12 host delegates (service owns storage choice behind a port).

## Known Limitations
- In-memory store only: no durability across processes; the
  `SecurityKnowledgeStore` port exists for a future engine.
- Secret detection relies on reference redaction patterns, not
  live secret scanning.
- Comparison is content-digest based; semantic equivalence of
  reworded content is not detected (reported as `CHANGED`).
- Retention/expiry is metadata only — nothing is ever auto-
  deleted, and no legal-hold workflow exists yet.
- `find_related_observations` matches source id / regression key
  substrings within scope; no fuzzy or embedding retrieval.
- One official template so far; template proliferation deferred
  until real audit profiles exist.

## Deferred Work
Durable storage engines (file/SQLite/remote with the same port),
retention/legal-hold execution, cross-record deduplication,
embedding/vector retrieval, knowledge-graph reasoning over
records, external feed ingestion with license tracking,
multi-version template registry, and Evaluation Lab regression
benchmarks — each in its dedicated stage.

## Evidence
- `pytest tests/unit/test_security_knowledge.py
  tests/unit/test_security_knowledge_isolation.py
  tests/unit/test_security_knowledge_regression.py
  tests/unit/test_security_knowledge_adversarial.py`
  → 110 passed.
- Full suite → 772 passed, 3 skipped. Schemas 24/24 valid
  (`scripts/validate_schemas.py`).
- `ruff check` clean on the new layer and tests.
- 1 starter + 1 official template loaded, provenance-enforced,
  category-allowlisted.
- E2E workflows A–F green with zero Findings.
- Files listed above.

## Final Status
**PASS** — security knowledge & regression memory complete:
atomic redacted records with digest identity, complete provenance
chains, three explicit fingerprint semantics, a closed regression
state machine with honest coverage, precedence and staleness that
label history instead of overwriting it, a six-name query surface
with recorded digests, enforced template provenance, and full
cross-audit/project/snapshot isolation — with memory that stays
inert, untrusted context all the way to the report. Authority
stays downstream with proof.
