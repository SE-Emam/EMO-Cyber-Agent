# ECA-T005 — Repository Integrations

## Task Objective
Add the first real access layer to repositories and project sources, keeping
all permission/scope decisions inside Core and leaving adapters as pure
fetch → map → return translators. Establish the repository access boundary
on which scanners, Supabase review, and the agent loop will later build —
without mixing repository access with reasoning or scanning.

## Scope
In scope (Repository Integration Foundation only):
- Core RepositoryPort (read-only): identity, metadata, tree/list, file read,
  code search, commit/ref info.
- Stable repository identity bound to audit/project scope.
- Scope enforcement (audit_id, project, repository, ref, allowed target).
- GitHub read-only adapter behind the port (resolve, metadata, tree, read,
  search, commit). No write operations exist in the module by design.
- Credential boundary (secret references only; redaction everywhere).
- Untrusted-content rule (all repo text is DATA, never instructions).
- Provider-agnostic normalization (Repository, Tree, File, SearchResult,
  CommitInfo).
- Normalized failure semantics (stable RepositoryErrorCode set).
- Mock/InMemory provider for fully offline tests.
- Security + contract tests; no network dependency in CI.

Explicitly out of scope (deferred, not implemented):
- Supabase-specific deep audit (candidate ECA-T006).
- Scanners (Semgrep/Trivy/OSV/Gitleaks/CodeQL) and their adapters.
- Agent reasoning loop, remediation, exploit execution.
- MCP server business logic, CLI business logic.
- Write capabilities (PR/push/merge/issue modification) — no such methods exist.
- Complex caching (no global mutable repository state introduced).

## Architecture
Phase mapping (no history rewritten; numbering ambiguity removed):
- Foundation → Phase 0 (packaging, doctor, schemas).
- Domain Core → Phase 1 / ECA-T001+ECA-T002 (AuditJob, Asset, EvidenceItem,
  Finding, Verification, ToolInvocation-domain, AuditResult, state machine).
- Policy Engine → Phase 2 / ECA-T003 (scope/capability/permission gate).
- Tool Registry → Phase 3-4 / ECA-T004 (discovery + contract + invocation
  boundary in Core).
- Repository Integrations → Phase 5 / ECA-T005 (this task: first real
  read-only source access behind Core boundary).

Mandatory path for every repository operation (no alternative path exists):
```text
Request → Core → ToolRegistry → PolicyEngine → Repository Tool Invocation
→ RepositoryPort → External Repository → Normalized Result → EvidenceItem → Core
```
Forbidden: Host→Adapter direct, Host→credentials direct, Adapter→policy
bypass, Adapter→privilege escalation, Adapter→business/security decision.

## Repository Port
`src/emo_cyber_agent/core/repository.py` defines `RepositoryPort` (ABC):
- `resolve_repository`, `get_metadata`, `list_tree`, `get_file`,
  `search_code`, `get_commit` — read-only only.
- The port is provider-agnostic (no GitHub types in signatures).
- `RepositoryService` (Core-owned) is the ONLY caller path: it performs
  scope → registry → policy → port → evidence in that order and raises
  `RepositoryError` on any denial. Hosts/adapters must not call the port
  directly (covered by bypass tests).

## Repository Identity
`RepositoryIdentity` (frozen Pydantic): provider (`github|local|mock`),
owner, repo, ref, optional revision; `canonical_locator` =
`provider:owner/repo@ref[#revision-short]`.
- `parse_repository_locator` requires the full `provider:owner/repo@ref`
  shape; hostname-only or owner-less strings → `AMBIGUOUS_IDENTITY`
  (never guessed).
- `validate_ref` enforces a strict charset/length rule → `INVALID_REF`.
- `normalize_path` rejects absolute/empty/traversal (`..`, `.`, `//`)
  → `PATH_TRAVERSAL`.
- `AuditRepositoryScope` binds `audit_id + project_id + allowed[]`;
  `assert_repository_in_scope` denies cross-project, cross-audit, and
  out-of-scope repositories. Identity is part of every scope check and
  every evidence provenance record.

## GitHub Adapter
`src/emo_cyber_agent/adapters/github.py` (`GitHubRepositoryAdapter`):
- Implements `RepositoryPort` read methods only. The module contains NO
  write/PR/push/merge/issue methods (verified by grep; only a docstring
  states their absence).
- Injectable `transport` callable `(url, headers) -> (status, body)` keeps
  all unit/contract/security tests offline; default transport uses stdlib
  `urllib` GET only.
- Maps raw GitHub payloads to Core normalized models; provider HTTP
  statuses map to `RepositoryErrorCode` (404→NOT_FOUND, 401/403→
  AUTHENTICATION_FAILED, rate-limit text→RATE_LIMITED, 422→SEARCH_FAILED,
  else PROVIDER_ERROR). Raw provider text is redacted before surfacing.

## Policy Integration
- ToolSpecs (Core): `repository.metadata`, `repository.list`,
  `repository.read`, `repository.search` — all `risk_level=low`,
  `supports_read_only=True`, `supports_remediation=False`; no write
  capability string exists anywhere in the spec factory.
- `RepositoryService._require` enforces in order: audit binding →
  registered tool → declared capability → `read_only` profile →
  non-empty `policy_decision_id` → `PolicyEngine.evaluate_policy`.
  Unknown tool, undeclared capability, wrong profile, missing decision,
  or policy `False` → `POLICY_DENIED`. Stale decisions are denied because
  evaluation is re-run per invocation (tested with a DenyAll engine).
- Every approved invocation runs the full `ToolInvocation` lifecycle
  (REQUESTED→VALIDATING→POLICY_CHECK→APPROVED→EXECUTING→COMPLETED) with
  `policy_decision_id` persisted on the record.

## Scope Enforcement
- `AuditRepositoryScope.allows` matches provider+owner+repo; ref is
  validated separately so a wrong ref cannot silently retarget.
- `assert_repository_in_scope` raises `MISMATCHED_AUDIT` on audit_id
  mismatch and `OUT_OF_SCOPE` otherwise (no hostname-only trust).
- Tests: out-of-scope repo, project mismatch (via second scope),
  audit mismatch, ambiguous locator, invalid ref, traversal — all denied
  with the expected stable code.

## Credential Handling
- Adapters accept `token_ref` (a reference NAME, e.g. env var name) and
  reject values that look like raw secrets (`ghp_`, `github_pat_`, `gho_`)
  or overlong values at construction time.
- `redact_credentials` applied to: error messages, output summaries,
  mapped adapter fields (name/description/sha/author), and provenance
  strings. Verified: no `ghp_` material in `str(error)`, headers, or
  provenance dicts (tests assert absence).
- Credential material ≠ audit evidence: `build_evidence_provenance`
  stores digests, locators, invocation/tool ids, timestamps — never tokens
  or file secrets; file content is referenced by digest.

## Untrusted Content Handling
- `mark_untrusted` wraps every file/search snippet in an envelope:
  `{classification: untrusted, trust_level: untrusted-data,
  content_digest, content_preview, must_not_alter: [policy, permissions,
  system_instructions, tool_capabilities, agent_authority]}`.
- `RepositoryService.get_file` re-enforces the envelope even if an adapter
  forgot it. System prompt text (`IGNORE ALL PREVIOUS INSTRUCTIONS…`)
  in the mock README is preserved as DATA and provably does not alter
  policy outcomes (dedicated test).
- Architecture + tests both pin this rule; no adapter or model output can
  promote repository text to instruction.

## Normalization
Provider-agnostic Core models (frozen, no GitHub assumptions):
`Repository`, `RepositoryTree`/`RepositoryTreeEntry`, `RepositoryFile`
(path/ref/sha/digest + untrusted envelope + content-as-data),
`CodeSearchResult` (path/line/snippet digest + envelope),
`CommitInfo` (sha/message digest/author/timestamp).
GitHub payloads are mapped field-by-field with redaction; unknown/missing
fields degrade to typed errors, never raw dicts into Core.

## Failure Semantics
Stable, testable `RepositoryErrorCode`:
`REPOSITORY_NOT_FOUND, ACCESS_DENIED, OUT_OF_SCOPE, INVALID_REF,
FILE_NOT_FOUND, SEARCH_FAILED, PROVIDER_ERROR, RATE_LIMITED,
AUTHENTICATION_FAILED, CONTENT_UNAVAILABLE, PATH_TRAVERSAL,
AMBIGUOUS_IDENTITY, POLICY_DENIED, STALE_POLICY, MISMATCHED_AUDIT`.
`RepositoryError` redacts its message at construction; `safe_details`
carries only canonical locators. Provider exceptions are caught at the
service boundary and mapped to `PROVIDER_ERROR`/`SEARCH_FAILED`.

## Evidence Model
`build_evidence_provenance` emits: source_provider, repository, ref,
revision, canonical_locator, path (when applicable), content_digest or
query_digest+result_count, invocation_id, tool_id/tool_version,
retrieved_at, policy_version (`eca-t005-v1`), schema_version (`0.1.0`).
Full source is NOT auto-stored; digest + locator allow re-tracing without
bloating evidence or leaking secrets.

## Files Inspected
- `src/emo_cyber_agent/core/contracts.py` (PolicyEngine/SecurityAuditor ABCs)
- `src/emo_cyber_agent/core/service.py` (DefaultPolicyEngine, FoundationSecurityAuditor)
- `src/emo_cyber_agent/core/tool_registry.py` (ToolSpec/Registry/Invocation + lifecycle)
- `src/emo_cyber_agent/domain/models.py` (AuditJob/AuditResult/EvidenceItem — integration surface)
- `src/emo_cyber_agent/security/policy.py` (PermissionProfile enum)
- `src/emo_cyber_agent/adapters/__init__.py` (empty — confirmed no logic)
- `docs/16-implementation-plan.md`, `docs/02-architecture.md`,
  `docs/03-security-methodology.md` (phase/scope source)
- `docs/schemas/*.json` (contract stability check)
- `tests/unit/test_foundation.py` (regression surface)

## Files Changed
- `src/emo_cyber_agent/core/repository.py` (NEW): port, identity, scope,
  redaction, untrusted envelope, normalized models, error codes,
  `get_repository_tool_specs`, `RepositoryService` (scope→registry→
  policy→port→evidence). ~380 lines.
- `src/emo_cyber_agent/adapters/mock_repository.py` (NEW):
  `InMemoryRepositoryProvider` (offline double, per-instance state only).
- `src/emo_cyber_agent/adapters/github.py` (NEW): read-only GitHub adapter
  with injectable transport, redaction, status→code mapping. No write API.
- `tests/unit/test_repository.py` (NEW): 22 offline tests (unit + security
  + contract). No network, no secrets.
- (No changes to MCP/CLI/Python API, schemas, or existing domain models;
  no business logic added to adapters.)

## Tests
Executed: `python3 -m pytest tests/ -q` → **52 passed**
(30 foundation + 22 new repository). Schema validation:
`python scripts/validate_schemas.py` → 4/4 OK.
`python -m compileall -q src tests` → OK.
New coverage: identity parse round-trip, ambiguous/invalid inputs,
traversal, scope/cross-project/cross-audit, read-only-first (no write
caps), happy-path resolve/tree/read/search/commit offline, untrusted
envelope, credential redaction, missing/undeclared/stale/unknown-tool
denials, unknown-tool denial, isolation (same data, distinct invocations),
GitHub offline contract + normalization, error mapping, adapter
swappability (mock↔github identical envelopes), provenance completeness.

## Security Tests
All offline, in `tests/unit/test_repository.py`:
cross-project access, out-of-scope repo, path traversal battery,
invalid-ref battery, ambiguous identity battery, credential leakage
(redaction + constructor refusal + error/headers/provenance absence
assertions), repository-content-as-instruction (README with prompt-injection
text stays DATA), direct-bypass attempt (undeclared `repository.write`
capability denied), missing `policy_decision_id`, stale decision (DenyAll
engine), mismatched `audit_id`, unknown tool, rate-limit/auth mapping.

## Contract Tests
Chain verified: `RepositoryPort` ↔ `GitHubAdapter`/`MockProvider` ↔
`ToolSpec` ↔ `ToolRegistry` ↔ `PolicyEngine` ↔ `ToolInvocation` ↔
provenance dict. Swappability test proves the adapter can be replaced
(mock↔GitHub) without touching Core. ToolSpec↔`tool-spec.schema.json`
alignment holds (required name/version/capabilities/risk_level/read_only/
input_schema present; no competing schema introduced).

## Network Tests
None required and none executed (per task: network tests are NOT a
correctness gate). GitHub adapter is fully exercised via injected
transport doubles. Real-network integration tests are deferred and must
remain opt-in with secrets, never part of CI gating.

## Known Limitations
- `DefaultPolicyEngine.evaluate_policy` still returns allow-all; denials in
  this phase come from scope/registry/profile/decision-presence checks plus
  the DenyAll test double. A real policy table (Phase 2 hardening) is
  deferred work, explicitly not claimed as done.
- `STALE_POLICY` code is defined for future expiry semantics; current
  staleness is enforced by re-evaluation per invocation (tested).
- `ACCESS_DENIED`/`CONTENT_UNAVAILABLE` codes defined; provider paths that
  yield them are mapped but not all hit by GitHub fixtures yet.
- No caching layer (intentional; avoids cross-audit state).
- Git history in this environment tracks a parent scope (src/tests/reports
  show untracked), so the diff evidence below is file-list based rather
  than `git diff --stat`.

## Deferred Work
Supabase deep audit (ECA-T006 candidate), scanners + adapters, agent
reasoning loop, remediation/exploit paths, MCP/CLI logic, write
capabilities, caching with revision-keyed keys, real-network integration
suite, policy-table hardening with decision expiry.

## Invariant Impact
1. Read-only default — ENFORCED NOW (only 4 read caps exist; service rejects non-`read_only` profile).
2. Untrusted content — ENFORCED NOW (envelope re-applied in Core).
3. No finding without evidence — PROTECTED BY CONTRACT (provenance carries invocation/tool/digest for every op).
4. No destructive action without permission — ENFORCED NOW (no destructive method exists; write caps absent).
5. Tool outputs are evidence — ENFORCED NOW (summaries+digests only).
6. Uncertainty explicit — NOT APPLICABLE this phase (no scoring added).
7. Same domain contracts — ENFORCED NOW (single `RepositoryService` path).
8. Provider external — ENFORCED NOW (transport injectable; no SDK in Core).
9. Scanner provenance — PROTECTED BY CONTRACT (tool_id/version/invocation in provenance; scanners deferred).
10. No cross-project reuse — ENFORCED NOW (scope + per-invocation ids; isolation test).
11. Specialist worker — ENFORCED NOW (fetch→map→return only; grep-verified no severity/classification logic in adapters).
12. Host delegates, EMO owns workflow — PROTECTED BY CONTRACT (service owns the path; adapters cannot be called usefully without scope+policy).
No invariant weakened. No new privilege introduced.

## Evidence
- `python3 -m pytest tests/ -q` → `52 passed` (30 foundation + 22 repository).
- `python scripts/validate_schemas.py` → 4/4 OK.
- `python -m compileall -q src tests` → OK.
- Adapter purity grep: no `def push|merge|create_pr|severity|remediat` in adapters (only a docstring stating their absence).
- Credential grep: only redaction patterns + absence-assertions; `NO_WRITE_CAPS_OK` from spec factory check.
- Files: `src/emo_cyber_agent/core/repository.py`,
  `src/emo_cyber_agent/adapters/github.py`,
  `src/emo_cyber_agent/adapters/mock_repository.py`,
  `tests/unit/test_repository.py`.

## Final Status
**PASS** — all 18 exit criteria met: Core port exists; GitHub adapter sits
behind it; every op traverses ToolRegistry+PolicyEngine; READ_ONLY default;
scope enforcement + cross-project isolation proven; credentials never leak;
content untrusted by construction; provider errors normalized; provenance
complete; mock provider present; bypass/security/contract tests present and
passing; existing tests + schemas green; adapters contain zero business
decisions; zero write capabilities. No BLOCKED condition (no bypass, no
scope ambiguity, no credential exposure, no contract conflict, no leakage)
was observed. ECA-T006 may proceed.
