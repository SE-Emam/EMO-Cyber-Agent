# ECA-T009 — Security Reasoning Engine & Agent Loop

## Objective
Build the first REAL reasoning loop: an AuditJob enters, a bounded
observe→hypothesize→plan→validate→authorize→execute→correlate→reassess
cycle runs, and the session ends with observations/candidates plus a
redacted audit trail. The model proposes; Core validates; StrictPolicy
authorizes; Registry resolves; tools prove; correlation informs. The model
is NEVER the security authority — enforced in code, tested, not documented.

## Scope
In scope: ReasoningSession + 15-state machine, ReasonerProvider/
ReasonerResponse/Action contracts, 7 typed action kinds, Core action
validation (incl. traversal/absolute/shell/privilege-field denial),
StrictPolicy-gated tool delegation, EvidenceContext-only model input,
6-state hypotheses with graph-grounded confidence, bounded loop (budgets,
loop/no-progress detection), 13 investigation phases (non-rigid labels),
cross-source reasoning via ECA-T008 re-entry, candidate-only outputs,
injection/tool-output boundaries, redacted audit trail, 11 failure codes,
11-scenario mock provider, 29 offline tests.
Out of scope (deferred): real model providers (no vendor SDK in Core),
exploit confirmation/mutation/penetration, write ops, remediation,
reporting engine (ECA-T010 owns verification execution; later phase owns
reporting).

## Architecture
```text
Audit Request → ReasoningSession → Observe → Classify → Hypothesize → Plan
→ Action Proposal → Core Validation → ToolRegistry → StrictPolicyEngine
→ ToolExecution → Evidence → Correlation → Reasoning Update → Candidate
→ more evidence? YES ↩ / NO → conclude → (Report later)
```
`src/emo_cyber_agent/core/reasoning.py` (~640 lines) owns session, loop,
and validation. `adapters/mock_reasoner.py` is test-only. No MCP/CLI
changes; no new public schemas (internal Core contracts).

## ReasoningSession
Frozen model: session_id, audit_id (scope anchor — a session can never
observe another audit), phase, status, iteration (counts loop passes, NOT
transitions — transitions never consume budget), budget, started/updated
timestamps, hypothesis/action id lists, evidence_context_id,
termination_reason, tool_calls, no_progress_streak.

## State Machine
INITIALIZING → OBSERVING → HYPOTHESIZING → PLANNING → {REQUESTING_ACTION →
WAITING_FOR_RESULT → CORRELATING → REASSESSING} → OBSERVING… → CONCLUDING
→ COMPLETED; terminals COMPLETED/FAILED/BLOCKED/BUDGET_EXHAUSTED/
USER_STOPPED have zero outgoing edges. Extra legal edges: PLANNING →
REASSESSING (rejection path) and PLANNING → OBSERVING (bounded retry
re-observes). All transitions deterministic and test-pinned (valid flow +
invalid-transition denial + terminal closure).

## ReasonerPort
`ReasonerProvider.propose(context, state, allowed_capabilities, objective)
→ ReasonerResponse`. Receives redacted context + loop state + capability
allow-list + objective string. Returns structured output only. Cannot
execute tools, raise permission, touch policy/repos/DBs, or write anything
(ABC with no capabilities — verified by inspection; engine never grants
it any handle).

## Response Contract
`ReasonerResponse`: response_id, session_id (must match — mismatch →
FAILED), bounded analysis_summary (2000 chars), hypothesis drafts,
≤5 typed next_actions (constructor DENY on excess), requested_observations,
uncertainty 0–1 (informational only, never becomes confidence),
termination_request. Free text is never interpreted as command.

## Action Contract
`ReasonerAction`: kind ∈ {OBSERVE, SEARCH, READ, SCAN, CORRELATE,
REQUEST_VERIFICATION, CONCLUDE}; tool actions carry tool_id/target/
structured parameters/reason/expected_evidence. Constructor denies
raw-shell fields (`command/shell/script/cmd/exec/system/eval`) AND
privilege-smuggling fields (`profile/permission(s)/role(s)/privilege(s)/
admin/sudo/escalate`) — the model may recommend verification in prose,
but can never set authority fields.

## Tool Delegation
Validated action → capability derived from the registered spec (first
allow-listed cap; unknown tool/capability → deny) → `StrictPolicyEngine.
issue_decision` → on ALLOW, injected `execute_tool` callable runs (tests
wire fakes or the REAL `ToolExecutor` + mock port + scanner adapters) →
results stored audit-scoped → correlation → reassess. No fallback to
arbitrary shell exists anywhere on this path.

## Policy Boundary
Model decides NOTHING about ALLOW/DENY/profiles/escalation: engine
hardcodes profile `read_only`; smuggled `parameters.profile=remediate`
is rejected at validation (test-pinned, zero calls); unknown tools,
undeclared caps, out-of-scope targets (via scope-aware engine), missing/
stale/mismatched decisions all deny. Executor additionally requires
`StrictPolicyEngine` (TypeError otherwise — ECA-T007 gate inherited).

## EvidenceContext
Provider input built by deterministic `select_relevant_evidence`
(hypothesis-asset overlap + security-salient labels + recency, capped by
`max_evidence_context`): per-item id/tool/locator/redacted 300-char
summary/digest/timestamp + hypothesis snapshots. Never: raw secrets,
foreign-audit items (test-pinned), hidden system content, credentials.

## Hypothesis Model
`SecurityHypothesis`: id, audit, category, statement, supporting/
contradicting evidence ids (foreign-audit refs dropped at ingest),
deterministic confidence (recomputed from graph counts on reassess),
status ∈ {OPEN, SUPPORTED, CONTRADICTED, NEEDS_EVIDENCE, DISMISSED,
PROMOTABLE}, timestamps. Model uncertainty (e.g. 0.99) never transfers —
test asserts engine values stay graph-grounded.

## Reasoning Loop
10 steps per task §12, implemented as: observe → gaps (relevance) →
hypothesize (draft ingest) → plan (first action) → Core-validate →
policy → execute-if-allowed → evidence-store → correlate → reassess →
repeat/conclude. Stopping: termination request, empty action list,
CONCLUDE action, loop detection, no-progress limit, any budget, model
failure. No infinite loop is constructible (every path either progresses
counters or terminates).

## Budget
`LoopBudget`: max_iterations (passes, default 12), max_tool_calls (8),
max_wall_time_s (300), max_evidence_context (20), max_repeated_action (2),
no_progress_limit (2). Any breach → BUDGET_EXHAUSTED (or no-progress
conclude). Exhaustion never yields a verdict — result carries candidates
only, possibly empty.

## Loop Detection
`action_fingerprint` (kind|tool|target|sorted-params) counted per session;
repeat beyond `max_repeated_action_count` → loop-conclude (tested: 10×
identical script stops after ≤3 executions). Repeated denials feed the
no-progress streak instead of spinning.

## Progress Detection
Each pass must yield ≥1 of NEW_EVIDENCE / NEW_RELATIONSHIP /
HYPOTHESIS_UPDATE / NEW_CANDIDATE / CONFLICT / CONCLUSION (tool passes use
real outputs: empty results + no correlation yield = no progress).
`no_progress_limit` breaches conclude without verdict (tested).

## Cross-Source Reasoning
Seeded GitHub + Supabase + scanner facts join through shared asset ids in
the ECA-T008 engine after every tool result (never tool→model direct —
re-entry is mandatory in code). Multi-step strategy (endpoint → identifier
→ DB access → RLS → authorization comparison → candidate) executes as
separate auditable actions. Cross test yields ≥1 candidate, zero
CONFIRMED language. Verification stays a recorded proposal (tool_calls 0).

## Prompt Injection Defense
Repository/README/SQL/policy/scanner/commit text enters the provider ONLY
inside redacted `EvidenceContext` summaries as DATA. Attack battery:
injection-worded reasons, hostile tool ids, traversal targets, smuggled
raw-shell params (bypassing constructors via `model_construct` to prove
the ENGINE boundary holds) — all rejected, zero calls, zero storage, zero
authority change. Tool output likewise stays observation DATA (ECA-T007
envelopes preserved end-to-end).

## Auditability
Every pass appends `IterationRecord` (iteration, context digest, hypothesis
snapshot, action fingerprint, policy result, invocation id, evidence ids,
transition, termination reason). Trail is secret-free (gitleaks-token test)
and contains NO chain-of-thought dump — field set is fixed and pinned
(decision summary + rationale fingerprint + references + transitions).

## Failure Semantics
11 codes: MODEL_UNAVAILABLE (provider raise → FAILED, never a conclusion),
MODEL_INVALID_RESPONSE (session mismatch / excess actions / smuggled shell →
FAILED or bounded single retry then reassess), ACTION_REJECTED,
POLICY_DENIED, TOOL_UNAVAILABLE/FAILED (distinct, via executor errors),
NO_PROGRESS, LOOP_DETECTED, BUDGET_EXHAUSTED, CONTEXT_LIMIT (cap enforced),
SECURITY_BLOCKED. Model failure never equals security conclusion.

## Mock Reasoner
11 queue-driven scripts (all 11 task scenarios incl. SAFE_RECON,
AUTHORIZATION/SQL/SUPABASE/DEPENDENCY investigations, PROMPT_INJECTION,
PRIVILEGE_ESCALATION, LOOP, INVALID_RESPONSE, NO_PROGRESS,
BUDGET_EXHAUSTION); queue exhaustion auto-concludes; seen-contexts
recorded for isolation assertions. No external model in any gating test.

## Tests
`pytest tests/ -p no:warnings` → **155 passed, 3 skipped** (126 prior +
29 new; skips are pre-existing optional binary probes). New: session
init/transitions/terminals; malformed/unavailable/oversized/invalid-tool/
missing-target/repeat/budget/no-progress; escalation/write/destructive/
scope/traversal/shell/injection/output-as-data; full registry→policy→
tool→evidence→correlation→hypothesis chain; REAL ToolExecutor wiring
(semgrep mock → 2 stored evidence); verification-proposal-only;
cross-source authorization; audit/project isolation (context + ref
filtering); redacted structured trail; no-CoT field pin; graph-grounded
confidence; context minimality; all-5-investigation-scenarios clean.

## Security Tests
In `test_reasoning.py`: escalation battery (2 scenarios, 0 calls, 0
stored items), write/destructive denial, scope-aware out-of-scope,
traversal/absolute/null-byte targets, smuggled raw-shell params (engine
boundary, not just constructor), injection-worded proposals, malicious
tool-output storage without authority change, cross-audit context/ref
exclusion, cross-project non-merge, secret-free trail + context.

## Files Inspected
- `core/contracts.py`, `service.py`, `policy.py`, `tool_registry.py`,
  `execution.py`, `scanners.py`, `repository.py`, `supabase.py`,
  `correlation.py` (all integration surfaces)
- `domain/models.py`, `adapters/*` (github/mock_repository/supabase/
  mock_supabase/mock_scanners), `docs/16/02/03`, `docs/schemas/*`
- `tests/unit/test_foundation|repository|supabase|toolchain.py`

## Files Changed
- `src/emo_cyber_agent/core/reasoning.py` (NEW, ~640 lines): session/state
  machine, provider/response/action/hypothesis contracts, deterministic
  relevance, validation (shell/privilege/traversal), bounded loop with
  budgets/loop/progress detection, correlation re-entry, redacted trail.
- `src/emo_cyber_agent/adapters/mock_reasoner.py` (NEW): 11-scenario
  scripted provider (test-only).
- `tests/unit/test_reasoning.py` (NEW): 29 offline tests.
- (No MCP/CLI/API/schema/domain changes; no vendor SDK; no verifier.)

## Schemas
No new/changed public contracts (reasoning objects are internal Core
state, same strategy as ECA-T008: domain = truth, schemas = serialized
contracts only when public). 4/4 existing schemas valid.

## Invariant Impact
1. Read-only — ENFORCED (engine profile hardcoded; write/destructive denied).
2. Untrusted content — ENFORCED (injection battery; envelopes end-to-end).
3. No finding without evidence — ENFORCED (engine emits observations/ candidates only, via evidence-bound correlation).
4. No destructive action — ENFORCED (no destructive path exists).
5. Tool outputs are evidence — ENFORCED (output→store→correlate mandatory re-entry).
6. Uncertainty explicit — ENFORCED (model uncertainty informational; confidence graph-computed).
7. Same contracts — ENFORCED (single engine path for all adapters).
8. Provider external — ENFORCED (no SDK; provider is an injected ABC).
9. Scanner provenance — ENFORCED (invocation ids flow into evidence).
10. No cross-project reuse — ENFORCED (audit-scoped store/context/refs).
11. Specialist worker — ENFORCED (security loop only; no general agency).
12. Host delegates — PROTECTED (session result is the delegation return).
No invariant weakened; model authority explicitly absent by construction.

## Known Limitations
- `execute_tool` is injected, not yet wired to a production audit runner
  (that wiring is release integration, outside Core).
- Relevance scoring is heuristic-weighted but fully deterministic.
- Investigation phases are advisory labels; ordering follows evidence.
- Wall-time budget uses monotonic clock (test-friendly, stated).

## Deferred Verification
Per task §33: REQUEST_VERIFICATION records proposals only (tool_calls
stays 0 — tested). Active confirmation/mutation/penetration/remediation
belong to ECA-T010. No reporting engine here either (structured
`SessionResult` only).

## Evidence
- `pytest tests/ -p no:warnings` → `155 passed, 3 skipped`.
- `validate_schemas.py` → 4/4 OK. `compileall` → OK. No new-module warnings.
- Purity: no Finding/shell/subprocess/policy-eval constructs in reasoning
  path beyond the engine's own legitimate policy calls; mock attack payloads
  are test data, rejected as designed.
- Files: `core/reasoning.py`, `adapters/mock_reasoner.py`,
  `tests/unit/test_reasoning.py`.

## Final Status
**PASS** — all 24 exit criteria met: session + state machine, integrated
reasoner port, structured responses, typed tool-action contract, no direct
execution, Registry+StrictPolicy on every tool action, EvidenceContext-only
input, hypothesis model, bounded loop with detection on all three axes,
cross-source candidates without confirmation language, no finding
authority, injection/tool-output boundaries, full audit trail, malformed
handling with bounded retry, mock scenarios, security tests, prior suites
+ schemas green. No BLOCKED condition (no bypass, no direct invocation, no
escalation, no cross-audit access, no instruction promotion, no
evidenceless finding) observed. ECA-T010 (Verification Layer) may proceed —
and is NOT started here.
