# POST-T018 Subagent Readiness Assessment — Final (Lead Orchestrator)

Date: 2026-10-05/06. Waves 0–L executed via scoped subagents + Lead verification.
Release posture: **DO NOT PUBLISH maintained throughout; final: NEW RC — PASS — DO NOT PUBLISH.**

## 1. Baseline

HEAD `12cc5a1` (main); version 0.1.0; frozen 0.1.0 RC (wheel `60fccf19…`,
sdist `053da707…`, manifest rev `9f6ba34a`) declared Frozen Reference.
Report: `POST-T018-phase0-baseline.md`. Architecture map confirmed Core
authority (`StrictPolicyEngine`), thin adapters, no subagent/host/firewall/
session concepts (term sweep evidence).

## 2. Gap Matrix

`POST-T018-gap-matrix.md`: 25 items — 5 EXISTS (mcp-discovery, compat
negotiation, exposure policy, compat-mgmt, observability, install entry),
9 PARTIAL, 10 MISSING (lifecycle, contract, firewall, sanitizer, negotiation,
session store, replay, tool-filtering, allowlist, adapters, bootstrap,
matrix, health aggregate, result-firewall), 1 NOT_REQUIRED (client bearer
tokens — correctly forbidden). Build order Waves C→H followed it.

## 3. Contracts

`subagent/` foundation (Agent 2): envelope, capabilities, session,
handoff, trust, hosts + `__init__`. Frozen pydantic, canonical JSON,
kebab/semver, audit/project/snapshot binding, no secret fields, server-only
authorization issuance. 36 contract tests green. Reuse>duplicate honored
(shapes cloned, no live logic duplicated).

## 4. Delegation

`delegation.py` pipeline (parse→normalize→validate→scope-bind→policy);
metadata never authority; hostile classes DENY/QUARANTINE; hardened twice
(F1 fillers/inflections/NFKC/role-classes; F2 `of`/hyphen separators +
benign-preservation tests). Live-verified deny on all canonical + evasion
variants; benign task text ALLOW.

## 5. Context Firewall

`sanitizer.py` (NFKC/ANSI/control/authority spans, 64 KiB bound) reused by
`firewall.py` (scope+size+policy gates, execution-sink deny, secret-marker
quarantine) fronting `isolation.py` (4-tuple partitioned store, sticky
quarantine, FIFO bounds, session purge). 27+35+18 tests green.

## 6. Capability

`negotiation.py` (offer/accept/narrow, replay-safe records) +
`minimization.py` (effective=requested∩allowed−denied−privileged∖allowlist,
escalation/widening named rejections, model-validator consistency proofs).
requested≤effective enforced server-side.

## 7. Session

`binding.py` (exact triple match, STALE vs MISMATCH codes, nonce single-use,
no partial use) + `trust_boundary.py` (depth≤3, audience, windows,
narrowing-only, cross-boundary quarantine) + `session_map.py` (opaque token
correlation, TTL, replay deny, 1024-entry cap + sweep). MCP `progressToken`
stays opaque correlation, never authority.

## 8. MCP

`discovery.py` (pinned identity, per-task subsets, tripwire version test) +
`tool_filter.py` (deny-wins, unknown/wildcard/empty-allow denied) + 5D
black-box tests vs real server (handshake, filtering, malformed, token
abuse, isolation, firewall spot-checks). Least-useful-surface enforced.

## 9. Lifecycle

`lifecycle.py` coordinator (start/heartbeat-timeout/cancel-terminal/
recover-bounded/complete-gated) over `SubagentSession.transition` —
coordination only, security lifecycle stays in Core. No orphans, no hidden
retries, terminal never rewritten.

## 10. Progress

`progress_bridge.py`: 11 lifecycle states → 10-phase delegation vocabulary
via EXISTING ProgressState/Reporter (no second system); `SUBAGENT_*_ADVISORY`
codes; session read-only; COMPLETED→100%; advisory-only proven (no
capability/auth fields in 12-key event dict — asserted by test).

## 11. Recovery

`recovery_bridge.py`: host failures → existing classifications; trio
fail-closed with zero attempts; budgets inherited; resume/fail mapping;
no policy/finding/evidence mutation; cross-audit refused. Existing
`recovery/` untouched.

## 12. Result Firewall

`result_firewall.py` (secret/CoT/raw/path/provider/oversize stripping,
cross-audit quarantine, 12-char whole-value rule with exact-bound-ref
exemption) + `handoff_gate.py` (verification-ref gate HOLD, scrub-first,
provenance chain, digest). Finding/evidence/verification/report refs,
provenance, limitations, status preserved.

## 13. Health

`health.py` aggregation (BLOCKED>UNAVAILABLE>DEGRADED>READY; READY≠authorized,
AST-guarded) + `bootstrap.py` pure-DATA checklist (evaluate-only, no
probing) + `compat_matrix.py` honest per-host table (only generic-mcp
Contract-tested; vendors Not-tested). `pi`→`pi-host` alias documented
(hosts.py regex untouched).

## 14. Compatibility

Matrix + `evaluate_compat` (UNKNOWN→quarantine, no silent fallback) +
per-host negotiation helpers (explicit intersect, abort on no-overlap).
Honest statuses; no parity assumed.

## 15. Host Matrix

5 config-only adapters (registration snippets, identity mapping, 5-tool safe
defaults + `cyber_extensions` opt-in, capability parity, troubleshooting;
AnythingLLM adds workspace/RAG/memory UNTRUSTED classification). No Core
changes, no policy logic, no host authorization. E2E: opencode/pi/hermes/jan
binaries present (`--version` OK); anythingllm NOT EXECUTED (honest skip).

## 16. Security Review

Agent 11 (independent): 1H+2M+5L+3I → BLOCKED. Fix F1 (all) → re-review:
8/8 RESISTED + 2 narrow residuals → Fix F2 → Lead live-verified (4
suppression variants deny + benign allow; authz bypass closed + bound-ref
preserved). Final: Agent 15 re-probed all 5 points live — RESISTED.
No Critical ever; no shell/privilege/cross-audit surfaces.

## 17. Fuzz

156 bounded abuse cases, zero crashes; every outcome in
VALID/REJECTED/SANITIZED/QUARANTINED/FAIL_CLOSED; only expected typed errors.

## 18. E2E

28 executed + 1 honest NOT-EXECUTED skip; full Host→MCP→delegation→EMO→
progress→verification→recovery→firewall→Host chain on generic-mcp;
vendor contract-only tests; malicious/degraded paths covered; no crash/
widening/leak/contamination/fallback.

## 19. Regression

Single-command full suite: **2202 passed, 3 skipped, 0 failed** (100 s).
Path: T018 introduced a duplicate-basename collection error
(`test_mcp_security.py` ×2) → fixed by Lead rename (no content change) →
green. Boundary suites (155) + subagent (703) + release (51) all green.
One release-test allowlist extension (proven-synthetic fixture; assertion
logic untouched).

## 20. 12 Invariants

Agent 15: **12/12 PASS** with per-invariant evidence. Core authority,
adapter thinness, policy sole-authority, evidence-as-data, no
finding-without-evidence / confirmation-without-verification, read-only
default, no cross-audit leakage, no skill-derived permission, no arbitrary
shell — all hold across ~30 new modules.

## 21. Known Limitations

Vendor interop Not-tested (beyond binary presence); HTTP transports
out-of-scope; `contract_only` mark warning (benign); pi-host alias;
checklist template unsigned; regex screens heuristic (defense-in-depth, not
semantic); nonce/store caller-held bounds documented per module.

## 22. Deferred Work

Unchanged from T017 (CPG/Joern/CodeQL, live red-team, exploit runners,
approval workflows, monitoring, durable knowledge, feeds, benchmarks,
multi-version templates) — not blockers.

## 23. Release Requalification

Source changed ⇒ old RC invalid (stated by Agents 15/16 + this report).
Clean `uv build`: wheel `f82e5d80…`/698015 B + sdist `a17247b5…`/971977 B
(both contain progress 4 + recovery 8 + subagent 31 files; RECORD 372 valid).
Records regenerated from final bytes (manifest rev `93999104`, digest
`c940d5e6…`). Exact-byte smoke PASS (wheel + sdist venvs). Release suite
51/51. Identity: build-once→verify→(publish pending authorization).
**NO tag/push/PyPI/commit performed.**

## 24. Final Decision

**PASS-WITH-NOTES → NEW RELEASE CANDIDATE — PASS — DO NOT PUBLISH.**

Acceptance matrix: Delegation/PASS, Scope/PASS, Capability/PASS, Context
Firewall/PASS, Session Binding/PASS, Result Firewall/PASS, Lifecycle/PASS,
Recovery/PASS, Progress (advisory)/PASS, Discovery/PASS, Tool
Filtering/PASS, Compatibility/PASS (honest), Health-Doctor/PASS,
Bootstrap/PASS, Handoff/PASS, Observability/PASS, OpenCode/Pi/Hermes/Jan
contract+presence/PASS, AnythingLLM contract-only/NOT-EXECUTED (note),
Adversarial/PASS (after fix loop), Fuzz/PASS, Regression/PASS (2202/0/3),
12 Invariants 12/12, Final Review PASS-WITH-NOTES.

EMO-Cyber-Agent is now a **Portable, Model-Agnostic, Governed Security
Subagent**: `discover → delegate → scope-bind → execute → monitor → verify →
recover safely → receive structured result`, with PolicyEngine sole
authority and Progress advisory-only. Publishing awaits separate
authorization; any further source change invalidates candidate `f82e5d80…`/
`a17247b5…`.
