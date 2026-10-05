# POST-T018 Gap Matrix — Subagent/Host Integration (Agents 1A–1F synthesis)

Wave B verdicts per item (EXISTS / PARTIAL / MISSING / NOT_REQUIRED).

## Delegation & contracts (1A)

| Item | Verdict | Key evidence |
|---|---|---|
| host-integration | PARTIAL | Generic MCP/CLI patterns exist (`docs/17`, `mcp/server.py`); `HostProfile` scoped to extensions only; no Host→EMO handshake |
| delegation | PARTIAL | Internal MCP→Core `dispatch()` exists; no task envelope / delegation context / scope-binding object |
| subagent-lifecycle | MISSING | No lifecycle, delegation-id, timeout/budget/expiry for Host→EMO runs |
| subagent-contract | MISSING | Fragments only (`TaskSpec`, `ResolvedTask`, `AdapterBinding`); no signed Host→EMO envelope |
| security-delegation | PARTIAL | `StrictPolicyEngine` + `PolicyDecision` exist; host scope/audience never bound to decisions |

## Context / trust (1B)

| Item | Verdict | Key evidence |
|---|---|---|
| host-context-isolation | PARTIAL | Per-audit isolation strong; no per-source host-context channel |
| context-firewall | MISSING | Keyword scans only; no parse→normalize→validate→scope-bind→policy layer |
| agent-trust-boundary | PARTIAL | Trust models descriptive/analytic; no runtime Host-edge enforcement |
| delegation-input-sanitizer | MISSING | Detectors only; no sanitization gate at dispatch |

## Capability / session (1C)

| Item | Verdict | Key evidence |
|---|---|---|
| capability-negotiation | MISSING | `negotiate_version` only; no offer/accept/narrowing handshake |
| capability-minimization | PARTIAL | Default-deny exists; no enforced requested≤effective; `scope_allows` defaults True; operator-precedence bug `policy.py:119-122` (pre-existing, flag for owner — NOT this wave) |
| session-binding | PARTIAL | Per-layer audit bindings; no unified session→audit→project→snapshot chain; MCP stateless; progress uses `audit_id="mcp"` placeholder |
| session lifecycle/store | MISSING | "Authorized session" is plan-only prose; no store/TTL/revocation |
| replay protection | MISSING | Decisions replayable; no nonce/TTL/single-use |
| capability bearer tokens | NOT_REQUIRED | Client tokens correctly forbidden; must stay blocked |

## MCP / host (1D)

| Item | Verdict | Key evidence |
|---|---|---|
| mcp-discovery | EXISTS | `tools/list` returns fixed 6 tools; by design |
| mcp-tool-filtering | MISSING | `tools/list` unconditional; no allowlist/per-task scoping |
| compat negotiation | EXISTS | 3 protocol versions + fallback; no per-host quirks |
| tool exposure policy | EXISTS | Static 6-tool surface + tests; no declarative manifest |
| server identity | PARTIAL | `serverInfo` present; `capabilities` empty |
| host-specific code | PARTIAL | Generic config only; zero host adapters; OpenCode/Hermes/pi NOT_TESTED |
| per-task allowlist | MISSING | All-or-nothing exposure |
| host adapters | MISSING | No `mcp/hosts/*`; principle only in CONTRIBUTING |

## Health / bootstrap / compat (1E)

| Item | Verdict | Key evidence |
|---|---|---|
| host install entrypoint | EXISTS | pyproject + Makefile + console script |
| bootstrap script | MISSING | No guided setup; config deferred to host docs |
| config/health gating | MISSING | Provider-only config; no pre-run gate |
| compatibility-management | EXISTS | Extension-scoped `HostProfile` + checks; not a host matrix |
| per-host compat matrix | MISSING | Classifiers only; no published matrix |
| doctor | PARTIAL | Presence-only; always `status:ok`; no READY/DEGRADED, no gating |
| subagent health aggregate | MISSING | Component health exists (extensions/adapters/tool-packs) but unwired to doctor |

## Observability / handoff (1F)

| Item | Verdict | Key evidence |
|---|---|---|
| audit-observability | EXISTS | ProgressReporter fan-out + sanitized MCP projection; nothing to redact |
| audit-handoff | PARTIAL | Point-redaction scattered per tool; no unified `ResultEnvelope`; `recovery detail=str()` unredacted |
| result-firewall | MISSING | Zero hits; no centralized stripping layer before Host |

## Build priority for Waves C+

1. Foundation contracts (envelopes, session, handoff, compat decision) — Wave C.
2. Delegation security pipeline (sanitizer → context firewall → scope bind). — Wave C.
3. Capability effective-set + session binding chain. — Wave D.
4. MCP filtering + discovery advertisement + session mapping. — Wave E.
5. Lifecycle + progress vocabulary + recovery bridge. — Wave F.
6. Result firewall + handoff + health/compat aggregation. — Wave G.
7. Per-host adapters (config-only). — Wave H.

Reuse mandates: `StrictPolicyEngine`/`PolicyDecision`, `validate_arguments`,
`AdapterBinding` pattern, `TaskScope.narrowed_by`, existing redaction
helpers, extension trust model shapes.
