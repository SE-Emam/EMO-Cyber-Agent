# POST-T020 G14 Invariants — 12/12 PASS (Lead audit, read-only)

Evidence focused on T020 additions (subagent/, http_server, checklists,
templates, platform alias, loader scoping); hardening suite green (in 45).

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | Read-only default | PASS | No exec surface in new code (grep: only docstrings/patterns); http localhost-default |
| 2 | Untrusted repository content | PASS | Firewall relabels all inbound UNTRUSTED; AnythingLLM workspace/RAG/memory UNTRUSTED |
| 3 | Evidence required | PASS | Handoff HOLD on empty verification_refs; no finding-without-evidence path added |
| 4 | No destructive action w/o permission | PASS | No destructive primitives in new code; recovery terminal actions make zero executor calls |
| 5 | Tool outputs are data | PASS | Chunks/envelopes typed DATA; result scrub before Host release |
| 6 | Explicit uncertainty | PASS | INCONCLUSIVE preserved; heuristic outputs labeled signal/hypothesis; no scores |
| 7 | Shared Core contracts | PASS | Reuse everywhere (PolicyEngine, AdapterBinding shapes, resolver conventions) |
| 8 | External provider choice | PASS | No provider pinned; hosts are config-only adapters |
| 9 | Provenance retained | PASS | ProvenanceLink chain; digest-signed handoffs; template provenance enforced |
| 10 | No cross-project reuse | PASS | 4-tuple isolation; cross-audit quarantine verified live; loader scoping |
| 11 | Specialist worker | PASS | Capability narrowing; least-surface discovery; task allowlists |
| 12 | Host owns delegation | PASS | Delegation metadata never authority; server-issued contexts only |

No T020 addition grants authority, mutates policy/findings/evidence, or
executes. Overall: **12/12 PASS.**
