# EMO-Cyber-Agent — Architect Brief (2026-10-07)

For: Responsible Architect. Classification: full-fidelity status, all figures re-verified this session unless marked prior.

## 1. Identity

- Product: EMO-Cyber-Agent — portable, model-agnostic, governed cybersecurity subagent (code, apps, agents, prompts, MCP, cloud).
- Distribution: PyPI `emo-cyber` (import `emo_cyber_agent`, CLI `cyber-agent`, MCP `emo-cyber-agent`, repo `SE-Emam/EMO-Cyber-Agent`, Apache-2.0, Python ≥3.11).
- Releases: **0.1.0** (2026-10-06, frozen/immutable) and **0.2.0** (2026-10-07, current). No other versions exist.

## 2. Architecture (unchanged principle, extended surface)

- Core owns security decisions (`core/policy.py` StrictPolicyEngine); CLI/MCP/Python are thin adapters; evidence-first (no finding without evidence); verification before confirmation; read-only default; Progress advisory-only; Recovery bounded + fail-closed; untrusted content never becomes authority.
- Tree: 253 source files across 25 packages; 108 test files; 94 templates; 190 fixtures; 77 reports; 30 docs.
- MCP surface: **7 tools** (`cyber_audit/review/verify/report/status/extensions` + `cyber_threat_intel`, the latter opt-in). Transports: stdio + Streamable HTTP (stdlib-only server, localhost-default, 404/405/400/401/403/413/440 semantics).
- New since 0.1.0: `threat_intel/` (leak monitor, feed triage, 24-row ATT&CK mapper, 20-tool Kali detector pack — defensive knowledge, zero network/exec), `subagent/` contracts + lifecycle + firewalls, `checklists/`, 8 official report templates, HTTP transport, benchmark corpus (+30 cases).
- Invariants: **12/12 PASS** (rear-guard audit this cycle; hardening suite green).

## 3. Release history (artifact identities)

- v0.1.0: wheel `60fccf19…` (598,306 B) + sdist `053da707…` (804,263 B). GitHub Release published. PyPI live. FROZEN — never touched since.
- v0.2.0: wheel `emo_cyber-0.2.0` SHA256 `010409b4e727e0bacc275cb5b2d99a363da39aee9ff4a70af52b5c9de4cd2034`; sdist SHA256 `a5a199dd516da902de82be6625c72be266e1408924a57df1534365475e428dea`. Built once in CI from tag, verified, published via Trusted Publishing (OIDC, no tokens). GitHub Release published with wheel+sdist+SHA256SUMS+manifest.
- Identity chain re-proven TODAY by fresh download + recomputation: draft bytes == SHA256SUMS == PyPI bytes (both artifacts). Note: GitHub API `size` fields once displayed stale values (698,673 vs true 754,105); ground truth is recomputed sha256 — matches everywhere. Display metadata, not a content issue.

## 4. Verification & QA (fresh figures)

- Full suite just now: **2716 passed, 6 skipped, 0 failed** (exit 0). Skips: optional scanners (trivy/osv), 1 honest anythingllm-env skip, contract mark.
- Release suite: **51/51**. CI matrix (`ci.yml`, 7 jobs incl. py3.11 + Windows): **all green** — it caught and we fixed a real py3.11 `Enum.__contains__` incompatibility plus a PowerShell/heredoc issue this cycle.
- Security reviews: T018 adversarial (closed), T020 adversarial (3 Mediums found → fixed → independently re-probed closed), template review (PASS + 2 hardenings applied), G11 re-review PASS. Fuzz: 253 + heuristiceval cases, zero crashes. Residuals (documented, non-blocking): L1 string-root trust, partial confusable map, word-order/padding evasions.

## 5. Interoperability (honesty-labeled)

- AnythingLLM: **ENVIRONMENT-TESTED full loop** (register→discover→filter→delegate→execute→result, live transcript; malicious-via-host NOT-EXECUTED).
- OpenCode: delegation live; 2 adapter doc drifts found+fixed. Hermes: filtering live. Pi/Jan: binaries present, no native MCP path / no models → delegation BLOCKED-environmental (not product). 
- Python 3.11–3.14 live-verified; darwin 23/23; Linux/Windows inspection-only + CI now executing (Windows green).
- Host matrix + per-host reports under `reports/development/POST-T020-G1-*` and `docs/integrations/`.

## 6. Threat-intel delta (0.2.0 headliner, verified live)

- 63 unit + 19 MCP tests green; live MCP run confirmed all 5 actions + rejection paths (`map-technique` CWE-89→T1190, `exposure-check` hydra logic, `leak-check` digest-only, `triage`, `coverage` honesty, `-32602` on bad input).
- Guarantees re-verified: no network imports, no exec surface, no secret storage, deterministic, unknown→empty (no hallucinated technique IDs).

## 7. Known limitations & deferred

- Vendor interop beyond contracts (anythingllm malicious-via-host, pi/jan delegation) needs provider quota/config.
- Linux/Windows need runtime proof beyond CI smoke.
- Heuristic screens are defense-in-depth (bounded coverage, documented).
- No benchmark security scores (by design); deferred: CPG/Joern/CodeQL, live red-team, exploit runners, approval workflows, durable knowledge/embeddings.

## 8. Repository state (now)

- Remote `origin https://github.com/SE-Emam/EMO-Cyber-Agent.git`; branch `main` @ `9af310f` (+0.2.0 docs commits after tag — docs only); tags `v0.1.0`, `v0.2.0` (annotated, on release commits); tree clean.
- Reports suite current through POST-T020 + 0.2.0 release records.

## 9. Recommendations

1. Keep v0.1.0/v0.2.0 immutable; next work → 0.3.0 or 0.2.1 via the proven tag→CI→draft→verify→publish pipeline (do not hand-build release artifacts).
2. Close the anythingllm adversarial-via-host test when provider quota is approved (single session, restorable).
3. Promote Windows/Linux from CI-smoke to behavior parity on the next cycle if enterprise adoption requires it.
4. Rotate the locally generated AnythingLLM test API key at the operator's convenience (test-only, never left the machine).
