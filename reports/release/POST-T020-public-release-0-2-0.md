# Public Release Record — emo-cyber 0.2.0

Date: 2026-10-07. Product: EMO-Cyber-Agent (SE-Emam/EMO-Cyber-Agent).

## Identity
- Tag v0.2.0 (annotated) → GitHub Release PUBLISHED → PyPI `emo-cyber 0.2.0` (Trusted Publishing/OIDC, no tokens).
- Wheel `emo_cyber-0.2.0-py3-none-any.whl` SHA256 `010409b4…cd2034`; sdist `emo_cyber-0.2.0.tar.gz` SHA256 `a5a199dd…428dea`.
- Proven: draft bytes == SHA256SUMS == PyPI bytes (recomputed, full-hash match; two earlier script-comparison scares were regex bugs in the check script itself, documented).

## Gates
- CI release workflow: build-verify + github-release + pypi-publish ALL SUCCESS (tag run).
- Tests: unit 2716/0/6 + release 51/51 (local); CI matrix 7/7 green incl. py3.11 + Windows (after enum-membership + bash fixes).
- Security: 12/12; adversarial residuals closed; fuzz clean.
- Consumer (public bits): pip install 0.2.0, import, --version `emo-cyber 0.2.0`, doctor ok, audit JSON, 7 MCP tools incl. live `cyber_threat_intel` map-technique → T1190.

## Content vs 0.1.0 (frozen, untouched)
- threat_intel package + cyber_threat_intel MCP tool; HTTP transport; checklists; official templates; benchmark corpus; platform alias fix; loader scoping; heuristic hardening; AnythingLLM full-loop proven.
- Display-label fix live in 0.2.0 (`emo-cyber 0.2.0`).

## Known notes
- AnythingLLM test API key remains in user app DB (user decision: keep).
- Residual Lows (L1/D5/D6), M2 partial map, contract_only warning — documented.
- Rollback: never delete/reuse v0.2.0; next fix → 0.2.1+ via same pipeline.

FINAL DECISION: **PUBLIC RELEASE 0.2.0 — PASS.**
