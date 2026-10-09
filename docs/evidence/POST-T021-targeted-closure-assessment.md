# POST-T021 Targeted Closure Assessment (G9)

Date (UTC): 2026-10-09 · Owner: G9 Independent Final Reviewer (READ-ONLY review; this file + `POST-T021-final-review.md` are the only G9 writes)
Previous reports preserved; history record: G0 baseline → G1 hosts → G2/G2-A platforms → Wave D → G7/G8 → this closure.

## Gate ledger

| Gate | Decision | Evidence | Remaining debt |
|---|---|---|---|
| G0 Baseline | PASS | HEAD 9098006→HEAD-tracked; 0.2.0×3; 7 tools; 9-gap matrix | none |
| G1 Host Closure | PASS | OpenCode/Hermes/AnythingLLM ENV-tested; Pi/Jan ENV-BLOCKED reproducible; 0 false-PASS | 3 ENV-BLOCKED (§Host debts) |
| G2 Online Linux | PASS (executed matrix) | run 37866150660: 234/234 × py3.11/3.14 (wheel/sdist/pypi) | PS-n/a; non-matrix combos untested |
| G2 Online Windows | PASS (executed matrix) | same run: 234/234 × py3.11/3.14; PS-live NOT-EXECUTED (declared) | PS-live + quoting/Unicode/Ctrl-C + wider Win surface |
| G2-A Android/Termux | PASS (executed tests) | A0–A9: install→CLI/MCP/HTTP/security/E2E on emulator-5554 | NOT officially-supported platform (needs pyproject/docs decision) |
| G3 Heuristics | PASS | word-join FIXED 13TP/0FN/0FP; L1/M2/D5-D6 DOCUMENTED; 37/37 deterministic | open-by-design residuals (documented) |
| G4 Benchmark | PASS | 135→155 additive; fingerprint match; 5/5 eval dims; no inflation/coupling | manifest `case_count` staleness; Gap 7 versioning owner |
| Wave D Security | PASS | SEC-D: no Crit/High/Med; secrets CLEAR | none |
| G7 Regression | PASS | 2720 passed / 6 skipped (all justified) / 0 failed, exit 0 | cosmetic warnings (unknown-mark + 2 RuntimeWarnings) |
| G8 Invariants | 12/12 PASS | per-invariant file:line + live probes; G9 re-probed security core | none |
| G9 Final | PASS-WITH-NOTES | this assessment + `POST-T021-final-review.md` §§1–14 | notes below, non-blocking |

## Platform parity debt (preserved, not closed by fiat)

- Linux/Windows: PASS **within** ubuntu-24.04 × windows-2025 × py3.11/3.14 full battery; everything outside that matrix is untested, not claimed.
- Android: functional PASS on emulator-5554; support-policy status explicitly NOT granted.
- macOS: 2720-green-at-HEAD + live CLI/MCP probes current; 23/23 0.1.0-era battery text carries a staleness note (doc-sync).

## Host environment debt (unchanged)

AnythingLLM adversarial-via-host / Pi / Jan: ENVIRONMENT-BLOCKED with reproducible reasons + one-step reproduction kits. Local sims stay sims.

## Test-key rotation status

LOW / OPEN: 1 test-key row at rest in AnythingLLM app DB; CLEAR elsewhere; rotation ENV-BLOCKED (app down); operator one-liner + 401-proof pending.

## Exact test counts (records of truth)

- Online parity: 936/936 (234 × 4 combos), 0 fails, 0 hidden skips.
- Full suite: 2720 passed / 6 skipped / 0 failed / 0 xfail, exit 0 (~118 s authoritative).
- Subagent suite (post-G): 722 passed / 1 skipped / 0 failed.
- Heuristic eval: fixed 13TP/0FN/0FP; determinism 37/37 ×3.
- Benchmark: 155 files (104 manifest + post_t020 30 + post_t021 20).

## Remaining risks

Heuristic documented bypasses (detective-only); platform scope edges (§Platform debt); host prerequisites; published-0.2.0 predates T21-G fix by design (immutable); Info-level doc-sync (O2 manifest anomaly, android-assessment wording, macOS staleness text).

## Release impact

- `v0.1.0` / `v0.2.0` tags unmoved; `SHA256SUMS` + `release-manifest.json` identical to tag; no publish/tag runs; no PyPI changes.
- Post-release tracked delta (dev path): parity workflow+harness, T21-G fix+tests, evidence reports, corpus, README badges+platform matrix.
- Any future release from this tree is a NEW version (0.2.1/0.3.0 policy decision) — never 0.2.0 content.
- NEXT RELEASE CANDIDATE material present (hardening fix + proven multi-platform battery); version choice and publish remain explicit future decisions, not taken here.
