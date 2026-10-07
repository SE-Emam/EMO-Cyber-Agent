# POST-T020 Acceptance Assessment (Lead Orchestrator)

Scope freeze: v0.1.0 tag/release/PyPI IMMUTABLE; all work on main = next dev line. No publish during POST-T020.

| Gate | Scope | Tests (pass/fail/skip) | Security findings | Decision | Evidence |
|---|---|---|---|---|---|
| G0 Baseline | HEAD/rev/tag/PyPI/version/hosts/HTTP/heuristics/checklists/templates/benchmark/tests/invariants | n/a (record) | none | PASS | POST-T020-G0-baseline.md + G0-gap-matrix.md |
| G1 Hosts | opencode/pi/hermes/jan/anythingllm live | 704/0/1 (subagent) | 2 adapter drifts (fixed) | PASS-WITH-NOTES | G1-host-matrix.md + 5 host reports |
| G2 HTTP | server/clients/security | 21+10/2+24, 0 bypass | none | PASS | POST-T020-G2-http.md |
| G3 Heuristics | inventory/measure | 8 measured; eval gaps fixed | M1/M2 closed | PASS | test_heuristics_evaluation.py |
| G4 Checklists | 7 official, data-only | 21/0/0 | none (2 info) | PASS | test_checklists.py |
| G5 Templates | 8 official + adversarial review | 35/0/0 | R1/R2/L2 closed; L1 residual Low | PASS-WITH-NOTES | POST-T020-template-review.md |
| G6 Python | 3.11/3.12/3.13/3.14 live venvs | 4×53 green | none | PASS | POST-T020-G6-python.md |
| G7 Platform | darwin 23/23; linux/win inspection | 23/0/0 live | win32 defect (fixed) | PASS-WITH-NOTES | POST-T020-G7-platform.md |
| G8 CI | tiered matrix workflow | YAML-valid, unexecuted | none | PASS-WITH-NOTES | POST-T020-G8-ci.md; first run on next push |
| G9 Benchmark | taxonomy + 30 cases + eval | 10+11 green; P/R 1.0 honest | M3 closed | PASS | POST-T020-G9-benchmark.md |
| G10 E2E | 17 scenarios black-box | 17/0/0 | none | PASS | test_e2e_post_t020.py |
| G11 Adversarial | new surface + fixes + re-probe | fixes verified live | 3M closed; L1 deferred-counted | PASS | POST-T020-G11-security.md |
| G12 Fuzz | new surface 253 cases | 253/0/0, no crash | none | PASS | test_fuzz_post_t020.py |
| G13 Regression | full suite | 2634/0/6 | stale ceiling (fixed, test-only) | PASS | POST-T020-G13-regression.md |
| G14 Invariants | 12 delta audit | hardening green | none | 12/12 PASS | POST-T020-G14-invariants.md |
| G15 Final | independent review | subset re-probed | notes, no blocker | PASS-WITH-NOTES | POST-T020-final-review.md |
| G16 Requal | clean build + smoke + records | release 51/51; smoke 9/9 | allowlist gap (fixed) | NEW RC PASS | hashes below |

New release candidate (UNPUBLISHED, no tag/push/commit performed by G16):
- wheel `emo_cyber-0.1.0-py3-none-any.whl` SHA256 `4350bf3a…370aa`, 729,637 B
- sdist `emo_cyber-0.1.0.tar.gz` SHA256 `adf572c1…6a79791`, 1,112,873 B
- manifest `47a14786…700846`; RECORD 372/372 valid
- Rule: any further source change invalidates this identity; publish only by separate authorization.

Residuals (documented, non-blocking): L1 trust-root string-based; M2 map
partial; D5/D6 word-order/padding; anythingllm NOT-EXECUTED; Windows/Linux
NEEDS-RUNTIME-PROOF; CI unexecuted until push; contract_only warning.

POST-T020 FINAL DECISION: **PASS-WITH-NOTES** (notes = residuals above;
zero blockers; v0.1.0 untouched; next release requires version decision +
fresh build/verify per G16 pattern).
