# POST-T020 G13 Regression (Lead-executed, read-only)

Verdict: **PASS.**

| Scope | Command | Result |
|---|---|---|
| subagent | `pytest tests/unit/subagent` | 718 passed, 1 skipped |
| heuristics+hardening | 2 files | 45 passed |
| release (local dist) | `pytest tests/release` | 51 passed |
| FULL | `pytest` | **2634 passed, 6 skipped, 0 failed** (178 s) |

Triage: single failure found during the run
(`test_f1_evasion_rate_hyphen_filler_case_caught_homoglyph_miss`) was a
STALE MEASUREMENT, not a regression — M2 confusable folding improved
detection 6/9→7/9 and the test pinned the old ceiling. Updated the
documented ceiling + corpus expectation (test-only change); re-green.
No collection errors; duplicate-basename fix holds.
