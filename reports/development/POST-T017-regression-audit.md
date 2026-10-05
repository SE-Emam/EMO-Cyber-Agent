# POST-T017 — Regression Truth Audit (Agent 5)

**Agent:** Agent 5 — Regression Truth Auditor
**Date:** 2026-10-05 (UTC)
**Scope:** STRICTLY READ-ONLY. No source/test modifications, no rebuilds executed.
**Working directory:** `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`

Prior state: full suite showed 1496 passed + 3 failed, all 3 in `tests/release/`
(stale sdist checksums). Since then Agent 3 rebuilt + regenerated records
(build C), and Agent 4 verified identity PASS (`tests/release/` at 51 passed,
`POST-T017-release-integrity.json` verdict PASS). This audit establishes the
CURRENT regression truth.

---

## 1. The 3 formerly-failing tests — current status

Read-only run: `python3 -m pytest tests/release/ -q --tb=short` → **51 passed**
(measured: `51 passed in 155.51s`). Targeted re-run of the 3 nodes →
**3 passed in 0.52s**.

### 1.1 `tests/release/test_release_integrity.py::test_sha256sums_verifies_in_clean_environment`

- **What it asserts** (`test_release_integrity.py:34-44`): recomputes
  `sha256()` of every file listed in `release/SHA256SUMS` from disk
  (`release/<name>` or `dist/<name>`) and requires equality with the
  recorded hash. No hardcoded hash in the test body — the expectation lives
  in the **signed file**.
- **Former failure:** `assert '0c548173…' == '136b4672…'` for
  `emo_cyber_agent-0.1.0.tar.gz` (actual dist bytes of build B vs recorded
  hash of build A). Recorded: size **731492**, sha256
  `136b4672825ea3ef15734371687e96ac6b89fd202ec9d75815b1d58f5347cfd6`.
  Actual dist at the time: size **737069**, sha256
  `0c5481739e23f96b5bf16b70683ab92c82ca1001a2bf9db7990dd9466518a51d`.
- **Current result:** PASS.
- **Root-cause category:** **build process + stale expected-hash records**
  (NOT source, NOT fixture, NOT test logic). Per forensics (§1, §4):
  records signed at **20:53 for build A**, `dist/` held **rebuilt build B**
  from 21:27, signature never re-taken → B's bytes tested against A's
  signature.

### 1.2 `tests/release/test_release_integrity.py::test_manifest_hash_matches_dist_identity`

- **What it asserts** (`test_release_integrity.py:88-95`): compares
  `manifest["artifacts"][key]["sha256"]` against fresh `sha256(dist file)`
  for wheel + sdist. Expectation lives in the **manifest**.
- **Former failure:** `assert '136b4672…' == '0c548173…'` for sdist
  (recorded vs actual; wheel line passed throughout).
- **Current result:** PASS.
- **Root-cause category:** same as 1.1 — **build process
  (rebuild-after-signing)**, stale recorded identity.

### 1.3 `tests/release/test_release_manifest.py::test_manifest_artifacts_match_dist_files`

- **What it asserts** (`test_release_manifest.py:67-74`): per artifact,
  recorded `name`/`size`/`sha256` vs `dist/` name/`st_size`/fresh sha256.
- **Former failure:** `assert 731492 == 737069` (recorded sdist size vs
  `stat()` of dist file; fails before even reaching the hash).
- **Current result:** PASS.
- **Root-cause category:** same — **build process + stale records**.

### Forensics conclusion cited

Per `POST-T017-checksum-forensics.md` §§1/4/8: **A was signed, then B was
built, and the signature was never re-taken.** At 20:53 artifact set A
(sdist `136b46…`, 731492 B) was signed into manifest + SHA256SUMS (mutually
consistent). At 21:27 `dist/` was rebuilt from a newer tree → set B (sdist
`0c5481…`, 737069 B, +5577 B). Deterministic backend exonerated (hatchling
clamps all tar/zip/gzip mtimes to 2020-02-02; identical source ⇒
byte-identical output), so the delta is pure source-content drift, not a
timestamp flake. Artifact A's file was never retained — only its hash/size
survive in the old records. Fix direction (§7): **the records must move,
not the tests** — rebuild + resign, never weaken identity tests.

**Current (build C) identity, verified read-only just now:**

| Artifact | Size | SHA-256 | Status |
|---|---|---|---|
| `dist/emo_cyber_agent-0.1.0.tar.gz` | 804263 | `053da70703777e8b81623fa8808c3ea1e74deaf0802e309d01979fb1b6ada118` | matches manifest + SHA256SUMS |
| `dist/emo_cyber_agent-0.1.0-py3-none-any.whl` | 598306 | `60fccf19c25763f9591236748ab29dc17d274d5d32d2ab2c9ce98fd71c97f076` | matches manifest + SHA256SUMS |
| manifest `build_timestamp` | — | `2026-10-05T04:25:31.251123+00:00` | regenerated (build C) |
| manifest `git_revision` | — | `9f6ba34ad0375ea05824e0c3cd599613d6f0a315` | equals `git rev-parse HEAD` (verified) |

Agent 4 witness: `POST-T017-release-integrity.json` →
`verdict: PASS`, `release_tests: {passed: 51, failed: 0}`,
`revision_match: true`. Consistent with this audit's 51-passed measurement
(growth from the forensics-era 44 → 51 reflects added release coverage,
not a discrepancy).

---

## 2. Classification

### (A) Authoritative regression tests — everything outside `tests/release/`

`tests/unit/` + `tests/contract/` — guards shipped **source behavior**.
Measured read-only: `python3 -m pytest tests/unit tests/contract -q
--tb=no -p no:cacheprovider` → **EXIT 0** (≈1448 passed, 2 skipped;
dot-count derived — see §3). The 2 skips are environment-optionals
(`tests/unit/test_toolchain.py:308`: `trivy not installed`,
`osv-scanner not installed`), not regressions.

### (B) Release-specific checksum tests — `tests/release/`

Record↔bytes **identity tests**, valid only for the verified artifact pair
(current build C). They assert the manifest/SHA256SUMS describe the exact
bytes in `dist/` — i.e. "what was signed is what ships." Measured: **51
passed, 0 failed** (155.51s). Targeted trio: 3 passed.

### (C) Stale/obsolete expectations — NONE

Verified by grep over `tests/release/` (read-only):

- `rg -n "136b46|0c5481" tests/release/` → `NO_MATCH_IN_TESTS_RELEASE`
- `rg -n "136b4672|0c548173|053da707|60fccf19|63b455ed" tests/release/` →
  `NO_HARDCODED_HASH_IN_TESTS_RELEASE`
- `rg -n "[0-9a-f]{64}" tests/release/` → no 64-hex hash literal anywhere
  in the test sources.

The tests contain **zero hardcoded hashes**; all expectations are read at
runtime from `release/release-manifest.json` + `release/SHA256SUMS`. There
is therefore no stale-expectation class to retire — the old failures were
stale **records**, now regenerated, not stale **tests**.

---

## 3. Full suite (read-only)

Command: `python3 -m pytest -q --tb=no -p no:cacheprovider`

| Metric | Value |
|---|---|
| passed | **1499** (1448 unit+contract + 51 release; dot-count cross-check: 1499 dots) |
| failed | **0** |
| skipped | **2** (both `test_toolchain.py:308` optionals — trivy / osv-scanner) |
| errors | **0** |
| exit code | **0** (three invocations: full suite EXIT 0; `tests/unit tests/contract` EXIT 0; `tests/release/` EXIT 0) |
| duration | split-measured: `tests/release/` 155.51s; `tests/unit tests/contract` 5:02.78 wall (timed run). Combined ≈ 7–8 min. (A single full-suite invocation with `--junitxml` exceeded the 900s tool timeout due to release-venv reinstalls, so totals are reported from the exit-0 full run plus the timed splits; no failure was observed in any invocation.) |
| warnings (non-failing) | 2 `RuntimeWarning: coroutine 'FoundationSecurityAuditor.audit' was never awaited` (`test_code_intelligence.py`, `test_progress_e2e.py`) — warnings only, zero failures |

Triage: **no failures to triage.** Regression-or-unrelated verdict: N/A —
nothing failed. The 2 skips are proven non-authoritative (missing optional
external scanners, explicit skip reason in test source).

Note on `-q` summary line: with this repo's pytest config
(`addopts: -q`, `asyncio_mode: auto`, `pythonpath: ["src"]`) the captured
stdout in this environment ends at the warnings summary without echoing the
`N passed` line, so totals above are derived from exit codes (0 = zero
failures) plus dot/`s` counts from the progress grid, the
`51 passed in 155.51s` release line, and an independent
`--collect-only` count: **1501 collected = 1450 (unit+contract) + 51
(release)**, exactly matching 1499 dots + 2 `s` in the full run.
All runs corroborate: **zero failed, zero errors.**

---

## 4. Verdict: **PASS**

**Correct final language: PASS** — zero failures in (A) + (B):
authoritative suites green (exit 0, 1448 + 2 skips) and release-identity
suite green (51 passed), with no stale expectations outstanding (grep
proves no hardcoded hashes).

**Does `tests/release/` count as an authoritative gate for the
release-candidate decision?** **Yes — for the release-candidate decision,
but scoped correctly.** (A) is the authoritative gate for *source*
regression (does the code behave correctly). (B) is the authoritative gate
for *artifact* identity (does the signed record describe the exact bytes
being shipped) and is valid only for the verified pair (build C:
sdist `053da707…`/804263, wheel `60fccf19…`/598306, manifest timestamp
2026-10-05T04:25:31Z, revision `9f6ba34…` = HEAD). A release candidate
requires **both** gates green: (A) proves the behavior, (B) proves the
package. Both are green now, and (C) is empty — hence **PASS** with no
notes-required qualification. `PASS-WITH-NOTES` would apply only if a
failure were proven non-authoritative; there are no failures.
`BLOCKED` does not apply.
