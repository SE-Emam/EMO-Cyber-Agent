# POST-T021 Pre-Release Assessment (Next Release Prep — read-only audit)

Date (UTC): 2026-10-09 · Auditor role: pre-release audit (started read-only; no code/test/workflow edits, no tags, no publish, no version selection)
Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
Candidate commit: `89ec190565d158e04812cff16c83b3e19b639cea` (branch `main`)

## 0. Commit + working-tree state

- HEAD: `89ec190` (`docs(evidence): publish POST-T021 parity reports + benchmark corpus + README platform matrix`), branch `main`.
- Working tree (tracked): CLEAN. Untracked only: `parity-artifacts/` (O2 local reference), `POST-T021-final-review.md`, `POST-T021-targeted-closure-assessment.md`, plus this file on creation. Nothing in `src/`/`tests/`/`docs/`/workflows modified outside committed HEAD.
- `git diff v0.2.0..HEAD -- src/`: exactly ONE file — `subagent/sanitizer.py` (+17/−3, the T21-G control-char separator). `tests/`: +2 files touched (3 sanitizer + 1 delegation-mirror regression cases) + 20 new `post_t021/` fixtures. No policy/capability/severity/evidence/verification file differs from v0.2.0.

## A. Sanitizer review

**A1. Implementation + call sites.** Authoritative `normalize()` at `src/emo_cyber_agent/subagent/sanitizer.py:193-226`. Shared-path consumers (no forks): `delegation.py:52` imports it as `_sanitizer_normalize`, `normalize_text()` (`:132-146`) is the single funnel used at `:288`; `firewall.py:38` consumes `sanitize` (hint-only). No new authorization path, no trust upgrade: outputs remain `decision_hint` signals; `PolicyEngine`/finding-lifecycle/evidence semantics untouched (zero diff).

**A2. Word-join probes (live, this audit, `PYTHONPATH=src`)** — CR (`\r`), VT (`\x0b`), FF (`\x0c`) between content now emit a collapsing space and are detected on both screens:

| Input | `normalize()` | hint | delegation |
|---|---|---|---|
| `ignore\rthe policy` / `\x0b` / `\x0c` variants, runs, edges, `grant\rwrite`, `disregard\rthe policy` (9 malicious shapes) | correctly split | deny | hostile span found |
| `line1\r\nline2` → `line1\nline2`; `a\rb\r\nc` → `a b\nc` | CRLF preserved | sanitize, no authority | () |
| `hello world`, `policystuff` (boundary: no token break) | unchanged | allow | () |

Grouped/repeated/boundary controls cannot fuse security-sensitive tokens; benign CRLF/plain text unaffected; substring-boundary (`policystuff`) does not over-fire.

**A3. Deterministic tests re-run (commands + counts, nothing converted to PASS without execution):**
- `test_sanitizer.py + test_delegation.py + test_contracts.py`: **110 passed** (`pytest … -p no:cacheprovider`, 0.44 s).
- Security set (`test_agent_security[.py,_adversarial,_isolation]`, `test_attack_surface`, `test_change_security`, `test_extension_security`, `test_heuristics_evaluation`): **109 passed** (1.94 s).
- Heuristic residuals preserved as documented: L1/M2/D5-D6 remain open-by-design (H re-verified 8/8 + 7/7 + 19/19); no scope broadening (no confusable-map change, no trust-architecture change).

## B. Build provenance + O2 reconciliation — EXPLAINED (not HOLD)

**B1. O2 record (as-written):** manifest `commit_sha=9098006…`, wheel `df176c2c…` (754365 B), sdist `9ac27496…` (1253437 B); O2's own log states the tree was **dirty** (uncommitted sanitizer/tests) at build time.

**B2. Reproduction (clean detached worktrees, both verified 0 dirty lines, `python3 -m build --outdir`, CPython 3.14.5):**

| Source | Wheel sha256 | Wheel size | Sdist sha256 | Sdist size |
|---|---|---|---|---|
| Pristine `9098006` worktree | `010409b4…de4cd2034` | 754105 | `3fac0147…` | 1148722 |
| HEAD `89ec190` worktree | `059f1b68…` | 755019 | `8f778778…` | 1259598 |
| CI run 37866150660 (`5c80880`, re-downloaded + re-hashed) | `df176c2c…bf946b` | 754365 | `c9075057…` | 1158577 |
| Published PyPI 0.2.0 (reference) | `010409b4…de4cd2034` | 754105 | `a5a199dd…` | 1145145 |

**B3. Findings:**
1. **Pristine-9098006 wheel == published PyPI wheel byte-for-byte** (`010409b4…`, 754105 B). Post-tag commits are docs-only for wheel purposes → wheel pipeline is byte-reproducible across builders (zip timestamps normalized to 2020-02-02 in all wheels inspected; 391 identical entry names CI-vs-local).
2. **O2 wheel == CI wheel because contents matched:** O2's dirty tree already contained the T21-G fix while its README was still pre-badge — exactly the content combination of CI's `5c80880` build. The manifest's `commit_sha=9098006` therefore described the *checkout*, not the *built content* — a manifest-generation weakness (records HEAD SHA, ignores dirty state), **not** a build defect and **not** fabrication.
3. **HEAD-vs-CI wheel delta fully attributed:** the two wheels differ in exactly 2 of 391 entries — `METADATA` (8743→10567 B) and its `RECORD` line — and the METADATA diff is exclusively the README badges + Platform-parity section added at `89ec190` (description payload). All 389 code/data entries identical in name and size.
4. **Sdist drift is expected:** sdists embed `reports/` + `scripts/runtime-parity/` which changed across every commit in range; each sdist hash is internally consistent with its own commit.
5. Each recorded artifact hash matches its bytes (all re-hashed locally: CI download, both worktree builds, PyPI reference).

**Remediation (process, non-blocking):** manifest generator should refuse-or-annotate dirty trees (record `git status` short + a content hash, e.g. `git rev-parse HEAD` plus `git diff --stat` hash) instead of bare HEAD SHA. No v0.2.0 artifact action (regeneration explicitly out of scope and unnecessary — §D).

## C. Candidate regression gate (exact candidate SHA `89ec190`)

- Full suite `python3 -m pytest tests -q -p no:cacheprovider --junitxml`: **2726 collected, 0 failures, 0 errors, 6 skipped** (→ 2720 passed), exit 0. Identical to G7 (src unchanged since G7 ran; only docs/reports/README/corpus-fixture commits after).
- Matrix validity: `git diff 5c80880..HEAD -- src/` is EMPTY (product code identical to the green online run); the only `tests/` delta is the 20 committed `post_t021/` fixtures, which were present (untracked) during G7 — suite count reconciles (2726 = 2722 + 4 new G+I cases… precisely: 2726 collected now vs 2726 at G7).
- Skips + env-blocked preserved verbatim (6 justified skips; Pi/Jan/AnythingLLM + PS-live + key rotation unchanged). No universal-platform claim (matrix = ubuntu-24.04 × windows-2025 × py3.11/3.14 full battery only).
- Release gating: `release.yml` triggers on `push.tags v*` only; no new tags (`v0.1.0`, `v0.2.0` only, `v0.2.0`→`67512ab` unmoved); no release runs since 2026-10-07; `runtime-parity.yml` contains no publish/tag steps. **No release triggered.**

## D. v0.2.0 immutability — CONFIRMED

Tags annotated and unmoved; `git diff v0.2.0..HEAD -- release/` = `CHANGELOG.md` notes only (`SHA256SUMS`, `release-manifest.json` identical); published wheel/sdist hashes unchanged (`010409b4…` / `a5a199dd…`); PyPI untouched (read-only metadata check by O2, no upload).

## Recommendation: GO (with listed risks; no version decision, no publication)

GO because: sanitizer behavior is bounded, probed, and regression-green (§A); artifact provenance is reproducible and internally consistent with the O2 item fully explained by evidence (§B1–B5); the candidate passes the full suite at its exact SHA with the online matrix valid for its product code (§C); releases are untouched (§D).

**Outstanding risks (do not invert GO, must travel with it):** heuristic open-by-design residuals (L1/M2/D5-D6 bypassable inputs documented); platform scope edges (PS-live, quoting/Unicode/Ctrl-C, non-matrix combos untested); host env-blockeds (AnythingLLM/Pi/Jan) + test-key LOW/OPEN; manifest dirty-tree labeling weakness (§B remediation); published 0.2.0 predates the T21-G fix by design (fix rides the next version — number and publish explicitly out of scope here).
