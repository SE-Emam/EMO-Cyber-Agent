# POST-T021 Wave D Assessment — Wave D Synthesizer

Date (UTC): 2026-10-08 · Owner: Wave D Assessment Synthesizer · Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
Scope: READ-ONLY everywhere except this file. No `src/`/`tests/`/corpus edits performed by this agent.
Inputs: T21-F (`reports/security/POST-T021-heuristic-gap.md`), T21-I (`reports/development/POST-T021-benchmark-maintenance.md`), T21-K (`reports/security/POST-T021-test-secret-hygiene.md`), T21-H (`reports/development/POST-T021-heuristic-evaluation.md`), T21-J (`reports/development/POST-T021-benchmark-evaluation.md`), T21-G change + subagent suite result (passed in), T21-SEC-D findings (passed in), `git status --porcelain` + `git diff --stat` (live 2026-10-08, quoted §2).

## 1. Agent ownership table

| Agent | Role | File(s) owned (wrote/modified) |
|---|---|---|
| T21-F (Heuristic Auditor) | Gap audit, 3 known residuals + 1 NEW bypass | `reports/security/POST-T021-heuristic-gap.md` only (read-only on `src/`/`tests/`) |
| T21-I (Benchmark Maintenance) | +20 corpus cases | `reports/development/POST-T021-benchmark-maintenance.md` + ADDED dir `tests/fixtures/evaluation/post_t021/` (20 files); 0 existing files modified |
| T21-K (Test-Key Hygiene) | Secret-hygiene audit + rotation attempt | `reports/security/POST-T021-test-secret-hygiene.md` only |
| T21-G (Hardening) | Bounded `normalize()` separator fix + 4 regression tests | `src/emo_cyber_agent/subagent/sanitizer.py` (one-spot fix) + `tests/unit/subagent/test_sanitizer.py` (3 new) + `tests/unit/subagent/test_delegation.py` (1 mirror) |
| T21-H (Heuristic Evaluation) | Adversarial before/after + determinism + regression check | `reports/development/POST-T021-heuristic-evaluation.md` only (read-only on impl) |
| T21-J (Benchmark Evaluation) | Reproducibility/stability/inflation/coupling check | `reports/development/POST-T021-benchmark-evaluation.md` only (read-only) |
| T21-SEC-D (Security Review) | Wave D security verdict | Findings passed in (no file owned by this synthesis): TRUSTED-by-match PASS; separator PASS; D5/D6 unchanged-open PASS; FP PASS; no permission/severity/verification/evidence change; secrets CLEAR; overall WAVE-D SECURITY PASS |
| Wave D Synthesizer (this agent) | Cross-agent assessment + G3/G4 decisions | This file only: `reports/development/POST-T021-wave-d-assessment.md` |

## 2. Modified files — exact list (live `git status --porcelain` + `git diff --stat`)

Tracked modified (4 files, `git diff --stat`: 62 insertions, 6 deletions):
- `src/emo_cyber_agent/subagent/sanitizer.py` (20 ++++---, T21-G one-spot fix) — Wave D `src` change: ONLY this file.
- `tests/unit/subagent/test_sanitizer.py` (38 +++, 3 new cases) — Wave D test change 1/2.
- `tests/unit/subagent/test_delegation.py` (8 ++++, 1 mirror case) — Wave D test change 2/2.
- `reports/development/POST-T020-G1-host-matrix.md` (2 +-; pre-existing Wave G1 file, 1-line tweak, NOT Wave D scope — listed for exactness).

New untracked corpus (20 files under `tests/fixtures/evaluation/post_t021/`): `t021-anythingllm-{01,02,03,04}`, `t021-pi-{01,02}`, `t021-jan-{01,02}`, `t021-http-{01,02,03}`, `t021-path-{01,02,03,04}`, `t021-heur-{01,02,03,04}`, `t021-reg-01-platform-alias-regression` (all `.json`; full stems §6).

New untracked reports (Wave D owned + out-of-scope siblings present in tree, listed for exactness; Wave D owned: F/I/K/H/J + this file):
- Wave D: `reports/security/POST-T021-heuristic-gap.md`, `reports/development/POST-T021-benchmark-maintenance.md`, `reports/security/POST-T021-test-secret-hygiene.md`, `reports/development/POST-T021-heuristic-evaluation.md`, `reports/development/POST-T021-benchmark-evaluation.md`, this file.
- Sibling untracked (NOT Wave D, present in `git status`): `POST-T021-G2-platform-parity-review.md`, `POST-T021-android-{assessment,cli,discovery,e2e,final-review,http,install,mcp,resources,runtime}.md`, `POST-T021-baseline.md`, `POST-T021-gap-matrix.md`, `POST-T021-{jan-native,linux-parity,pi-native,windows-parity}.md`, `reports/security/POST-T021-android-security.md`, `reports/security/POST-T021-anythingllm-adversarial.md`.

## 3. Exact tests + results

- T21-G subagent suite: **722 passed / 1 skipped / 0 failed**, incl. 4 new cases (3 sanitizer + 1 delegation mirror for `\r`/`\x0b`/`\x0c` word-join).
- T21-H heuristic evaluation (hardened code, live): fixed class **13 TP / 0 FN / 0 FP** (TN=2 benign CRLF); **37/37 determinism** (15 fixed + 7 M2 + 19 D5/D6 + L1 probes, each 3x identical); **no regression** (zero F-recorded deny→allow flips; zero new benign denies; documented classes byte-identical: L1 8/8, M2 7/7, D5/D6 19/19 incl. `n=34 deny / n=39 allow` window edge).
- T21-J benchmark evaluation: **5/5 PASS** dimensions (reproducibility / baseline stability / new cases / no mock-to-host inflation / no benchmark→policy coupling); counts 135→155 reconcile; fingerprint match `d3db766b98e975d3a7d3800d546ff375e7688f50d459420b222e0303724c5898` (full: `d3db766b…0303724c`).

## 4. Key-hygiene outcome (T21-K)

- App DB at rest: **1 row FOUND** — `api_keys.id=1` (`ak-test-<redacted>`, secret length non-zero) in `~/Library/Application Support/anythingllm-desktop/storage/anythingllm.db`; sibling tables 0 rows.
- Tracked files / fixtures / shell history / logs / screenshots / repo env: **CLEAR** (no `ak-test-<redacted>` value anywhere; `sk-` hits are false-positive substrings; 2 `ghp_` hits are pre-existing synthetic fixtures; logs prose-only; no repo `.env*`; server `.env` holds provider-name slots only, no test-key value).
- Rotation: **ENV-BLOCKED, app DOWN** (no process, port 3001 refused, `/api/ping` curl exit 7); old-key-dead 401 proof NOT OBTAINED (no unsafe call against down port).
- Residual: **LOW but OPEN** — local-disk-only test key persists until operator runs: `open -a AnythingLLM` → Settings → API Keys → delete `id=1` → re-probe auth endpoint expecting `401` without printing the key.

## 5. Heuristic before/after (F → G → H)

- 3 known residuals → **DOCUMENTED, unchanged**: L1 string-root trust (attacker-clone ⇒ TRUSTED, double-space skill ⇒ TRUSTED, classifier fail-closed — 8/8 re-verified); M2 partial map (61 entries; mapped ⇒ deny, palochka/de/ghe/admin ⇒ allow BYPASS — 7/7 re-verified); D5/D6 reorder/padding/separators (reorder/insert/pad>~38ch/punctuation/hyphen/intra-token ⇒ allow BYPASS; casing/repeats/NBSP/ZWSP/newline-between-tokens ⇒ deny — 19/19 re-verified).
- 1 NEW word-join (`\r`/`\x0b`/`\x0c` deleted → `ignorethe policy`, both screens miss, firewall admits) → **FIXED via separator**: `normalize()` now emits one `" "` only where deletion would fuse content chars (collapses runs, suppresses next to whitespace/edges, `\r\n`→`\n` preserved); delegation inherits via shared normalizer; F1–F15 all deny with spans on both screens.
- Benign CRLF: **safe** — `line1\r\nline2`→`line1\nline2`, `a\rb\r\nc`→`a b\nc`, both `sanitize` with zero authority labels (no FP); intended `sanitized.text` deltas (`abcdef`→`a b c d e f` class) stay non-authority.

## 6. Benchmark before/after (I → J)

- Counts: **135 → 155** (+20 `post_t021/`; manifest `case_count=104` intentionally untouched — pre-existing staleness, owner versioning per Gap 7).
- Class split **13 adversarial / 3 ambiguous / 2 negative / 1 positive / 1 regression** (65% adversarial max, no >0.6-Jaccard duplicate pair, each row gap-mapped with `must_not` invariants on adversarial, `source.fixture=post-t021`, no `cross_scope`, no `expected` inside `input`).
- **NOT-COVERED list carried** (nothing faked): live Pi round-trip, live Jan inference, Linux runtime proof, Windows runtime proof (D1 alias source-present/runtime-unproven), live AnythingLLM-via-host remainder, M1/M3/R1/R2/L2 (closed, no variants), Gap 8 credential hygiene + Gap 9 meta (not corpus-testable).

## 7. Security outcome (SEC-D, as passed in)

**WAVE-D SECURITY PASS, no Crit/High/Med.** Per-finding: TRUSTED-by-match PASS (advisory only, Core decides); separator fix PASS (no over-redaction, CRLF safe); D5/D6 unchanged-open PASS (documented detective-only); FP PASS (no benign-text alarm introduced); no permission / severity / verification / evidence-model change; secrets CLEAR in Wave D diff.

## 8. Remaining limitations

- M2 partial map stays open-by-design (d/f/g/l/n/q/r/w + U+04CF; over-folding FP risk `н→h`/`р→p` argues against hasty extension).
- D5/D6 reorder/padding/punctuation stays open-by-design (widening risks benign-text FPs).
- Linux/Windows runtime proof still open (no runner/host; path/exec shapes are corpus inputs only).
- Test key at rest persists (LOW/OPEN, operator-side one-liner + 401 proof pending).
- Meta items unchanged: manifest staleness (`case_count=104` vs additive dirs), `POST-T020-G1-host-matrix.md` 1-line tweak outside Wave D scope, sibling Android/platform reports out of scope.

## 9. G3 decision: PASS

Gate G3 (heuristic hardening must fix-or-document without authority leakage, regression, or irreproducibility):
- fixes-or-documented ✓ (NEW word-join FIXED with 13TP/0FN/0FP; L1/M2/D5-D6 DOCUMENTED with live re-verification 8/8 + 7/7 + 19/19)
- no authority leakage ✓ (SEC-D TRUSTED-by-match PASS; trust advisory-only; firewall ignores classification claims; Core decides)
- no unexplained regression ✓ (H: zero deny→allow flips, zero new benign denies; G suite 722/1/0; intended FN→TP flips + non-authority text deltas openly surfaced)
- reproducible ✓ (37/37 determinism 3x; runnable probe blocks in F/H)
- residuals documented ✓ (F §§Residual 1–3 + NEW bypass; H §2 before/after quotes; §8 limitations)

**G3: PASS.**

## 10. G4 decision: PASS

Gate G4 (benchmark extension must preserve baseline, map to real gaps, reproduce, and claim no policy control or host proof):
- baseline preserved ✓ (J: fingerprint `d3db766b…0303724c` exact match; `?? post_t021/` only; 0 tracked-file mods under evaluation dir)
- mapped to real gaps ✓ (J: 20/20 gap-id→source→expected→class rows verified; 13/3/2/1/1 split; no >0.6 duplicate)
- reproducible ✓ (J: 155 count reconciles; static sha + reg-target + heur-score 2x identical; volatile-token scan clean)
- no policy control ✓ (J §5: no Policy directive/severity/escalation; residual labels are descriptors with measurement-only disclaimers)
- no unexplained conflicts ✓ (J §4: every host-adjacent case carries NOT-proof label; grep returns only denial strings; NOT-COVERED list carried openly)

**G4: PASS.**

## 11. Blockers

**None for Wave D.** Test-key rotation stays operator-side OPEN (app-down ENV-BLOCKED, LOW local-only residual + one-liner in §4) — non-blocking for Wave D close-out.
