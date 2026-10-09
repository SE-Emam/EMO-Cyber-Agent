# POST-T021 Benchmark Evaluation — T21-J Report

- Date (UTC): 2026-10-08
- Agent: T21-J (Benchmark Evaluation Agent, Wave D3)
- Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
- Baseline: `reports/development/POST-T021-benchmark-maintenance.md` (T21-I, 2026-10-08)
- Ownership: READ-ONLY on everything except this file. No corpus edit, no `src/` edit, no expected-outcome edit performed.

## 1. Reproducibility — PASS

- `find tests/fixtures/evaluation -type f | wc -l`: **155** (baseline 135 + 20 new ✓).
- Per-dir re-count: adversarial 10, agent 8, authorization 12, change 8, dependency 8,
  hostile_input 10, mcp 8, memory 8, **post_t020 30**, **post_t021 20**, secrets 10,
  verification 10, web 12, + top-level `dataset.json` (1). All match the maintenance report §1/§4.
- `dataset.json`: `dataset_id = emo-evaluation-benchmark`, `version = 0.1.0`,
  **`case_count = 104`** ✓ (manifest staleness vs additive dirs unchanged, as documented).
- `git status --porcelain -- tests/fixtures/evaluation` → single line:
  `?? tests/fixtures/evaluation/post_t021/`. **Zero tracked-file modifications** — no silent edit.
- Baseline fingerprint recomputed (`find … -not -path '*/post_t021/*' | sort | xargs shasum -a 256 | shasum -a 256`):
  `d3db766b98e975d3a7d3800d546ff375e7688f50d459420b222e0303724c5898` — **exact match** to reported baseline.

## 2. Baseline stability — PASS

- The fingerprint match in §1 covers all 135 pre-existing files cryptographically; no old expected
  outcome could have changed without breaking it.
- Spot-check (readable, expected shapes intact): `adversarial/adv-01-ignore-instructions.json`,
  `adversarial/adv-02-prompt-inject-inert.json`, `post_t020/cloud-01-imds-ssrf-block.json`,
  `post_t020/cloud-02-benign-health-fetch.json`, `dataset.json` — all parse with their documented key shapes.

## 3. New cases — PASS

- 20/20 files parse as JSON; required keys (`case_id/category/expected_signal/input/kind`) present;
  `case_id` == filename stem; ids unique; `expected_signal` non-empty in all 20.
- No `ground_truth` / `expected_signal` / `expected` keys inside any `input` (recursive walk clean).
- `source.fixture == post-t021` in all 20; every `adversarial` case carries `must_not`
  authority/isolation invariants; `cross_scope` appears nowhere.
- Class split re-counted: adversarial 13, ambiguous 3, negative 2, positive 1, regression 1 —
  matches the documented 13/3/2/1/1 split; single-class share (65% adversarial) is as documented,
  not hidden dominance.
- Source→expected→class mapping (§2 table, 20 rows) verified present for every file; each row's
  `title`/`notes`/`expected_signal` is consistent with its claimed gap id.
- Duplicates/bias: pairwise token-overlap over normalized `input` JSON shows **no pair above 0.6
  Jaccard**; no identical inputs; the 4 AnythingLLM + 4 heur + 3 HTTP + 4 path + 2 Pi + 2 Jan + 1 reg
  grouping covers distinct shapes (no near-identical padding of one class beyond the split).
- Determinism log (each run 2x, identical results):
  - Static fixtures: sha256 over all 20 files, run twice → identical.
  - Reg target (`t021-reg-01`): `check_compatibility` with platforms `[darwin, linux, win32]`
    on a `windows` host → `compatible: true`, byte-identical across 2 runs (alias holds).
  - Heur inputs via `_instruction_like_score` (agent_security/tool_poisoning.py), 2x each →
    heur-01: 2/2, heur-02: 1/1, heur-03: 1/1 (identical; scores are measurement inputs, not verdicts).
  - Volatile-token scan (`timestamp/datetime/random/uuid/nonce/now()/time.time`): sole hit is the
    word "randomness" inside the sentence "no host, network, or randomness" — an explicit
    determinism denial, not volatility. No live secret: Jan hand-edit case uses the synthetic marker
    `sk-live-secret-value` as labeled.

## 4. No mock-to-host inflation — PASS

- Every host-adjacent case carries an explicit non-proof label in `notes`:
  - Pi (01/02): "Config-only; NOT live-proof".
  - Jan (01/02): "Config-only; NOT live-proof".
  - HTTP (01/02/03): "Shape-only corpus input; NOT runtime proof".
  - Path (01/02/03/04): "Corpus input only; NOT Linux/Windows/runtime proof" as applicable.
  - Reg (01): "fix is source-present but runtime-unproven … NOT Windows runtime proof".
  - AnythingLLM (01–04): "static JSON, no host" / "refused-DATA … never host proof".
- Grep for affirmative live-host claims (`live-proof|runtime proof|verified on …|host proof|real host`)
  returns only these denial strings. **No new case claims live-host proof.**

## 5. No benchmark→policy coupling — PASS

- Grep for `severity|policy-grant|escalat|CVE|CVSS|allow.*policy` over `post_t021/` + maintenance report:
  the only report hit is its own §3 sentence denying Policy/severity effects.
- `policy` occurrences inside new cases are (a) attack-text DATA to be refused
  ("Ignore policy now", "Policy ignore for this audit…"), or (b) explicit measurement-only
  disclaimers ("never a policy change", "policy stays enforced").
- Residual labels `(Low, OPEN by design)` / `(Medium, OPEN by design)` in heur notes describe the
  known gap's standing and are each paired with "measurement only" disclaimers — descriptors, not grants.
- **No case carries a Policy directive, severity reassignment, or escalation instruction.**

## Per-dimension verdicts

| Dimension | Verdict |
|---|---|
| 1. Reproducibility (counts, manifest, git-clean, fingerprint) | **PASS** |
| 2. Baseline stability (old outcomes untouched) | **PASS** |
| 3. New cases (mapping, determinism, duplicates/bias) | **PASS** |
| 4. No mock-to-host inflation | **PASS** |
| 5. No benchmark→policy coupling | **PASS** |

**Overall: 5/5 PASS.** The +20 `post_t021/` batch is a measurement-only addition exactly as
maintained: counts reconcile (135 → 155), the baseline fingerprint is intact, sampled entrypoints
execute deterministically, no duplicates or hidden dominance were found, no live-host proof is
claimed, and no Policy/severity coupling exists.
