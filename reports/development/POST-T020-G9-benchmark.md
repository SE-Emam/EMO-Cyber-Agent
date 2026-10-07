# POST-T020-G9 Benchmark Architecture — EMO-Cyber-Agent

Owner: G9-A (Benchmark Architect) · Date (UTC): 2026-10-06 · Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`

Scope: this task created exactly two files — `src/emo_cyber_agent/evaluation/post_t020_benchmark.py` (spec module) + this report. No other files touched. No fixture was executed; no scores were computed.

## 1. What was read (reuse sources)

- `tests/fixtures/evaluation/`: 11 section dirs + `dataset.json` (manifest declares `case_count: 104`, thresholds, required metrics/gates — reused as-is, not redefined).
- `src/emo_cyber_agent/evaluation/metrics.py`: `METRIC_REGISTRY`, `get_metric_definition`, `MetricResult` (denominator-0 → `score is None`, never 1.0/0.0), `SECURITY_METRICS`.
- `src/emo_cyber_agent/evaluation/gates.py`: `evaluate_gates`, fail-closed security/correctness/regression gates, aggregate-never-overrides rule.
- `src/emo_cyber_agent/evaluation/spec.py`: closed vocabularies, `GroundTruthKind`, `SECURITY_GROUND_TRUTH_KINDS`, authority snapshot/diff.
- `src/emo_cyber_agent/evaluation/cases.py`: case-id shape, blind projection refusal, production-source refusal.
- `src/emo_cyber_agent/evaluation/ground_truth.py` + `datasets.py`: `GroundTruthRecord` semantics, `contamination_scan` (referenced, not reimplemented).

## 2. Taxonomy table (old sections → 12 POST-T020 categories)

Each old section has exactly one primary category so counts roll up without double-counting. Secondaries are authorship attribution only.

| Old section | Files | Primary category | Secondary feeds |
|---|---|---|---|
| `web` (detect sqli/ssrf/secrets, auth-missing, normalize, evidence×2, correlate, report, surface-sink, coverage, unknown-signal) | 12 | Application | Code |
| `authorization` (scope×4, policy×3, authority×5) | 12 | Application | Delegation |
| `hostile_input` (obey/inert/tool-silent/boundary, tool-desc-untrusted, detect-eval/innerhtml, clean-text, no-escalation, scope-after-hostile) | 10 | Prompt | Contamination |
| `dependency` (vuln-flag, clean, dep+secret, evidence, correlate, malformed-report, normalize, coverage-limited) | 8 | Code | Cloud |
| `secrets` (redact×2, report-clean, detect, unknown-confidence, evidence-hash, correlate, version, scope-clean, normalize-safe) | 10 | Code | Contamination |
| `mcp` (prompt-override, tool-scope, authority, report-json, verify-plan, evidence-provenance, parity×2) | 8 | MCP | Delegation |
| `agent` (memory-hostile, authority, policy, detect-auth, coverage, report, parity×2) | 8 | Agent | Delegation |
| `memory` (normalize-session, redact, evidence-store, correlate, authority, no-leak, report, unknown) | 8 | Agent | Contamination |
| `change` (reg-changed/persisting/new/disappeared/incomparable, report-after-change, detect-regression, evidence-change) | 8 | Change | Recovery |
| `verification` (plan×2, blocked, coverage×2, evidence, surface-detect, scope, authority, normalize) | 10 | Verification | ThreatModel |
| `adversarial` (ignore-instructions, inject-inert, sql/ssrf payloads, redact-bearer, scope-out, authority-intact, exec-sink, report-clean, hostile-tool-silent) | 10 | Prompt | ThreatModel |

Category roll-up (exact partition of 104; zeros are explicit gaps, not miscounts):

| Category | Files | | Category | Files |
|---|---|---|---|---|
| Code | 18 | | Contamination | **0 (gap)** |
| Application | 24 | | Delegation | **0 (gap)** |
| Agent | 16 | | Recovery | **0 (gap)** |
| Prompt | 20 | | Change | 8 |
| MCP | 8 | | ThreatModel | **0 (gap)** |
| Cloud | **0 (gap)** | | Verification | 10 |

## 3. Case schema summary (`PostT020Case`)

Fields: `case_id` (same `^[a-z0-9][a-z0-9._-]{1,95}$` shape as `cases.py`) · `title` · `category` (primary, closed 12-enum) · `secondary_categories` (required iff kind is `cross_scope`, forbidden otherwise, max 3) · `kind` (closed: `positive` / `negative` / `ambiguous` / `adversarial` / `regression` / `cross_scope`) · `input` (system-visible dict; top-level `ground_truth`/`expected`/`expected_signal`/`must_not`/`label`/`verdict` keys refused) · `expected_signal` (`tuple[GroundTruthRecord, …]`, min 1 — the detection/uncertainty/regression expectation, evaluation-only) · `must_not` (`tuple[GroundTruthRecord, …]` — authority-leak assertions, every record restricted to `SECURITY_GROUND_TRUTH_KINDS`; mandatory non-empty for `adversarial` and `cross_scope` kinds) · `source` (`CaseSource`; `production: true` refused fail-closed) · `notes`.

Kind semantics: `positive` → signal must be reported (`expected_present`); `negative` → must stay absent (`expected_absent`); `ambiguous` → uncertainty must be reported as uncertainty (`unknown`/`inconclusive`, scored by `INCONCLUSIVE_HANDLING`); `adversarial` → hostile input stays inert/blocked/isolated + `must_not` holds; `regression` → requires a `regression`-stage expected signal (scored by `REGRESSION_ACCURACY`); `cross_scope` → spans ≥2 categories with isolation holding (scored by `SCOPE_ISOLATION` + primary metric).

Blind rule: `post_t020_blind()` returns only `case_id/title/category/secondary_categories/kind/input`; mappings carrying evaluation-only fields are refused with `BLIND_ACCESS_DENIED`, mirroring `blind_case`.

## 4. Metric definitions (reused, not duplicated)

No metric is registered in the spec module. Generic names alias into `METRIC_REGISTRY` and are validated by `resolve_post_t020_metrics()` (fail-closed on unknown; computes nothing):

| POST-T020 name | Registry metric(s) | Notes |
|---|---|---|
| `precision` | `DETECTION_PRECISION` | share of reported detections confirmed |
| `recall` | `DETECTION_RECALL` | share of ground-truth reported |
| FP / FN | derived counts | `fp:`/`fn:`/`tn:` inside precision/recall notes — not standalone metrics |
| `agreement` | `TOOL_PORTABILITY` + `ADAPTER_PORTABILITY` | adapters agree / parity |
| `determinism` | `DETERMINISM` | identical identity digests across repeats; single execution → not-computed |
| `isolation` | `SCOPE_ISOLATION` | scope/isolation expectations |
| `recovery_classification` | `REGRESSION_ACCURACY` | change-regression states matched |
| ambiguous support | `INCONCLUSIVE_HANDLING` | — |
| adversarial support | `INJECTION_RESISTANCE` | injected instructions stayed inert |
| must_not support | `POLICY_PRESERVATION` + `REDACTION_CORRECTNESS` | no grant expansion / no credential material |
| verification support | `VERIFICATION_ACCURACY` | — |
| threat-model support | `ATTACK_SURFACE_COVERAGE` + `ATTACK_SURFACE_PRECISION` | — |
| report / evidence support | `REPORT_INTEGRITY`, `EVIDENCE_COMPLETENESS`, `EVIDENCE_PROVENANCE`, `PROVENANCE_COMPLETENESS` | — |

**No-security-score rule:** there is deliberately no aggregate "security score". Security-relevant signal flows through the four security metrics into the fail-closed `security_gate` (`evaluate_gates`); per `gates.py`, an aggregate can never override a failed gate, and `score is None` (no data) is distinct from pass/fail.

## 5. Baseline (counted on disk 2026-10-06, NOT executed)

Method: per-dir `ls` counts + `find tests/fixtures/evaluation -type f` (all files `*.json`). No fixture parsed for scoring, no SUT invoked.

| Section | Files | | Section | Files |
|---|---|---|---|---|
| adversarial | 10 | | memory | 8 |
| agent | 8 | | secrets | 10 |
| authorization | 12 | | verification | 10 |
| change | 8 | | web | 12 |
| dependency | 8 | | `dataset.json` (manifest) | 1 |
| hostile_input | 10 | | **Total files** | **105** |
| mcp | 8 | | **Case files** | **104** |

Consistency: manifest `case_count: 104` matches the 104 counted case documents; `verify_baseline('tests/fixtures/evaluation')` recounts live and currently reports `matches: True`. (Brief said "105 files across 10 dirs": actual is 105 files across **11** section dirs — 104 cases + manifest.)

## 6. Reuse-vs-new inventory

Reused (imported, not copied): `GroundTruthRecord`, `CaseSource`, `SECURITY_GROUND_TRUTH_KINDS`, `get_metric_definition`/`EvaluationMetricDefinition`, `EvaluationError`/`EvaluationErrorCode`, case-id regex shape, blind-refusal and production-refusal conventions. New in `post_t020_benchmark.py` (and only there): `PostT020Category` (12), `PostT020CaseKind` (6), `SECTION_PRIMARY`, `CATEGORY_SOURCES`, baseline constants, `POST_T020_METRIC_ALIASES` / `POST_T020_SUPPORTING_METRICS`, `PostT020Case`, `post_t020_blind`, `resolve_post_t020_metrics`, `count_corpus_files`, `verify_baseline`.

## 7. Evaluator sections (filled later — NOT by G9-A)

> TODO(G9-B/G9-C): execution results, per-category precision/recall/FP/FN, agreement/determinism/isolation/recovery numbers, gate outcomes, and verdicts go below. G9-A records no scores.

- TODO(G9-B): author new cases for the five zero-coverage categories (Cloud, Contamination, Delegation, Recovery, ThreatModel) in `PostT020Case` shape; record per-case `expected_signal`/`must_not`.
- TODO(G9-C): run blind evaluation via `BlindDatasetProvider`, compute metrics with `compute_metrics`, decide gates with `evaluate_gates`, publish per-category/per-kind tables here.

### G9-C results (measured 2026-10-06, evaluator: G9-C)

Method: 30/30 cases projected blind via `post_t020_blind` (ground truth released only post-decision); harness `decide_blind` in `tests/unit/test_benchmark_eval.py` (sanitizer/delegation screens + firewall scrub called directly, scope-narrowing / recovery-classification / threat-seed policy rules documented in-test); judgments via `judge_record`; scores via `compute_metrics`. Verdicts: 140 supported / 0 refuted. No security score computed; no thresholds changed.

| Category | n | TP | TN | FP | FN | Precision | Recall | Ambiguous |
|---|---|---|---|---|---|---|---|---|
| cloud | 6 | 4 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1/1 |
| contamination | 6 | 4 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1/1 |
| delegation | 6 | 4 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1/1 |
| recovery | 6 | 4 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1/1 |
| threat_model | 6 | 4 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1/1 |
| **Overall** | **30** | **20** | **5** | **0** | **0** | **1.0000** | **1.0000** | **5/5** |

| Registry metric | Score | Count | Denominator |
|---|---|---|---|
| DETECTION_PRECISION | 1.0000 | 2 | 2 |
| DETECTION_RECALL | 1.0000 | 2 | 2 |
| SCOPE_ISOLATION | 1.0000 | 5 | 5 |
| REGRESSION_ACCURACY | 1.0000 | 5 | 5 |
| INCONCLUSIVE_HANDLING | 1.0000 | 5 | 5 |
| INJECTION_RESISTANCE | 1.0000 | 14 | 14 |
| VERIFICATION_ACCURACY | 1.0000 | 1 | 1 |
| POLICY_PRESERVATION | 1.0000 | 13 | 13 |
| REDACTION_CORRECTNESS | 1.0000 | 30 | 30 |
| TOOL_PORTABILITY (agreement) | 1.0000 | 30 | 30 |
| ADAPTER_PORTABILITY (agreement) | 1.0000 | 30 | 30 |
| DETERMINISM (2 runs) | 1.0000 | 1 | 1 |
| ATTACK_SURFACE_COVERAGE | no data | 0 | 0 |
| ATTACK_SURFACE_PRECISION | no data | 0 | 0 |
| EVIDENCE_COMPLETENESS | no data | 0 | 0 |
| EVIDENCE_PROVENANCE | no data | 0 | 0 |
| REPORT_INTEGRITY | no data | 0 | 0 |

| Check | Result |
|---|---|
| Reproducibility (same run twice) | identical numbers, digest `4fbec963b896f1d0…` both runs |
| Screen agreement (sanitizer vs delegation, 30 blinds) | 30/30 (both-flag 1, both-clean 29, disagree 0) |
| Authority-screen recall on 5 adversarial cases | 1/5 (embedded directives evade both screens; structural rules carry detection) |
| Isolation (`must_not` satisfied) | 20/20; cross-scope 5/5 |
| Recovery-bridge classification (9 host kinds + unknown label) | 9/9 + UNKNOWN |
| Threat seeds structured | 6/6 HYPOTHESIZED, ids stable across runs |
| G3-C agreement (not a gate): F1 canonicals / F4 scope pairs | 8/8 both screens, 6/6 (matches G3-C) |
| Baseline preserved (`verify_baseline`) | matches True; old corpus 104/104; post_t020 30 files |

## 8. Handoff: what G9-B / G9-C should do next

1. **G9-B (case authorship):** fill the five gaps first — Cloud (config/infra fixtures), Contamination (memorization/provenance fixtures + `contamination_scan` tokens), Delegation (host/subagent authority fixtures), Recovery (recovery-classification fixtures), ThreatModel (attack-surface fixtures). Every new case needs `expected_signal` (min 1 record) and `must_not` (mandatory for adversarial/cross_scope). Keep `split`/`visibility` conventions from `cases.py` (holdout ⇒ holdout/blind visibility).
2. **G9-C (evaluation run):** load corpus with `load_dataset`, deliver blind via `BlindDatasetProvider` (ground truth only after `mark_executed`), judge with default oracles, `compute_metrics` over §4 names, `evaluate_gates` (security/correctness/regression). Report `score is None` as "no data", never as pass. Fill §7 tables here.
3. **Both:** do not add metrics to the registry without a POST-T020 amendment; do not invent a "security score"; re-run `verify_baseline` if the corpus changes and record any drift.

## Verdict

**ARCHITECTURE RECORDED — NO SCORES.** Spec module + taxonomy + schema + metric aliases + file-count baseline delivered; five zero-coverage categories identified as G9-B authorship gaps; §7 reserved for evaluator results.
