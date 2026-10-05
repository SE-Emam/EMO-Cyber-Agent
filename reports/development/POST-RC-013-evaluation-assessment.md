# POST-RC-013 — Evaluation & Benchmark Lab Assessment

## Objective
Measure the shipped system instead of asserting it: a blind
fixture corpus, a deterministic scoring runner, ground-truth and
redaction/authority/parity oracles, metric pools and threshold
gates, cross-interface parity checks, and a reproducible run/report
contract — so that Core owns evaluation, transports are only SUT
adapters, ground truth never leaks into the system under test, and
every claim in this document is reproducible from a command.

## Scope
In scope: `src/emo_cyber_agent/evaluation/` (14 modules, 4,891
lines, 95 exports), 5 new JSON schemas (33 total), 104 blind
fixtures in 11 sections plus `dataset.json` manifest, 6 new test
files (116 tests), one one-line MCP projection fix, one MCP-output
field fix, and one fixture-naming fix for contamination. Out of
scope (deferred): stored run history across sessions, human-rater
calibration, live model/provider judging, drift dashboards,
multi-version baselines, automatic threshold tuning, and any write
path from evaluation into findings or trust.

## Architecture
Host → `load_dataset()`/`build_dataset()` → blind
`BlindEvaluationCase` (scenario payload + ground truth, split into
provider and evaluation views) → `EvaluationRunner.run(sections/
tracks/cases, repeat)` → per case: `SUTAdapter.invoke` → typed
observations → oracle battery (`ground_truth`, `redaction`,
`authority`, `parity`) → judgments → metric pools
(`SECURITY_METRICS` plus precision/recall/coverage/provenance/
determinism/regression families) → gate evaluation
(`security_gate`, `correctness_gate`, `regression_gate` against
manifest thresholds) → frozen `EvaluationRun` → `build_report()` →
`reports/*.json` under the run digest. Selection, ordering,
repeat ordering, digests and gate evaluation are all pure and
deterministic; the model is never consulted and no network, process
or filesystem write happens anywhere in the layer.

## Boundaries (enforced, tested)
Ground-truth isolation: the SUT view carries only scenario payload;
`test_ground_truth_never_reaches_the_system` proves the blind case
exposes no expected values, and scripted operations are rules over
payload only. Contamination: `contamination_scan` over 40 forbidden
tokens (model, provider, credential and sibling-fixture identifiers)
returns zero hits on all 104 cases; one real hit was found and fixed
during development — the negative token `injection` matched the
sibling fixture id `agent_config.json`, so the hostile-input
material was renamed (`injection` → `hostile_input` section, case
ids, titles and tags; the stale `tests/fixtures/evaluation/injection/`
directory was removed) instead of weakening the scanner. Offline:
a static scan of the package refuses `requests`, `socket`,
`subprocess`, `urllib`, `os.system(`, `shell=True`, `open(`-for-write
and learning hooks (`remember(`, `promote_candidate(`,
`store.add(`) outside string literals, and the E2E file asserts the
same for its own code. Error honesty: unknown metric/gate names,
empty selections, provider/dataset digest mismatches and
already-concluded runs all raise typed `EvaluationError` codes;
adapter failures become `ADAPTER_ERROR`/`ADAPTER_CAPABILITY_MISSING`
observations that count as disagreements, never as passes.
No authority: evaluation never writes a Finding, never assigns
severity, and `evaluation.report` renders — it does not decide.

## Contracts
Frozen, extra-forbidden, digest-carrying models: `EvaluationCase`
(13 stages, 6 tracks, 14 scenario kinds, closed ground-truth kinds),
`BlindDatasetProvider`/`BlindEvaluationCase` (dataset digest binding),
`SUTResult`/`SUTAdapter` (capabilities declared, one `invoke`),
`EvaluationObservation`, `OracleJudgment` (closed verdicts,
`security_relevant`/`disagreement` flags), `MetricResult`
(`not_computed()` notes instead of fake zeroes, `higher_is_better`
declared per metric), `GateResult`/`GateSet` (closed gate statuses,
reason codes), `EvaluationRun` (counts, events, judgments, metrics,
gates, security disagreements, environment capture), `EvaluationReport`
(id `eval-<digest>`, reproducibility block, limitations). Schemas:
`evaluation-{case,dataset,run,report,metric}` validate every fixture
file and every artifact the runner emits (33/33 with the pre-existing
28). 18 metrics are computed on the shipped corpus; only
`ADAPTER_PORTABILITY` and `TOOL_PORTABILITY` are parity-only and
report `not_computed` on non-parity runs; all 8 manifest thresholds
are met at 1.0 or their declared value.

## Fixture Corpus
104 cases, 11 sections (web, authorization, hostile_input,
dependency, secrets, mcp, agent, memory, change, verification,
adversarial), tracks: reasoning 31, safety 23, authority 22,
detection 19, regression 5, parity 4. Manifest declares
`case_count: 104`, thresholds, required metrics/gates,
`baseline: {REGRESSION_ACCURACY: 1.0}`, `production: false`.
Ground-truth semantics were corrected during generation: expected
block outcomes for `accepted_instructions` and
`capability_escalation` are `False` (the system must accept, not
block), so no case asserts a contradictory expectation. Every case
file validates against `evaluation-case.schema.json` with zero
errors.

## Runner, Oracles, Metrics, Gates
`repeat=n` re-executes each case and `assert_deterministic` compares
stable digests (single execution is reported as
`single-execution`, never as a pass). `GroundTruthOracle` compares
closed kinds (`state` exact/absent, `expected_present`/`absent`
evidence, `unknown` → inconclusive, blind `judge_or_reject`),
`RedactionOracle` scans serialized output for credential patterns,
`AuthorityOracle` compares the probe snapshot against declared
expectations, `ParityOracle` reads cross-interface projections.
`evaluate_gates` applies manifest thresholds and required gates;
unknown gate names raise `GATE_UNKNOWN` (the `wanted` set always
includes the three real gates), `security_disagreements` filters on
`security_relevant`, and metrics excluded by
`NOT_APPLICABLE` leave the pool rather than dilute the score.

## Adversarial Results
All contained: a `HostileSUT` that obeys hostile payloads registers
security disagreements and fails `security_gate`; a `SilentSUT` that
reports nothing scores `DETECTION_RECALL = 0.0` and fails
`correctness_gate` with a `below-threshold` reason while precision
stays honestly `not computed`; MCP argument validation failures
surface as `EVALUATION_ADAPTER_ERROR`, not as data; unknown metric
and gate names are refused; a provider built over the wrong dataset
is refused as `INVALID_DATASET`; script-injection payloads in
fixture fields never reach the shipped corpus (contamination scan);
and the static scan proves there is no live attack surface in the
layer or its tests.

## Cross-Interface Parity & Fixes Found
`parity_audit` cases compare `audit_projection` (mode,
permission_profile, status, findings, limitations) across the real
Python API, CLI and MCP surfaces in-process: all three agree
(`mismatched_fields` empty, `failed_interfaces` empty,
`interfaces_ok = 3`) and both portability metrics score 1.0. Testing
caught two real adapter defects: `mcp/delegate.py` `call_audit` did
not return `permission_profile` inside the MCP result (silent parity
mismatch), and `McpSUTAdapter` passed `response["result"]` into
`_result_fields`, which expects a whole payload — so `status`,
`plan_id`, `method` and `safety_level` were dropped from MCP
(non-audit) outputs while the CLI returned them (interface
inconsistency). Both are fixed and covered by E2E assertions.

## Tests
`test_evaluation_spec.py` (40) +
`test_evaluation_datasets.py` (12) +
`test_evaluation_sut.py` (19) +
`test_evaluation_oracles_metrics_gates.py` (21) +
`test_evaluation_runner.py` (13) +
`test_evaluation_e2e.py` (11) — 116/116 new: spec/enum/digest
contracts, manifest and section integrity, contamination and
root-isolation scans, scripted/python-api/CLI/MCP adapter
behaviour (including `_parse_cli_output`, capability refusal and
projection parity), each oracle's supported/refuted/inconclusive
paths, metric pooling and determinism notes, gate refusal and
threshold evaluation, runner lifecycle (cancellation, stale state,
provider mismatch, report building), and the E2E suite: scripted
corpus green over the 100 non-parity cases at `repeat=3`, parity
green over the 4 parity cases through all three interfaces, hostile
and silent systems failing their gates, MCP in-process, and static
offline/learning scans of the package and the test file itself.
Full suite: **1179 passed, 3 skipped** (baseline 1063 + 116).
Schemas 33/33 valid. Testing caught the MCP projection and MCP
output-field defects above, the contamination token, the GT
block-outcome contradiction, and three test-side bugs (wrong module
imports for `BlindEvaluationCase`/`DETERMINISM`, CLI projection of
a non-mapping payload, and over-broad static bans that matched
`re.compile` and the in-memory `EvidenceStore.store` call).

## Files Inspected
- `docs/21-developer-agent-execution-directive.md` (12 invariants),
  `docs/14-mcp-agent-bridge.md` + `src/emo_cyber_agent/mcp/`
  (bridge contract and `delegate.py`), `src/emo_cyber_agent/cli/
  main.py` (documented CLI surface), `src/emo_cyber_agent/core/
  {repository,policy,findings}.py` (redaction, scope, finding
  lifecycle), `tests/unit/test_release.py` (report inventory only
  enumerates `ECA-T001..T016`, so POST-RC reports stay additive),
  `scripts/validate_schemas.py` + `docs/schemas/*.json`, existing
  `tests/fixtures/*` sibling roots (contamination source list),
  `reports/development/POST-RC-012-security-assessment.md`
  (report format precedent).

## Files Changed
- `src/emo_cyber_agent/evaluation/{__init__,errors,spec,cases,
  datasets,ground_truth,sut,oracle,metrics,gates,reproducibility,
  mutation,runner,report}.py` (layer complete this session)
- `src/emo_cyber_agent/mcp/delegate.py` (`permission_profile` in
  `call_audit` result — parity fix)
- `docs/schemas/evaluation-{case,dataset,run,report,metric}.
  schema.json` (5 NEW; 33 total)
- `tests/fixtures/evaluation/` (104 cases in 11 sections +
  `dataset.json`; `injection` → `hostile_input` rename; stale
  `injection/` directory removed)
- `tests/unit/test_evaluation_{spec,datasets,sut,
  oracles_metrics_gates,runner,e2e}.py` (6 files, 116 tests)
- (No Core, policy, finding, CLI-behavior, or MCP-protocol changes.)

## Invariant Impact
All 12 PASS: 1 read-only (layer and tests do no network/process/
fs writes; static-scanned), 2 untrusted content (fixture content is
data — scanned, never trusted), 3 evidence-gated (judgments come
from observations; missing data → `inconclusive`/`not computed`,
never a pass), 4 no destructive transition (no Finding/severity/trust
mutation anywhere in evaluation), 5 tool outputs as evidence
(SUT outputs become observations with provenance), 6 explicit
uncertainty (inconclusive verdicts, `not_computed` notes,
limitations on reports), 7 shared contracts (frozen models, closed
vocabularies, Core redaction/digest helpers reused), 8 external
provider choice (the SUT is an injected adapter behind a contract),
9 scanners authoritative (scanner output enters as data judged by
oracles), 10 human review (reports are rendered artifacts for
review — nothing is auto-promoted), 11 specialist worker (runner
owns scoring; no model suggestion path exists), 12 host delegates
(transports stay outside Core; only adapters touch CLI/MCP).

## Known Limitations
- The corpus is synthetic and internally authored: it measures
  contract conformance, not real-world attack prevalence; absolute
  scores should not be read as external benchmarks.
- `ADAPTER_PORTABILITY`/`TOOL_PORTABILITY` are only computed on
  parity runs; scripted runs report them as `not computed`.
- Parity compares a fixed projection (5 audit fields); drift in
  fields outside the projection is invisible by design.
- `RedactionOracle` patterns are conservative: outputs without
  quoting markers may pass (documented, tested).
- Thresholds come from the dataset manifest; there is no history
  to detect slow drift across versions yet.
- The scripted reference system is deterministic, so
  `DETERMINISM` proves reproducibility of the harness, not of any
  stochastic production component.

## Deferred Work
Stored multi-run history with trend and drift detection, external
or human-rater calibration, live model-based judges behind a
contract, per-section threshold policies, baseline versioning and
roll-forward comparison, report HTML rendering, CI badges from run
artifacts, and cross-dataset transfer evaluation — each in its
dedicated stage.

## Evidence
- `python3 -m pytest tests/unit/test_evaluation_spec.py
  tests/unit/test_evaluation_datasets.py
  tests/unit/test_evaluation_sut.py
  tests/unit/test_evaluation_oracles_metrics_gates.py
  tests/unit/test_evaluation_runner.py
  tests/unit/test_evaluation_e2e.py -o addopts="" -q` → 116 passed.
- Full suite → **1179 passed, 3 skipped**. Schemas 33/33 valid
  (`python3 scripts/validate_schemas.py`).
- `uvx ruff@0.11.13 check src/emo_cyber_agent/evaluation
  src/emo_cyber_agent/mcp/delegate.py
  tests/unit/test_evaluation_*.py` → All checks passed.
- Scripted corpus (100 non-parity cases, `repeat=3`) → status
  `completed`, `cases_failed 0`, all three gates `pass`, zero
  security disagreements, all 8 manifest thresholds met (coverage,
  precision, recall, redaction, policy, scope, injection at 1.0).
- Parity (4 cases through Python API + CLI + MCP) → all judgments
  supported, `TOOL_PORTABILITY = 1.0`, `ADAPTER_PORTABILITY = 1.0`.
- Contamination scan → 104 cases scanned, 0 hits across 40
  forbidden tokens; every fixture file validates against
  `evaluation-case.schema.json` with 0 errors.
- Adversarial systems (hostile, silent) fail their gates with
  recorded reasons; MCP and CLI adapters agree on projections.
- Files listed above.

## Status: PASS
