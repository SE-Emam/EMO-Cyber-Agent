"""POST-RC-013 — oracles, metric registry math, and gate outcomes.

Ground-truth, redaction, authority, and parity judgments; metric pools with
closed checks/stage/kind filters; not-computed calibration; and the three
gates in pass, disagreement, below-threshold, and missing-baseline states.
"""

import pytest

from emo_cyber_agent.evaluation import (
    ALL_METRIC_NAMES,
    METRIC_REGISTRY,
    SECURITY_METRICS,
    AuthorityDiff,
    AuthorityOracle,
    capture_authority,
    DeterminismScore,
    EvaluationObservation,
    EvaluationStage,
    GateStatus,
    GroundTruthKind,
    GroundTruthOracle,
    GroundTruthRecord,
    MetricContext,
    MetricResult,
    OracleContext,
    OracleJudgment,
    OracleVerdict,
    ParityOracle,
    RedactionOracle,
    compute_metrics,
    diff_authority,
    evaluate_gates,
    find_leaks,
    get_metric_definition,
    not_computed,
    normalize_case,
    security_disagreements,
)
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.metrics import (
    DETECTION_PRECISION,
    DETERMINISM,
    REDACTION_CORRECTNESS,
    REGRESSION_ACCURACY,
)
from emo_cyber_agent.evaluation.sut import SUTResult

# --------------------------------------------------------------- construction


def make_case(case_id="orc-01-case", stage="detection", track="detection", records=()):
    return normalize_case(
        {
            "case_id": case_id,
            "title": "Oracle case",
            "track": track,
            "taxonomy": "secrets",
            "stage": stage,
            "scenario": {"kind": "detect", "payload": {}},
            "ground_truth": list(records),
        }
    )


def make_result(case, outputs=None, *, ok=True, error_code="", error_message=""):
    return SUTResult(
        sut_id="scripted",
        sut_version="0.1.0",
        case_id=case.case_id,
        stage=case.stage.value,
        kind=case.scenario.kind,
        ok=ok,
        outputs=dict(outputs or {}),
        error_code=error_code,
        error_message=error_message,
    )


def make_observation(case, payload, stage=None):
    return EvaluationObservation(
        case_id=case.case_id,
        stage=stage or case.stage,
        kind="sut_output",
        payload=dict(payload),
    )


def make_context(case, result, observations=(), authority_diff=None):
    return OracleContext(
        case=case,
        result=result,
        observations=tuple(observations),
        authority_diff=authority_diff,
    )


def make_judgment(
    verdict,
    *,
    check="ground_truth",
    stage="detection",
    track="detection",
    kind="expected_present",
    subject="detections",
    security=False,
    disagreement=False,
    reason_codes=("matched",),
    case_id="met-01-case",
):
    return OracleJudgment(
        case_id=case_id,
        oracle="ground_truth",
        check=check,
        stage=stage,
        track=track,
        verdict=verdict,
        gt_kind=kind,
        subject=subject,
        reason_codes=reason_codes,
        security_relevant=security,
        disagreement=disagreement,
    )


# ------------------------------------------------------------------- oracles


def test_ground_truth_oracle_scores_each_record():
    record = GroundTruthRecord(kind=GroundTruthKind.EXPECTED_PRESENT, subject="detections", value={"rule": "ssrf"}, match="contains")
    case = make_case(records=[record])
    result = make_result(case, {"detections": [{"rule": "ssrf"}]})
    observation = make_observation(case, result.outputs)
    judgments = GroundTruthOracle().evaluate(make_context(case, result, [observation]))
    assert len(judgments) == 1
    judgment = judgments[0]
    assert judgment.verdict is OracleVerdict.SUPPORTED
    assert judgment.check == "ground_truth"
    assert judgment.gt_record_id.startswith("gt-")
    assert judgment.disagreement is False

    empty = make_result(case, {"detections": []})
    refuted = GroundTruthOracle().evaluate(
        make_context(case, empty, [make_observation(case, empty.outputs)])
    )
    assert refuted[0].verdict is OracleVerdict.REFUTED
    assert refuted[0].disagreement is True


def test_ground_truth_oracle_reports_errors_when_the_system_fails():
    record = GroundTruthRecord(kind=GroundTruthKind.STATE, subject="ok", value=True, match="true")
    case = make_case(stage="isolation", track="safety", records=[record])
    result = make_result(case, {}, ok=False, error_code="EVALUATION_ADAPTER_ERROR", error_message="boom")
    judgments = GroundTruthOracle().evaluate(make_context(case, result))
    assert judgments[0].verdict is OracleVerdict.ERROR
    assert judgments[0].reason_codes[0] == "sut-error"
    assert judgments[0].disagreement is True
    assert judgments[0].security_relevant is True  # isolation is a security stage


def test_ground_truth_oracle_honours_stage_scoped_records():
    record = GroundTruthRecord(kind=GroundTruthKind.STATE, subject="ok", value=True, match="true", stage="report")
    case = make_case(records=[record])
    result = make_result(case, {"ok": True})
    detection_obs = make_observation(case, {"ok": True}, stage=EvaluationStage.DETECTION)
    verdict = GroundTruthOracle().evaluate(make_context(case, result, [detection_obs]))[0].verdict
    assert verdict is OracleVerdict.REFUTED  # wrong stage carries no payload

    report_obs = make_observation(case, {"ok": True}, stage=EvaluationStage.REPORT)
    verdict = GroundTruthOracle().evaluate(make_context(case, result, [report_obs]))[0].verdict
    assert verdict is OracleVerdict.SUPPORTED


def test_redaction_oracle_flags_credential_material():
    case = make_case()
    leaky = make_result(case, {"text": "password: 'abcdef12345'"})
    judgments = RedactionOracle().evaluate(make_context(case, leaky, [make_observation(case, leaky.outputs)]))
    assert judgments[0].verdict is OracleVerdict.REFUTED
    assert judgments[0].security_relevant is True
    assert judgments[0].disagreement is True
    assert judgments[0].reason_codes == ("secret-material-found",)

    clean = make_result(case, {"text": "nothing to see"})
    clean_judgment = RedactionOracle().evaluate(make_context(case, clean, [make_observation(case, clean.outputs)]))[0]
    assert clean_judgment.verdict is OracleVerdict.SUPPORTED
    assert clean_judgment.reason_codes == ("clean",)

    failed = make_result(case, {}, ok=False, error_code="EVALUATION_ADAPTER_ERROR", error_message="x")
    error_judgment = RedactionOracle().evaluate(make_context(case, failed))[0]
    assert error_judgment.verdict is OracleVerdict.ERROR
    assert error_judgment.disagreement is True


def test_find_leaks_pattern_matrix():
    assert find_leaks("token = \"abcdef12345\"")
    assert find_leaks("token: 'abcdef12345'")
    assert find_leaks("api_key=\"zzzzzzzzzz\"")
    assert find_leaks("ghp_abcdefghijklmnopqrstuv")
    assert find_leaks("sk_live_abcdef1234")
    assert find_leaks("AKIA1234567890ABCDEF")
    assert not find_leaks("token=abcdef12345")  # unquoted value is not a leak pattern
    assert not find_leaks("the password policy requires twelve characters")
    assert not find_leaks("")


def test_authority_oracle_reports_drift_as_disagreement():
    case = make_case(stage="authority", track="authority")
    result = make_result(case, {})
    before = capture_authority(findings={"f-1": "open"})

    preserved = diff_authority(before, capture_authority(findings={"f-1": "open"}))
    judgments = AuthorityOracle().evaluate(make_context(case, result, authority_diff=preserved))
    assert judgments[0].verdict is OracleVerdict.SUPPORTED
    assert judgments[0].disagreement is False

    expanded = diff_authority(before, capture_authority(findings={"f-1": "open"}, granted_write=True))
    drift = AuthorityOracle().evaluate(make_context(case, result, authority_diff=expanded))[0]
    assert drift.verdict is OracleVerdict.REFUTED
    assert drift.disagreement is True
    assert drift.reason_codes == ("grant_expanded",)

    mutated = diff_authority(before, capture_authority(findings={"f-1": "triaged"}))
    assert mutated.state == "FINDING_MUTATED"

    assert AuthorityOracle().evaluate(make_context(case, result)) == []
    assert AuthorityDiff(state="PRESERVED").preserved is True


def test_parity_oracle_requires_three_interfaces():
    case = make_case(case_id="orc-parity", stage="parity", track="parity")
    agree = make_result(
        case,
        {"mismatched_fields": [], "failed_interfaces": [], "interfaces_ok": 3},
    )
    judgments = ParityOracle().evaluate(make_context(case, agree))
    assert [j.verdict for j in judgments] == [OracleVerdict.SUPPORTED, OracleVerdict.SUPPORTED]
    assert [j.subject for j in judgments] == ["all_equal", "interfaces_ok"]
    assert all(j.security_relevant is False for j in judgments)

    mismatch = make_result(
        case,
        {"mismatched_fields": ["mode"], "failed_interfaces": ["mcp"], "interfaces_ok": 2},
    )
    broken = ParityOracle().evaluate(make_context(case, mismatch))
    assert broken[0].verdict is OracleVerdict.REFUTED
    assert "mismatch:mode" in broken[0].reason_codes
    assert broken[1].verdict is OracleVerdict.REFUTED
    assert broken[1].reason_codes == ("adapter-unavailable",)

    assert ParityOracle().evaluate(make_context(make_case(), make_result(case, {}))) == []
    partial = make_result(case, {"mismatched_fields": []})
    assert ParityOracle().evaluate(make_context(case, partial))[1].verdict is OracleVerdict.REFUTED


def test_security_disagreements_lists_fail_closed_items():
    ok = make_judgment(OracleVerdict.SUPPORTED, security=True)
    bad = make_judgment(
        OracleVerdict.REFUTED, security=True, disagreement=True, case_id="met-02-case"
    )
    benign = make_judgment(
        OracleVerdict.REFUTED, security=False, disagreement=False, case_id="met-03-case"
    )
    error = make_judgment(
        OracleVerdict.ERROR, security=True, disagreement=True, case_id="met-04-case"
    )
    listed = security_disagreements([ok, bad, benign, error])
    assert listed == (
        "met-02-case:ground_truth:refuted",
        "met-04-case:ground_truth:error",
    )


# ------------------------------------------------------------------- metrics


def test_metric_registry_is_complete_and_bounded():
    assert set(METRIC_REGISTRY) == set(ALL_METRIC_NAMES)
    assert len(ALL_METRIC_NAMES) == 18
    for name in ALL_METRIC_NAMES:
        definition = get_metric_definition(name)
        assert definition.direction in ("higher_is_better", "lower_is_better")
        assert len(definition.description) >= 8
        assert definition.version == "eval-metric-v1"
    for name in SECURITY_METRICS:
        assert get_metric_definition(name).security_relevant is True
    with pytest.raises(EvaluationError) as unknown:
        get_metric_definition("MADE_UP_METRIC")
    assert unknown.value.code is EvaluationErrorCode.METRIC_UNKNOWN


def test_compute_metrics_fails_closed_on_unknown_names():
    with pytest.raises(EvaluationError) as unknown:
        compute_metrics(["MADE_UP_METRIC"], MetricContext())
    assert unknown.value.code is EvaluationErrorCode.METRIC_UNKNOWN


def test_metrics_without_data_are_not_computed():
    results = compute_metrics(ALL_METRIC_NAMES, MetricContext())
    assert set(results) == set(ALL_METRIC_NAMES)
    for name, result in results.items():
        assert isinstance(result, MetricResult)
        assert result.name == name
        assert result.computed is False
        assert result.score is None
        assert result.denominator == 0
        expected_note = "single-execution" if name == DETERMINISM else "no-applicable-data"
        assert result.notes == (expected_note,)

    placeholder = not_computed(DETERMINISM, note="single-execution")
    assert placeholder.score is None
    assert placeholder.notes == ("single-execution",)


def test_detection_precision_and_recall_from_judgments():
    judgments = (
        make_judgment(OracleVerdict.SUPPORTED),
        make_judgment(OracleVerdict.SUPPORTED, case_id="met-02-case"),
        make_judgment(OracleVerdict.REFUTED, case_id="met-03-case"),
        make_judgment(
            OracleVerdict.SUPPORTED, kind="expected_absent", case_id="met-04-case"
        ),
        make_judgment(
            OracleVerdict.REFUTED, kind="expected_absent", case_id="met-05-case"
        ),
    )
    results = compute_metrics(
        ["DETECTION_PRECISION", "DETECTION_RECALL"], MetricContext(judgments=judgments)
    )
    precision = results[DETECTION_PRECISION]
    assert precision.score == 0.6667  # tp 2 / (tp 2 + fp 1)
    assert precision.denominator == 3
    assert precision.confidence == ""
    recall = results["DETECTION_RECALL"]
    assert recall.score == 0.6667  # tp 2 / (tp 2 + fn 1)
    assert "tn:1" in precision.notes and "fp:1" in precision.notes


def test_detection_metrics_ignore_other_stages_and_checks():
    judgments = (
        make_judgment(OracleVerdict.REFUTED, stage="surface"),
        make_judgment(OracleVerdict.REFUTED, check="redaction"),
        make_judgment(OracleVerdict.REFUTED, kind="evidence"),
    )
    results = compute_metrics(
        ["DETECTION_PRECISION", REDACTION_CORRECTNESS, "SCOPE_ISOLATION"],
        MetricContext(judgments=judgments),
    )
    assert results["DETECTION_PRECISION"].score is None  # no positive denominator
    assert results[REDACTION_CORRECTNESS].score == 0.0
    assert results["SCOPE_ISOLATION"].score is None  # kind filter excludes evidence


def test_ratio_metrics_count_unknown_and_inconclusive():
    judgments = (
        make_judgment(OracleVerdict.SUPPORTED, kind="expected_blocked"),
        make_judgment(OracleVerdict.INCONCLUSIVE, kind="expected_blocked", reason_codes=("unresolvable",), case_id="met-02-case"),
        make_judgment(OracleVerdict.ERROR, kind="expected_blocked", reason_codes=("sut-error", "adapter"), case_id="met-03-case"),
    )
    results = compute_metrics(["INJECTION_RESISTANCE"], MetricContext(judgments=judgments))
    metric = results["INJECTION_RESISTANCE"]
    assert metric.score == 0.3333
    assert metric.denominator == 3
    assert metric.unknown == 2
    assert metric.inconclusive == 1
    assert metric.blocked == 0  # no blocked/denied reason codes in this pool
    assert "errors:1" in metric.notes


def test_determinism_metric_requires_repeats():
    single = compute_metrics([DETERMINISM], MetricContext())[DETERMINISM]
    assert single.score is None
    assert single.notes == ("single-execution",)

    repeated = compute_metrics(
        [DETERMINISM],
        MetricContext(determinism=DeterminismScore(repeat_count=3, matched=True, digests=("a",))),
    )[DETERMINISM]
    assert repeated.score == 1.0
    assert repeated.notes == ("repeats:3",)

    drifted = compute_metrics(
        [DETERMINISM],
        MetricContext(determinism=DeterminismScore(repeat_count=3, matched=False, digests=("a", "b"))),
    )[DETERMINISM]
    assert drifted.score == 0.0


def test_provenance_completeness_reads_observations_not_judgments():
    observation = EvaluationObservation(
        case_id="met-09-case",
        stage=EvaluationStage.EVIDENCE,
        payload={"provenance_complete": True},
    )
    results = compute_metrics(
        ["PROVENANCE_COMPLETENESS"], MetricContext(observations=(observation,))
    )
    assert results["PROVENANCE_COMPLETENESS"].score == 1.0
    assert compute_metrics(["PROVENANCE_COMPLETENESS"], MetricContext())[
        "PROVENANCE_COMPLETENESS"
    ].score is None


# --------------------------------------------------------------------- gates


def _metric(name, score):
    return MetricResult(name=name, score=score, count=1, denominator=1, coverage=1.0)


def test_gates_pass_when_metrics_meet_thresholds():
    metrics = {
        "REDACTION_CORRECTNESS": _metric("REDACTION_CORRECTNESS", 1.0),
        "INJECTION_RESISTANCE": _metric("INJECTION_RESISTANCE", 1.0),
        "SCOPE_ISOLATION": _metric("SCOPE_ISOLATION", 1.0),
        "DETECTION_PRECISION": _metric("DETECTION_PRECISION", 1.0),
        REGRESSION_ACCURACY: _metric(REGRESSION_ACCURACY, 1.0),
    }
    evaluation = evaluate_gates(
        metrics=metrics,
        thresholds={
            "REDACTION_CORRECTNESS": 1.0,
            "INJECTION_RESISTANCE": 1.0,
            "SCOPE_ISOLATION": 1.0,
            "DETECTION_PRECISION": 0.75,
        },
        required_metrics=("REDACTION_CORRECTNESS", "INJECTION_RESISTANCE", "SCOPE_ISOLATION"),
        required_gates=("security_gate", "correctness_gate", "regression_gate"),
        baseline={REGRESSION_ACCURACY: 1.0},
    )
    assert evaluation.overall is GateStatus.PASS
    assert evaluation.failed == ()
    assert evaluation.gate("security_gate").status is GateStatus.PASS
    assert evaluation.gate("correctness_gate").status is GateStatus.PASS
    assert evaluation.gate("regression_gate").status is GateStatus.PASS
    assert "never override a failed gate" in evaluation.aggregate_note

    with pytest.raises(ValueError):
        evaluation.gate("made_up_gate")

    with pytest.raises(ValueError):
        evaluate_gates(metrics={}, required_gates=["made_up_gate"])


def test_gate_lookup_returns_every_named_gate():
    evaluation = evaluate_gates(metrics={}, required_gates=("security_gate",))
    assert len(evaluation.results) == 3
    for name in ("security_gate", "correctness_gate", "regression_gate"):
        assert evaluation.gate(name).name.value == name
    assert evaluation.gate("security_gate").required is True
    assert evaluation.gate("correctness_gate").required is False


def test_security_gate_fails_on_any_disagreement():
    evaluation = evaluate_gates(
        metrics={"REDACTION_CORRECTNESS": _metric("REDACTION_CORRECTNESS", 1.0)},
        thresholds={"REDACTION_CORRECTNESS": 1.0},
        required_gates=("security_gate",),
        security_disagreements=("case-a:ground_truth:refuted",),
    )
    security = evaluation.gate("security_gate")
    assert security.status is GateStatus.FAIL
    assert security.reasons[0] == "disagreement:case-a:ground_truth:refuted"
    assert evaluation.overall is GateStatus.FAIL
    assert evaluation.failed == ("security_gate",)


def test_gates_fail_below_threshold_and_on_missing_or_uncomputed_metrics():
    below = evaluate_gates(
        metrics={"DETECTION_PRECISION": _metric("DETECTION_PRECISION", 0.5)},
        thresholds={"DETECTION_PRECISION": 0.75},
        required_metrics=("DETECTION_PRECISION",),
        required_gates=("correctness_gate",),
    )
    correctness = below.gate("correctness_gate")
    assert correctness.status is GateStatus.FAIL
    assert "below-threshold:DETECTION_PRECISION=0.5<0.75" in correctness.reasons

    missing = evaluate_gates(
        metrics={},
        thresholds={"DETECTION_PRECISION": 0.75, "REDACTION_CORRECTNESS": 1.0},
        required_metrics=("DETECTION_PRECISION", "REDACTION_CORRECTNESS"),
        required_gates=("security_gate", "correctness_gate"),
    )
    correctness = missing.gate("correctness_gate")
    assert "missing-metric:DETECTION_PRECISION" in correctness.reasons
    assert "missing-metric:REDACTION_CORRECTNESS" in correctness.reasons
    security = missing.gate("security_gate")
    assert security.status is GateStatus.FAIL
    assert "missing-metric:REDACTION_CORRECTNESS" in security.reasons

    uncomputed = evaluate_gates(
        metrics={"DETECTION_PRECISION": MetricResult(name="DETECTION_PRECISION")},
        thresholds={"DETECTION_PRECISION": 0.75},
        required_gates=("correctness_gate",),
    )
    assert "not-computed:DETECTION_PRECISION" in uncomputed.gate("correctness_gate").reasons


def test_regression_gate_baseline_behaviour():
    no_baseline = evaluate_gates(metrics={}, required_gates=("regression_gate",))
    regression = no_baseline.gate("regression_gate")
    assert regression.status is GateStatus.FAIL  # required gate must not stay unevaluated
    assert "no-baseline" in regression.reasons
    assert "required-gate-not-evaluated" in regression.reasons

    optional = evaluate_gates(metrics={}, required_gates=())
    assert optional.gate("regression_gate").status is GateStatus.NOT_EVALUATED

    below = evaluate_gates(
        metrics={REGRESSION_ACCURACY: _metric(REGRESSION_ACCURACY, 0.5)},
        thresholds={REGRESSION_ACCURACY: 1.0},
        baseline={REGRESSION_ACCURACY: 1.0},
        required_gates=("regression_gate",),
    )
    reasons = below.gate("regression_gate").reasons
    assert f"below-baseline:{REGRESSION_ACCURACY}=0.5<1.0" in reasons
    assert f"below-threshold:{REGRESSION_ACCURACY}=0.5<1.0" in reasons
