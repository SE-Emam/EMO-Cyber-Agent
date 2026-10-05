"""POST-RC-013 — evaluation spec, ground truth comparator, blind cases.

Closed vocabularies, digest stability, authority snapshots, subject
resolution, the full comparison-match matrix, kind-aware ground-truth
verdicts, and the blind projection that must never leak expected values.
"""

import pytest

from emo_cyber_agent.evaluation import (
    ALL_STAGES,
    PIPELINE_STAGES,
    PROTOCOL_STAGES,
    SECURITY_GROUND_TRUTH_KINDS,
    AuthoritySnapshot,
    BlindEvaluationCase,
    ComparisonMatch,
    EvaluationCase,
    EvaluationEvent,
    EvaluationObservation,
    EvaluationStage,
    EvaluationTaxonomy,
    EvaluationTrack,
    GateName,
    GateStatus,
    GroundTruthKind,
    GroundTruthRecord,
    OracleVerdict,
    RunStatus,
    capture_authority,
    compare_value,
    diff_authority,
    evaluate_gates,
    evaluation_digest,
    judge_record,
    normalize_case,
    blind_case,
    resolve_subject,
)
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.ground_truth import (
    is_security_relevant,
    judge_or_reject,
    record_identity,
)

# --------------------------------------------------------------------- vocab


def test_pipeline_and_protocol_stages_are_disjoint_and_complete():
    assert set(PIPELINE_STAGES).isdisjoint(PROTOCOL_STAGES)
    assert ALL_STAGES == PIPELINE_STAGES + PROTOCOL_STAGES
    assert len(set(ALL_STAGES)) == len(ALL_STAGES) == len(list(EvaluationStage))
    assert set(ALL_STAGES) == {stage.value for stage in EvaluationStage}


def test_tracks_taxonomies_and_verdicts_are_closed():
    assert len(list(EvaluationTrack)) == 8
    assert len(list(EvaluationTaxonomy)) == 16
    assert "advisory_regression" in {t.value for t in EvaluationTaxonomy}
    assert {g.value for g in GateName} == {"security_gate", "correctness_gate", "regression_gate"}
    assert {s.value for s in GateStatus} >= {"pass", "fail", "partial"}
    assert {r.value for r in RunStatus} == {"completed", "partial", "failed"}
    assert {v.value for v in OracleVerdict} == {
        "supported",
        "refuted",
        "inconclusive",
        "error",
        "not_applicable",
    }


def test_security_ground_truth_kinds_are_a_subset_and_security_stages_declared():
    kinds = {k.value for k in GroundTruthKind}
    assert SECURITY_GROUND_TRUTH_KINDS <= kinds
    assert GroundTruthKind.EXPECTED_BLOCKED.value in SECURITY_GROUND_TRUTH_KINDS
    assert GroundTruthKind.EXPECTED_PRESERVED.value in SECURITY_GROUND_TRUTH_KINDS
    for kind in SECURITY_GROUND_TRUTH_KINDS:
        record = GroundTruthRecord(kind=GroundTruthKind(kind), subject="x", value=1)
        assert record.security_relevant is True
        assert is_security_relevant(record, stage="") is True
    plain = GroundTruthRecord(kind=GroundTruthKind.EXPECTED_PRESENT, subject="x", value=1)
    assert plain.security_relevant is False
    assert is_security_relevant(plain, stage="isolation") is True


def test_all_comparison_matches_are_covered():
    assert {m.value for m in ComparisonMatch} == {
        "exact",
        "contains",
        "not_contains",
        "superset",
        "subset",
        "set_equals",
        "absent",
        "nonempty",
        "true",
    }


# ------------------------------------------------------------------- digests


def test_evaluation_digest_is_order_independent_and_value_sensitive():
    assert evaluation_digest({"a": 1, "b": 2}) == evaluation_digest({"b": 2, "a": 1})
    assert evaluation_digest({"a": 1}) != evaluation_digest({"a": 2})
    assert evaluation_digest({"a": 1}) != evaluation_digest({"a": "1"})


def test_event_and_observation_identity_ignores_volatile_ids():
    first = EvaluationEvent(case_id="c-1", stage=EvaluationStage.EVIDENCE, kind="observed")
    second = EvaluationEvent(case_id="c-1", stage=EvaluationStage.EVIDENCE, kind="observed")
    assert first.event_id != second.event_id
    assert first.identity_digest == second.identity_digest

    changed = EvaluationEvent(
        case_id="c-1", stage=EvaluationStage.EVIDENCE, kind="observed", payload={"k": 1}
    )
    assert changed.identity_digest != first.identity_digest

    obs_a = EvaluationObservation(case_id="c-1", stage=EvaluationStage.REPORT, payload={"ok": True})
    obs_b = EvaluationObservation(case_id="c-1", stage=EvaluationStage.REPORT, payload={"ok": True})
    assert obs_a.observation_id != obs_b.observation_id
    assert obs_a.identity_digest == obs_b.identity_digest


def test_authority_snapshot_digest_ignores_capture_time():
    a = capture_authority(findings={"f-1": "open"})
    b = capture_authority(findings={"f-1": "open"})
    assert a.captured_at != b.captured_at or a.identity_digest == b.identity_digest
    assert a.identity_digest == b.identity_digest
    assert a.grants == {"read": True, "write": False, "network": False, "restricted": False}


def test_authority_diff_states_and_closed_grant_keys():
    before = capture_authority(findings={"f-1": "open"})
    assert diff_authority(before, capture_authority(findings={"f-1": "open"})).preserved

    added = diff_authority(before, capture_authority(findings={"f-1": "open", "f-2": "open"}))
    assert added.state == "FINDING_MUTATED"
    assert added.finding_additions == ("f-2",)
    assert not added.preserved

    granted = diff_authority(
        before, capture_authority(findings={"f-1": "open"}, granted_write=True)
    )
    assert granted.state == "GRANT_EXPANDED"
    assert granted.grant_expansions == ("write",)

    status = diff_authority(
        before, capture_authority(findings={"f-1": "triaged"})
    )
    assert status.state == "FINDING_MUTATED"
    assert status.status_changes == ("f-1",)

    with pytest.raises(Exception) as exc:
        AuthoritySnapshot(grants={"root": True})
    assert "root" in str(exc.value)


# ------------------------------------------------------- subject & comparison


def test_resolve_subject_paths_indices_and_merge():
    payloads = [{"a": {"b": [{"c": 1}]}}, {"z": 9}]
    assert resolve_subject(payloads, "a.b[0].c") == (True, 1)
    assert resolve_subject(payloads, "a.b.0.c") == (True, 1)
    assert resolve_subject(payloads, "z") == (True, 9)
    assert resolve_subject(payloads, "missing.path") == (False, None)
    assert resolve_subject([], "a") == (False, None)
    found, merged = resolve_subject(payloads, "")
    assert found is True
    assert merged == {"a": {"b": [{"c": 1}]}, "z": 9}


def test_contains_matches_dict_inside_list():
    payload = [{"rule": "secret_literal", "severity": "high"}]
    assert compare_value(payload, {"rule": "secret_literal"}, ComparisonMatch.CONTAINS) is True
    assert compare_value(payload, {"rule": "ssrf"}, ComparisonMatch.CONTAINS) is False
    assert compare_value(payload, ["secret_literal"], ComparisonMatch.CONTAINS) is False
    assert compare_value(payload, {"rule": "ssrf"}, ComparisonMatch.NOT_CONTAINS) is True


@pytest.mark.parametrize(
    ("match", "actual", "expected", "want"),
    [
        (ComparisonMatch.EXACT, 3, 3, True),
        (ComparisonMatch.EXACT, 3, 4, False),
        (ComparisonMatch.EXACT, True, True, True),
        (ComparisonMatch.CONTAINS, "token=abc12345", "abc", True),
        (ComparisonMatch.NOT_CONTAINS, "clean text", "abc", True),
        (ComparisonMatch.SUPERSET, ["a", "b"], ["a"], True),
        (ComparisonMatch.SUPERSET, ["a"], ["a", "b"], False),
        (ComparisonMatch.SUBSET, ["a"], ["a", "b"], True),
        (ComparisonMatch.SET_EQUALS, ["b", "a"], ["a", "b"], True),
        (ComparisonMatch.ABSENT, None, None, True),
        (ComparisonMatch.ABSENT, "", "", True),
        (ComparisonMatch.ABSENT, [], None, True),
        (ComparisonMatch.ABSENT, ["x"], None, False),
        (ComparisonMatch.NONEMPTY, ["x"], None, True),
        (ComparisonMatch.NONEMPTY, [], None, False),
        (ComparisonMatch.TRUE, True, None, True),
        (ComparisonMatch.TRUE, False, None, False),
        (ComparisonMatch.EXACT, None, 1, None),
        (ComparisonMatch.CONTAINS, None, "x", None),
    ],
)
def test_compare_value_matrix(match, actual, expected, want):
    assert compare_value(actual, expected, match) is want


# ------------------------------------------------------------- judging rules


def _record(kind, subject="", value=None, match=ComparisonMatch.EXACT, **kw):
    return GroundTruthRecord(kind=kind, subject=subject, value=value, match=match, **kw)


def test_expected_absent_inverts_the_observed_shape():
    record = _record(GroundTruthKind.EXPECTED_ABSENT, "detections", {"rule": "sql_injection"}, ComparisonMatch.CONTAINS)
    assert judge_record(record, [{"detections": [{"rule": "sql_injection"}]}]) is OracleVerdict.REFUTED
    assert judge_record(record, [{"detections": [{"rule": "ssrf"}]}]) is OracleVerdict.SUPPORTED
    assert judge_record(record, [{"other": 1}]) is OracleVerdict.SUPPORTED


def test_expected_present_and_state_missing_subject():
    present = _record(GroundTruthKind.EXPECTED_PRESENT, "detections", {"rule": "ssrf"}, ComparisonMatch.CONTAINS)
    assert judge_record(present, [{"detections": [{"rule": "ssrf"}]}]) is OracleVerdict.SUPPORTED
    assert judge_record(present, [{"detections": []}]) is OracleVerdict.REFUTED
    assert judge_record(present, [{}]) is OracleVerdict.REFUTED

    state = _record(GroundTruthKind.STATE, "scope_size", 3)
    assert judge_record(state, [{"scope_size": 3}]) is OracleVerdict.SUPPORTED
    assert judge_record(state, [{}]) is OracleVerdict.REFUTED


def test_unknown_and_inconclusive_score_the_uncertainty_contract():
    unknown = _record(GroundTruthKind.UNKNOWN, "status")
    assert judge_record(unknown, [{"status": "unknown"}]) is OracleVerdict.SUPPORTED
    assert judge_record(unknown, [{}]) is OracleVerdict.SUPPORTED
    assert judge_record(unknown, [{"status": "confirmed"}]) is OracleVerdict.REFUTED

    inconclusive = _record(GroundTruthKind.INCONCLUSIVE, "confidence")
    assert judge_record(inconclusive, [{"confidence": "inconclusive"}]) is OracleVerdict.SUPPORTED
    assert judge_record(inconclusive, [{"confidence": "high"}]) is OracleVerdict.REFUTED


def test_unresolvable_comparison_is_inconclusive():
    record = _record(GroundTruthKind.EXPECTED_PRESENT, "count", 5)
    assert judge_record(record, [{"count": None}]) is OracleVerdict.INCONCLUSIVE


def test_expected_blocked_and_isolated_kinds():
    blocked = _record(GroundTruthKind.EXPECTED_BLOCKED, "accepted_instructions", False)
    assert judge_record(blocked, [{"accepted_instructions": False}]) is OracleVerdict.SUPPORTED
    assert judge_record(blocked, [{"accepted_instructions": True}]) is OracleVerdict.REFUTED

    inert = _record(GroundTruthKind.EXPECTED_INERT, "inert", True, ComparisonMatch.TRUE)
    assert judge_record(inert, [{"inert": True}]) is OracleVerdict.SUPPORTED
    assert judge_record(inert, [{"inert": False}]) is OracleVerdict.REFUTED


def test_judge_or_reject_refuses_double_negation_and_empty_records():
    records = judge_or_reject(
        [_record(GroundTruthKind.EXPECTED_PRESENT, "x", 1)]
    )
    assert len(records) == 1
    assert records[0].record_id.startswith("gt-")
    assert record_identity(records[0]) == records[0].record_id

    with pytest.raises(EvaluationError) as absent:
        judge_or_reject(
            [_record(GroundTruthKind.EXPECTED_ABSENT, "detections", {"rule": "x"}, ComparisonMatch.ABSENT)]
        )
    assert absent.value.code is EvaluationErrorCode.ORACLE_REJECTED

    with pytest.raises(EvaluationError) as negated:
        judge_or_reject(
            [_record(GroundTruthKind.EXPECTED_ABSENT, "x", "y", ComparisonMatch.NOT_CONTAINS)]
        )
    assert negated.value.code is EvaluationErrorCode.ORACLE_REJECTED

    with pytest.raises(EvaluationError) as empty:
        judge_or_reject([_record(GroundTruthKind.STATE)])
    assert empty.value.code is EvaluationErrorCode.ORACLE_REJECTED


# ----------------------------------------------------------------- blind case


def _case_payload(**overrides):
    payload = {
        "case_id": "spec-01-basic",
        "title": "Spec case",
        "track": "detection",
        "taxonomy": "secrets",
        "stage": "detection",
        "scenario": {"kind": "detect", "payload": {"text": "token=abcdef123456"}},
        "ground_truth": [
            {"kind": "expected_present", "subject": "detections", "value": {"rule": "secret_literal"}, "match": "contains"}
        ],
    }
    payload.update(overrides)
    return payload


def test_normalize_case_round_trip_and_identity():
    case = normalize_case(_case_payload())
    assert isinstance(case, EvaluationCase)
    assert case.ground_truth[0].record_id.startswith("gt-")
    assert case.identity_digest == normalize_case(_case_payload()).identity_digest

    relabelled = normalize_case(_case_payload(ground_truth=[]))
    assert relabelled.identity_digest != case.identity_digest


def test_blind_projection_hides_ground_truth():
    case = normalize_case(_case_payload())
    blind = blind_case(case)
    assert isinstance(blind, BlindEvaluationCase)
    assert not hasattr(blind, "ground_truth")
    assert blind.scenario.kind == "detect"
    assert blind.case_id == case.case_id

    with pytest.raises(EvaluationError) as leak:
        blind_case(_case_payload())
    assert leak.value.code is EvaluationErrorCode.BLIND_ACCESS_DENIED

    with pytest.raises(EvaluationError) as labelled:
        blind_case({"case_id": "x-1", "title": "t", "label": "positive"})
    assert labelled.value.code is EvaluationErrorCode.BLIND_ACCESS_DENIED


def test_case_shape_rules_and_invalid_cases():
    with pytest.raises(EvaluationError) as bad_id:
        normalize_case(_case_payload(case_id="Bad Case ID"))
    assert bad_id.value.code is EvaluationErrorCode.INVALID_CASE

    with pytest.raises(EvaluationError) as holdout:
        normalize_case(_case_payload(split="holdout", visibility="public"))
    assert holdout.value.code is EvaluationErrorCode.INVALID_CASE

    with pytest.raises(EvaluationError) as slug:
        normalize_case(_case_payload(scenario={"kind": "not a slug", "payload": {}}))
    assert slug.value.code is EvaluationErrorCode.INVALID_CASE

    with pytest.raises(EvaluationError) as unknown:
        normalize_case(_case_payload(track="made_up"))
    assert unknown.value.code is EvaluationErrorCode.INVALID_CASE

    with pytest.raises(EvaluationError) as forbidden:
        normalize_case(_case_payload(extra_field=1))
    assert forbidden.value.code is EvaluationErrorCode.INVALID_CASE


def test_holdout_split_accepts_holdout_visibility():
    case = normalize_case(_case_payload(split="holdout", visibility="holdout"))
    assert case.split.value == "holdout"
    assert case.blind().visibility.value == "holdout"


def test_evaluate_gates_unknown_gate_name_fails_closed():
    with pytest.raises(ValueError):
        evaluate_gates(metrics={}, required_gates=["made_up_gate"])
