"""Contract tests for the bounded recovery layer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.recovery import (
    MAX_RECOVERY_ATTEMPTS,
    NEVER_RETRY,
    Checkpoint,
    FailureClassification,
    RecoveryAction,
    RecoveryManager,
    RecoveryRequest,
    ScopeViolationError,
    build_report,
    capture,
    classify,
    classify_or_unknown,
    decide,
    describe,
    policy_table,
    restore,
)
from emo_cyber_agent.recovery.errors import (
    CheckpointError,
    ClassificationError,
    RecoveryError,
)
from emo_cyber_agent.recovery.reporting import RecoveryAttemptRecord


EXPECTED_MAPPING = {
    FailureClassification.TRANSIENT: (RecoveryAction.RETRY, 3, True),
    FailureClassification.STALE_CONTEXT: (RecoveryAction.REFRESH_SNAPSHOT, 1, True),
    FailureClassification.PROVIDER_UNAVAILABLE: (RecoveryAction.RELOAD_PROVIDER, 2, True),
    FailureClassification.MALFORMED_OUTPUT: (RecoveryAction.REVALIDATE, 2, True),
    FailureClassification.RESOURCE_EXHAUSTED: (RecoveryAction.RELOAD_RESOURCE, 1, True),
    FailureClassification.DEPENDENCY_MISMATCH: (RecoveryAction.RECOMPUTE, 1, True),
    FailureClassification.SCOPE_MISMATCH: (RecoveryAction.QUARANTINE, 0, False),
    FailureClassification.POLICY_DENIED: (RecoveryAction.FAIL_CLOSED, 0, False),
    FailureClassification.INTEGRITY_FAILURE: (RecoveryAction.FAIL_CLOSED, 0, False),
    FailureClassification.UNKNOWN: (RecoveryAction.FAIL_CLOSED, 0, False),
}


class TestClassification:
    def test_all_ten_categories_exist(self):
        assert len(FailureClassification) == 10
        assert set(EXPECTED_MAPPING) == set(FailureClassification)

    @pytest.mark.parametrize("classification", list(FailureClassification))
    def test_classify_roundtrip_enum_and_string(self, classification):
        assert classify(classification) is classification
        assert classify(classification.value) is classification
        assert classify(classification.value.lower()) is classification

    def test_classify_unknown_token_raises(self):
        with pytest.raises(ClassificationError):
            classify("NOT_A_REAL_FAILURE")

    def test_classify_or_unknown_maps_garbage_to_unknown(self):
        assert classify_or_unknown("NOT_A_REAL_FAILURE") is FailureClassification.UNKNOWN
        assert classify_or_unknown(None) is FailureClassification.UNKNOWN

    @pytest.mark.parametrize("classification", list(FailureClassification))
    def test_policy_mapping_all_ten(self, classification):
        expected_action, expected_attempts, expected_retryable = EXPECTED_MAPPING[classification]
        decision = decide(classification)
        assert decision.action is expected_action
        assert decision.max_attempts == expected_attempts
        assert decision.retryable is expected_retryable

    def test_decide_rejects_non_member(self):
        with pytest.raises(ClassificationError):
            decide("TRANSIENT")  # type: ignore[arg-type]

    def test_policy_table_covers_all_ten(self):
        table = policy_table()
        assert len(table) == 10
        for classification, (action, attempts, retryable) in EXPECTED_MAPPING.items():
            row = table[classification.value]
            assert row == {
                "action": action.value,
                "max_attempts": attempts,
                "retryable": retryable,
            }


class TestFailClosed:
    @pytest.mark.parametrize(
        "classification", [FailureClassification.POLICY_DENIED, FailureClassification.INTEGRITY_FAILURE]
    )
    def test_deny_and_integrity_always_fail_closed(self, classification):
        decision = decide(classification)
        assert decision.action is RecoveryAction.FAIL_CLOSED
        assert decision.max_attempts == 0
        assert decision.retryable is False
        assert classification in NEVER_RETRY

    @pytest.mark.parametrize(
        "classification", [FailureClassification.POLICY_DENIED, FailureClassification.INTEGRITY_FAILURE]
    )
    def test_manager_never_executes_for_fail_closed(self, classification):
        calls: list = []

        def executor(action, ctx):
            calls.append((action, ctx))
            return True  # would succeed if called; must not be called

        mgr = RecoveryManager(executor=executor)
        report = mgr.recover(RecoveryRequest(audit_id="audit-1", failure=classification))
        assert report.outcome == "FAILED_CLOSED"
        assert report.attempts_made == 0
        assert calls == []

    def test_scope_mismatch_quarantines_without_attempts(self):
        calls: list = []
        mgr = RecoveryManager(executor=lambda a, c: calls.append(a) or True)
        report = mgr.recover(
            RecoveryRequest(audit_id="audit-1", failure=FailureClassification.SCOPE_MISMATCH)
        )
        assert report.outcome == "QUARANTINED"
        assert report.action == RecoveryAction.QUARANTINE.value
        assert report.attempts_made == 0
        assert calls == []


class TestBoundedRetry:
    def test_max_attempts_constant_is_bounded(self):
        assert MAX_RECOVERY_ATTEMPTS == 3

    def test_always_failing_executor_stops_at_budget(self):
        calls: list = []
        mgr = RecoveryManager(executor=lambda a, c: calls.append(a) or False)
        report = mgr.recover(
            RecoveryRequest(audit_id="audit-1", failure=FailureClassification.TRANSIENT)
        )
        assert report.outcome == "BUDGET_EXHAUSTED"
        assert report.attempts_made == MAX_RECOVERY_ATTEMPTS
        assert len(calls) == MAX_RECOVERY_ATTEMPTS

    def test_eventual_success_recovers_within_budget(self):
        calls: list = []

        def executor(action, ctx):
            calls.append(action)
            return len(calls) >= 3

        mgr = RecoveryManager(executor=executor)
        report = mgr.recover(
            RecoveryRequest(audit_id="audit-1", failure=FailureClassification.TRANSIENT)
        )
        assert report.outcome == "RECOVERED"
        assert report.attempts_made == 3
        assert len(calls) == 3

    def test_single_attempt_budget_for_stale_context(self):
        calls: list = []
        mgr = RecoveryManager(executor=lambda a, c: calls.append(a) or False)
        report = mgr.recover(
            RecoveryRequest(audit_id="audit-1", failure=FailureClassification.STALE_CONTEXT)
        )
        assert report.attempts_made == 1
        assert report.outcome == "BUDGET_EXHAUSTED"
        assert len(calls) == 1

    def test_no_infinite_loop_guarantee(self):
        # Every retryable decision's budget is <= the global max.
        for classification in FailureClassification:
            decision = decide(classification)
            assert decision.max_attempts <= MAX_RECOVERY_ATTEMPTS


class TestCheckpoint:
    def test_roundtrip(self):
        handle, stored = capture("audit-1", "pre-plan", b'{"phase": 1}')
        assert isinstance(handle, Checkpoint)
        assert handle.audit_id == "audit-1"
        out = restore(handle, stored, audit_id="audit-1")
        assert out == b'{"phase": 1}'

    def test_payload_is_copied_not_aliased(self):
        buf = bytearray(b"abc")
        _handle, stored = capture("audit-1", "snap", buf)
        buf[:] = b"XXX"
        assert stored == b"abc"

    def test_cross_audit_restore_rejected(self):
        handle, stored = capture("audit-1", "snap", b"data")
        with pytest.raises(ScopeViolationError):
            restore(handle, stored, audit_id="audit-2")

    def test_tampered_payload_rejected(self):
        handle, _stored = capture("audit-1", "snap", b"data")
        with pytest.raises(CheckpointError):
            restore(handle, b"tampered", audit_id="audit-1")

    def test_bad_inputs_rejected(self):
        with pytest.raises(CheckpointError):
            capture("", "snap", b"data")
        with pytest.raises(CheckpointError):
            capture("audit-1", "", b"data")
        with pytest.raises(CheckpointError):
            capture("audit-1", "snap", "not-bytes")  # type: ignore[arg-type]

    def test_describe_is_data_only(self):
        handle, _ = capture("audit-1", "snap", b"data")
        summary = describe(handle)
        assert summary["audit_id"] == "audit-1"
        assert summary["label"] == "snap"
        assert "data" not in str(summary.get("payload", ""))


class TestCrossAuditRejection:
    def test_mismatched_checkpoint_audit_rejected(self):
        mgr = RecoveryManager()
        with pytest.raises(ScopeViolationError):
            mgr.recover(
                RecoveryRequest(
                    audit_id="audit-1",
                    failure=FailureClassification.TRANSIENT,
                    checkpoint_audit_id="audit-2",
                )
            )

    def test_matching_checkpoint_audit_allowed(self):
        mgr = RecoveryManager(executor=lambda a, c: True)
        report = mgr.recover(
            RecoveryRequest(
                audit_id="audit-1",
                failure=FailureClassification.TRANSIENT,
                checkpoint_audit_id="audit-1",
            )
        )
        assert report.outcome == "RECOVERED"


class TestNoMutation:
    def test_context_not_mutated_by_recovery(self):
        original = {
            "findings": [{"id": "F1", "severity": "HIGH"}],
            "evidence": [{"id": "E1", "hash": "abc"}],
            "scope": ["repo-a"],
        }
        snapshot = {
            "findings": [dict(f) for f in original["findings"]],
            "evidence": [dict(e) for e in original["evidence"]],
            "scope": list(original["scope"]),
        }
        mgr = RecoveryManager(executor=lambda a, c: True)
        mgr.recover(
            RecoveryRequest(
                audit_id="audit-1",
                failure=FailureClassification.TRANSIENT,
                context=original,
            )
        )
        assert original == snapshot

    def test_findings_evidence_severity_in_forbidden_set(self):
        forbidden = RecoveryManager.forbidden_mutation_targets()
        for key in ("findings", "evidence", "severity", "policy_engine", "scope"):
            assert key in forbidden

    def test_executor_cannot_reach_caller_mapping(self):
        seen: list = []

        def executor(action, ctx):
            ctx["injected"] = True  # mutate only the manager-owned copy
            seen.append(dict(ctx))
            return True

        caller_ctx = {"findings": []}
        mgr = RecoveryManager(executor=executor)
        mgr.recover(
            RecoveryRequest(
                audit_id="audit-1", failure=FailureClassification.TRANSIENT, context=caller_ctx
            )
        )
        assert caller_ctx == {"findings": []}
        assert seen and seen[0].get("injected") is True


class TestReporting:
    def test_report_is_data_only(self):
        report = build_report(
            audit_id="audit-1",
            classification=FailureClassification.TRANSIENT,
            action=RecoveryAction.RETRY,
            outcome="RECOVERED",
            records=[RecoveryAttemptRecord(attempt=1, action="RETRY", succeeded=True)],
        )
        payload = report.to_dict()
        assert payload["type"] == "recovery_report"
        assert payload["classification"] == "TRANSIENT"
        assert payload["outcome"] == "RECOVERED"
        assert payload["attempts_made"] == 1

    def test_invalid_outcome_rejected(self):
        with pytest.raises(RecoveryError):
            build_report(
                audit_id="audit-1",
                classification=FailureClassification.UNKNOWN,
                action=RecoveryAction.FAIL_CLOSED,
                outcome="RETRY_FOREVER",
            )
