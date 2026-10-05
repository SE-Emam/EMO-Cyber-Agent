"""Progress bridge tests — POST-T018 (Agent 6B scope only).

Covers vocabulary mapping for all SubagentLifecycle states, advisory-only
markers, terminal percents, reuse of ProgressState/ProgressReporter (no
second event system), and no decision leakage (no capability/auth fields,
no security-state decisions from progress).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.progress.events import ProgressEvent, ProgressEventType
from emo_cyber_agent.progress.reporter import ProgressReporter
from emo_cyber_agent.progress.state import ProgressState
from emo_cyber_agent.subagent.progress_bridge import (
    DELEGATION_PHASES,
    LIFECYCLE_TO_PROGRESS_PHASE,
    TERMINAL_PROGRESS_PHASES,
    bridge,
    delegation_phases,
    progress_state_for,
)
from emo_cyber_agent.subagent.session import SubagentLifecycle, SubagentSession

AUDIT = "audit-001"
PROJECT = "project-001"
SNAPSHOT = "snap-001"
HOST = "host-alpha"

EXPECTED_VOCABULARY = (
    "DELEGATED",
    "INITIALIZING",
    "COLLECTING",
    "ANALYZING",
    "VERIFYING",
    "REPORTING",
    "RECOVERING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
)

# Lifecycle -> (progress phase, message code, event type).
EXPECTED_MAPPING: dict[SubagentLifecycle, tuple[str, str, ProgressEventType]] = {
    SubagentLifecycle.STARTING: (
        "DELEGATED",
        "SUBAGENT_DELEGATED_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.READY: (
        "INITIALIZING",
        "SUBAGENT_INITIALIZING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.RUNNING: (
        "COLLECTING",
        "SUBAGENT_COLLECTING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.VERIFYING: (
        "VERIFYING",
        "SUBAGENT_VERIFYING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.REPORTING: (
        "REPORTING",
        "SUBAGENT_REPORTING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.RECOVERING: (
        "RECOVERING",
        "SUBAGENT_RECOVERING_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.COMPLETED: (
        "COMPLETED",
        "SUBAGENT_COMPLETED_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.FAILED: (
        "FAILED",
        "SUBAGENT_FAILED_ADVISORY",
        ProgressEventType.ERROR,
    ),
    SubagentLifecycle.CANCELLED: (
        "CANCELLED",
        "SUBAGENT_CANCELLED_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
    SubagentLifecycle.QUARANTINED: (
        "FAILED",
        "SUBAGENT_QUARANTINED_ADVISORY",
        ProgressEventType.ERROR,
    ),
    SubagentLifecycle.UNAVAILABLE: (
        "RECOVERING",
        "SUBAGENT_UNAVAILABLE_ADVISORY",
        ProgressEventType.PROGRESS,
    ),
}

EXPECTED_EVENT_KEYS = frozenset(
    {
        "run_id",
        "audit_id",
        "phase",
        "phase_index",
        "phase_count",
        "completed",
        "total",
        "percent",
        "status",
        "message_code",
        "event_type",
        "timestamp",
    }
)

FORBIDDEN_SUBSTRINGS = (
    "capab",
    "auth",
    "permit",
    "allow",
    "deny",
    "trust",
    "quarantine",
    "grant",
    "role",
    "scope",
    "secret",
    "clearance",
)


def _session(**over) -> SubagentSession:
    base = dict(
        session_id="sess-01",
        host_id=HOST,
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        created=100,
        expires=9999,
    )
    base.update(over)
    return SubagentSession(**base)


# --- vocabulary --- #


def test_delegation_vocabulary_order():
    assert tuple(delegation_phases()) == EXPECTED_VOCABULARY
    assert tuple(DELEGATION_PHASES) == EXPECTED_VOCABULARY


def test_mapping_covers_every_lifecycle_state():
    assert set(LIFECYCLE_TO_PROGRESS_PHASE) == set(SubagentLifecycle)
    assert set(EXPECTED_MAPPING) == set(SubagentLifecycle)
    for state in SubagentLifecycle:
        assert LIFECYCLE_TO_PROGRESS_PHASE[state] in EXPECTED_VOCABULARY


@pytest.mark.parametrize("lifecycle", list(SubagentLifecycle))
def test_vocabulary_mapping_for_all_states(lifecycle):
    session = _session()
    event = bridge(session, lifecycle)
    assert isinstance(event, ProgressEvent)
    expected_phase, expected_code, expected_type = EXPECTED_MAPPING[lifecycle]
    assert event.phase == expected_phase
    assert event.message_code == expected_code
    assert event.event_type == expected_type
    assert event.phase in EXPECTED_VOCABULARY
    assert event.status == expected_phase
    assert event.phase_index == EXPECTED_VOCABULARY.index(expected_phase)
    assert event.phase_count == len(EXPECTED_VOCABULARY)
    assert event.run_id == session.session_id
    assert event.audit_id == session.audit_id


@pytest.mark.parametrize("lifecycle", list(SubagentLifecycle))
def test_fixed_phase_names_and_message_codes(lifecycle):
    first = bridge(_session(), lifecycle)
    second = bridge(_session(), lifecycle)
    # Fixed mapping: same inputs give equal events (eq ignores timestamp).
    assert first == second
    assert first.phase == second.phase
    assert first.message_code == second.message_code


def test_string_lifecycle_coerced():
    event = bridge(_session(), "running")
    assert event.phase == "COLLECTING"
    assert event.message_code == "SUBAGENT_COLLECTING_ADVISORY"


def test_unknown_lifecycle_rejected():
    with pytest.raises(ValueError):
        bridge(_session(), "bogus-state")
    with pytest.raises(ValueError):
        bridge(_session(), None)


# --- advisory-only markers --- #


@pytest.mark.parametrize("lifecycle", list(SubagentLifecycle))
def test_advisory_markers_present(lifecycle):
    event = bridge(_session(), lifecycle)
    assert "ADVISORY" in event.message_code


# --- terminal percents --- #


def test_completed_maps_to_100_percent():
    event = bridge(_session(), SubagentLifecycle.COMPLETED)
    assert event.phase == "COMPLETED"
    assert event.percent == 100.0
    assert event.completed == event.total


@pytest.mark.parametrize(
    "lifecycle", [SubagentLifecycle.FAILED, SubagentLifecycle.CANCELLED]
)
def test_failed_cancelled_terminal_preserved(lifecycle):
    event = bridge(_session(), lifecycle)
    assert event.phase in TERMINAL_PROGRESS_PHASES
    assert event.phase in ("FAILED", "CANCELLED")
    # Terminal reflection keeps a non-zero positional percent and never
    # regresses to an active-work phase.
    assert event.percent > 0.0
    assert event.status == event.phase


def test_quarantined_reflected_as_failed_terminal():
    event = bridge(_session(), SubagentLifecycle.QUARANTINED)
    assert event.phase == "FAILED"
    assert event.event_type == ProgressEventType.ERROR
    assert event.message_code == "SUBAGENT_QUARANTINED_ADVISORY"


def test_unavailable_reflected_as_recovering():
    event = bridge(_session(), SubagentLifecycle.UNAVAILABLE)
    assert event.phase == "RECOVERING"
    assert event.message_code == "SUBAGENT_UNAVAILABLE_ADVISORY"


# --- reuse of existing progress machinery (no second event system) --- #


def test_reuses_progress_state_and_reporter():
    import emo_cyber_agent.subagent.progress_bridge as bridge_module

    assert bridge_module.ProgressState is ProgressState
    assert bridge_module.ProgressReporter is ProgressReporter
    # No second event class defined in the bridge module.
    assert not hasattr(bridge_module, "BridgeEvent")
    assert bridge_module.ProgressEvent is ProgressEvent


def test_bridge_emits_through_given_state_and_reporter():
    session = _session()
    state = progress_state_for(session)
    reporter = ProgressReporter()
    assert isinstance(state, ProgressState)

    event = bridge(
        session,
        SubagentLifecycle.RUNNING,
        state=state,
        reporter=reporter,
    )
    assert reporter.events == [event]
    assert state.events[-1] == event
    assert event.phase == "COLLECTING"


def test_progress_state_for_binds_session_ids():
    state = progress_state_for(_session())
    assert state.run_id == "sess-01"
    assert state.audit_id == AUDIT
    assert state.phases == list(EXPECTED_VOCABULARY)


def test_foreign_phase_list_rejected():
    session = _session()
    foreign = ProgressState(
        run_id=session.session_id,
        audit_id=session.audit_id,
        phases=["ONE", "TWO"],
    )
    with pytest.raises(ValueError):
        bridge(session, SubagentLifecycle.RUNNING, state=foreign)


# --- no decision leakage --- #


@pytest.mark.parametrize("lifecycle", list(SubagentLifecycle))
def test_no_decision_leakage_in_event(lifecycle):
    event = bridge(_session(), lifecycle)
    payload = event.to_dict()
    assert set(payload.keys()) == set(EXPECTED_EVENT_KEYS)
    for key in payload:
        lowered = key.lower()
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in lowered, f"leaked field: {key!r}"
    for attr in (
        "capability",
        "capabilities",
        "authorization",
        "authorized",
        "permit",
        "trust",
        "quarantine",
    ):
        assert not hasattr(event, attr)


def test_no_security_state_decisions_from_progress():
    session = _session()
    before = session.to_dict()
    for lifecycle in SubagentLifecycle:
        bridge(session, lifecycle)
    # The bridge never transitions, quarantines, or mutates the session:
    # coordination state is read, not decided.
    assert session.to_dict() == before
    assert session.state == SubagentLifecycle.STARTING
