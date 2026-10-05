"""Subagent health aggregation tests — POST-T018 (Agent 8B scope only)."""

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent.health import ComponentReport, check_subagent, for_doctor
from emo_cyber_agent.subagent.session import SubagentHealth


def _rep(name: str, state: SubagentHealth, detail: str = "") -> ComponentReport:
    return ComponentReport(name=name, state=state, detail=detail)


# --- aggregation truth table --- #


def test_empty_aggregates_ready():
    assert check_subagent([]) == SubagentHealth.READY
    assert check_subagent(()) == SubagentHealth.READY


def test_all_ready_aggregates_ready():
    reports = [_rep("a", SubagentHealth.READY), _rep("b", SubagentHealth.READY)]
    assert check_subagent(reports) == SubagentHealth.READY


def test_single_states_passthrough():
    assert check_subagent([_rep("a", SubagentHealth.DEGRADED)]) == SubagentHealth.DEGRADED
    assert check_subagent([_rep("a", SubagentHealth.UNAVAILABLE)]) == SubagentHealth.UNAVAILABLE
    assert check_subagent([_rep("a", SubagentHealth.BLOCKED)]) == SubagentHealth.BLOCKED


def test_degraded_beats_ready():
    reports = [_rep("a", SubagentHealth.READY), _rep("b", SubagentHealth.DEGRADED)]
    assert check_subagent(reports) == SubagentHealth.DEGRADED


def test_unavailable_beats_degraded_and_ready():
    reports = [
        _rep("a", SubagentHealth.READY),
        _rep("b", SubagentHealth.DEGRADED),
        _rep("c", SubagentHealth.UNAVAILABLE),
    ]
    assert check_subagent(reports) == SubagentHealth.UNAVAILABLE


def test_blocked_beats_everything():
    reports = [
        _rep("a", SubagentHealth.READY),
        _rep("b", SubagentHealth.DEGRADED),
        _rep("c", SubagentHealth.UNAVAILABLE),
        _rep("d", SubagentHealth.BLOCKED),
    ]
    assert check_subagent(reports) == SubagentHealth.BLOCKED


def test_blocked_alone_with_ready():
    reports = [_rep("a", SubagentHealth.READY), _rep("b", SubagentHealth.BLOCKED)]
    assert check_subagent(reports) == SubagentHealth.BLOCKED


def test_mapping_inputs_coerced():
    reports = [
        {"name": "a", "state": "ready"},
        {"name": "b", "state": "degraded"},
    ]
    assert check_subagent(reports) == SubagentHealth.DEGRADED


# --- READY semantics: technical availability only, never capability permission --- #


def test_ready_does_not_grant_capabilities():
    from emo_cyber_agent.subagent.capabilities import EffectiveCapabilitySet

    before = EffectiveCapabilitySet(
        audit_id="a",
        project_id="p",
        snapshot_id="s",
        effective=(),
        requested_snapshot=(),
        denied_snapshot=(),
        policy_version="1.0.0",
        computed_by="core-policy",
        computed_at=100,
    )
    assert check_subagent([_rep("host", SubagentHealth.READY)]) == SubagentHealth.READY
    # Explicit capabilities unaffected: health aggregation cannot widen grants.
    assert before.effective == ()
    assert before.allows("tool.exec") is False


def test_health_module_has_no_capability_permission_semantics():
    import ast

    source = Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "health.py"
    tree = ast.parse(source.read_text())
    # No dependency on the capability-permission machinery.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
            for mod in modules:
                assert "capabilit" not in mod.lower(), f"health.py must not import capability machinery: {mod!r}"
    # No permission-grant identifiers in executable code (docstrings excluded by AST).
    forbidden = {"allowed", "denied", "effective", "grants", "authorize", "permits", "capabilities"}
    code_ids: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            code_ids.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            code_ids.add(node.attr.lower())
    overlap = forbidden & code_ids
    assert not overlap, f"health.py code must not carry capability-permission semantics: {overlap}"


def test_ready_state_value_is_availability_not_permission():
    report = _rep("host", SubagentHealth.READY)
    assert report.state == SubagentHealth.READY
    assert report.state.value == "ready"  # availability token, not a permission token


# --- determinism --- #


def test_aggregation_is_order_independent():
    base = [
        _rep("a", SubagentHealth.READY),
        _rep("b", SubagentHealth.DEGRADED),
        _rep("c", SubagentHealth.UNAVAILABLE),
    ]
    expected = check_subagent(base)
    for perm in itertools.permutations(base):
        assert check_subagent(list(perm)) == expected


def test_repeated_calls_stable():
    reports = [_rep("a", SubagentHealth.DEGRADED, detail="slow host"), _rep("b", SubagentHealth.READY)]
    first = check_subagent(reports)
    for _ in range(5):
        assert check_subagent(reports) == first
    assert for_doctor(reports) == for_doctor(reports)
    assert for_doctor(reports) == for_doctor(list(reversed(reports)))


def test_canonical_json_stable():
    report = _rep("a", SubagentHealth.DEGRADED, detail="slow")
    assert report.to_canonical_json() == report.to_canonical_json()
    assert ComponentReport.from_dict(report.to_dict()) == report


# --- for_doctor projection --- #


def test_for_doctor_empty():
    assert for_doctor([]) == {"subagent": "READY"}


def test_for_doctor_projects_aggregate_and_components():
    reports = [_rep("b-host", SubagentHealth.DEGRADED), _rep("a-host", SubagentHealth.READY)]
    checks = for_doctor(reports)
    assert checks["subagent"] == "DEGRADED"
    assert checks["subagent:a-host"] == "READY"
    assert checks["subagent:b-host"] == "DEGRADED"
    assert list(checks) == sorted(checks)  # deterministic key order
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in checks.items())


def test_for_doctor_matches_check_subagent():
    reports = [_rep("a", SubagentHealth.UNAVAILABLE), _rep("b", SubagentHealth.BLOCKED)]
    assert for_doctor(reports)["subagent"] == check_subagent(reports).value.upper()


def test_for_doctor_never_echoes_detail():
    reports = [_rep("a", SubagentHealth.DEGRADED, detail="internal note here")]
    checks = for_doctor(reports)
    assert not any("internal note here" in v for v in checks.values())
