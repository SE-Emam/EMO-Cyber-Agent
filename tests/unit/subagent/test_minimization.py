"""Capability-minimization tests — POST-T018 (Agent 4B)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent.minimization import (
    MinimizationResult,
    is_privileged,
    minimize,
    privilege_category,
)
from emo_cyber_agent.subagent.trust import HostIntegrationError


def test_narrowing_effective_subset_of_requested_allowed_disjoint_denied():
    res = minimize(
        ("repo.read", "evidence.read", "repo.write"),
        ("repo.read", "evidence.read"),
        ("repo.write",),
    )
    assert res.effective == ("evidence.read", "repo.read")
    assert set(res.effective) <= set(res.requested)
    assert set(res.effective) <= set(res.allowed)
    assert set(res.effective).isdisjoint(set(res.denied))
    assert res.allows("repo.read") is True
    assert res.allows("repo.write") is False
    assert res.rejected == ("repo.write",)
    assert "denied:repo.write" in res.reasons[0]
    assert "repo.write" in res.reason  # never silent


def test_read_only_to_write_escalation_rejected_with_reason():
    res = minimize(("repo.write",), ("repo.read",), ())
    assert res.effective == ()
    assert res.rejected == ("repo.write",)
    assert any("escalation" in entry and "repo.write" in entry for entry in res.reasons)
    assert "repo.write" in res.reason


@pytest.mark.parametrize("scope", ["repo", "code", "evidence", "report"])
def test_escalation_across_scopes(scope):
    res = minimize((f"{scope}.write",), (f"{scope}.read",), ())
    assert res.effective == ()
    assert res.rejected == (f"{scope}.write",)
    assert "escalation" in res.reason


def test_scope_widening_rejected_with_reason():
    res = minimize(("repo.read", "admin.shell"), ("repo.read",), ())
    assert res.effective == ("repo.read",)
    assert res.rejected == ("admin.shell",)
    # admin-flavoured widening is held under default-deny (explicit allowlist required)
    assert "admin.shell" in res.reason
    assert "admin" in res.reasons[0]


def test_widening_of_unprivileged_capability_rejected():
    res = minimize(("repo.read", "unknown.read"), ("repo.read",), ())
    assert res.effective == ("repo.read",)
    assert res.rejected == ("unknown.read",)
    assert "scope-widening:unknown.read" in res.reasons
    assert "unknown.read" in res.reason


def test_default_deny_privileged_categories():
    privileged = [
        "repo.write",
        "data.delete",
        "admin.read",
        "net.network.egress",
        "incident.remediation.apply",
    ]
    for token in privileged:
        assert is_privileged(token) is True
        assert privilege_category(token)  # every category detected
    assert is_privileged("repo.read") is False
    assert privilege_category("repo.read") is None

    res = minimize(privileged, tuple(privileged), ())
    # Nothing granted without an explicit server allowlist …
    assert res.effective == ()
    assert set(res.rejected) == set(privileged)
    assert all("default-deny" in entry for entry in res.reasons)

    # … and each category is granted once explicitly allowlisted.
    allowed = minimize(privileged, tuple(privileged), (), server_allowlist=privileged)
    assert set(allowed.effective) == set(privileged)
    assert allowed.rejected == ()


def test_default_deny_still_needs_allowed_and_respects_denied():
    res = minimize(("repo.write",), ("repo.write",), (), server_allowlist=("repo.write",))
    assert res.effective == ("repo.write",)
    # allowlist cannot resurrect an explicit deny
    denied = minimize(("repo.write",), ("repo.write",), ("repo.write",), server_allowlist=("repo.write",))
    assert denied.effective == ()
    assert denied.rejected == ("repo.write",)
    # allowlist cannot widen beyond ``allowed``
    widened = minimize(("repo.write",), (), (), server_allowlist=("repo.write",))
    assert widened.effective == ()
    assert "repo.write" in widened.reason


def test_determinism_same_input_same_output():
    first = minimize(("b.read", "a.read"), ("a.read", "b.read"), ())
    second = minimize(("a.read", "b.read"), ("b.read", "a.read"), ())
    assert first == second
    assert first.to_canonical_json() == second.to_canonical_json()
    assert MinimizationResult.from_dict(first.to_dict()) == first


def test_empty_edge():
    res = minimize((), (), ())
    assert res.effective == ()
    assert res.rejected == ()
    assert res.reasons == ()
    assert res.reason  # reason still recorded
    empty_allowed = minimize(("a.read",), (), ())
    assert empty_allowed.effective == ()
    assert empty_allowed.rejected == ("a.read",)


def test_result_invariants_reject_forgery():
    with pytest.raises(Exception):
        MinimizationResult(
            effective=("extra.read",),
            rejected=(),
            reasons=(),
            reason="forged",
            requested=("a.read",),
            allowed=("a.read", "extra.read"),
            denied=(),
            server_allowlist=(),
        )
    with pytest.raises(Exception):
        MinimizationResult(
            effective=("a.read",),
            rejected=(),
            reasons=(),
            reason="forged",
            requested=("a.read",),
            allowed=(),
            denied=(),
            server_allowlist=(),
        )
    with pytest.raises(Exception):
        MinimizationResult(
            effective=("a.read",),
            rejected=(),
            reasons=(),
            reason="forged",
            requested=("a.read",),
            allowed=("a.read",),
            denied=("a.read",),
            server_allowlist=(),
        )


def test_invalid_tokens_rejected():
    with pytest.raises(HostIntegrationError):
        minimize(("",), (), ())
    with pytest.raises(HostIntegrationError):
        minimize(("  ",), (), ())
    with pytest.raises(HostIntegrationError):
        minimize((123,), (), ())  # type: ignore[arg-type]


def test_module_has_no_execution():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "minimization.py").read_text()
    for marker in ("subprocess", "os.system", "popen", "socket", "urllib", "__import__"):
        assert marker not in src, marker
