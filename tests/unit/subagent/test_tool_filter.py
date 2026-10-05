"""Per-task/per-session tool allowlist tests — POST-T018 (Agent 5B)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent import tool_filter
from emo_cyber_agent.subagent.tool_filter import filter_tools, tools_for_session
from emo_cyber_agent.subagent.trust import HostIntegrationError

AVAILABLE = (
    "cyber_audit",
    "cyber_extensions",
    "cyber_report",
    "cyber_review",
    "cyber_status",
    "cyber_verify",
)


def test_allow_deny_precedence_deny_wins():
    out = filter_tools(
        AVAILABLE,
        ["cyber_audit", "cyber_review", "cyber_status"],
        ["cyber_review"],
    )
    assert out["allowed"] == ("cyber_audit", "cyber_status")
    assert out["denied_with_reasons"]["cyber_review"] == "denied:cyber_review"
    # in-allow-but-denied never appears in allowed
    assert "cyber_review" not in out["allowed"]


def test_unknown_names_denied():
    out = filter_tools(AVAILABLE, ["cyber_audit", "cyber_nope"], ["cyber_ghost"])
    assert "cyber_nope" not in out["allowed"]
    assert "cyber_ghost" not in out["allowed"]
    assert out["denied_with_reasons"]["cyber_nope"] == "unknown-tool:cyber_nope"
    assert out["denied_with_reasons"]["cyber_ghost"] == "unknown-tool:cyber_ghost"
    # non-allowed known tools also denied (never silent)
    assert out["denied_with_reasons"]["cyber_review"] == "not-allowed:cyber_review"


def test_empty_allow_deny_all_fail_closed():
    out = filter_tools(AVAILABLE, [])
    assert out["allowed"] == ()
    assert set(out["denied_with_reasons"]) == set(AVAILABLE)
    assert all(
        reason == "empty-allow:fail-closed"
        for reason in out["denied_with_reasons"].values()
    )


def test_empty_allow_with_explicit_deny_still_closed():
    out = filter_tools(AVAILABLE, [], ["cyber_audit"])
    assert out["allowed"] == ()
    assert out["denied_with_reasons"]["cyber_audit"] == "denied:cyber_audit"
    assert out["denied_with_reasons"]["cyber_review"] == "empty-allow:fail-closed"


def test_explicit_only_wildcard_never_allowed():
    out = filter_tools(AVAILABLE, ["*"])
    assert out["allowed"] == ()
    assert out["denied_with_reasons"]["*"] == "wildcard-forbidden:*"
    # all available still denied (fail closed — wildcard grants nothing)
    for name in AVAILABLE:
        assert name in out["denied_with_reasons"]

    out2 = filter_tools(AVAILABLE, ["cyber_*", "cyber_audit"], [])
    assert "cyber_audit" in out2["allowed"]
    assert out2["denied_with_reasons"]["cyber_*"] == "wildcard-forbidden:cyber_*"
    # prefix wildcard must not expand to siblings
    assert "cyber_review" not in out2["allowed"]


def test_determinism_ordering_and_repeat():
    kwargs = {
        "available": list(reversed(AVAILABLE)),
        "allow": ["cyber_verify", "cyber_audit", "cyber_audit", "cyber_status"],
        "deny": ["cyber_status", "cyber_status"],
    }
    first = filter_tools(**kwargs)
    second = filter_tools(**kwargs)
    assert first == second
    assert first["allowed"] == tuple(sorted(first["allowed"]))
    assert list(first["denied_with_reasons"]) == sorted(first["denied_with_reasons"])
    assert first["allowed"] == ("cyber_audit", "cyber_verify")


def test_session_helper_ties_to_discovery_subset():
    # security-review subset withholds cyber_extensions (safe_default=False)
    out = tools_for_session(None, "security-review")
    assert "cyber_extensions" not in out["allowed"]
    assert out["denied_with_reasons"]["cyber_extensions"] == "not-allowed:cyber_extensions"
    assert set(out["allowed"]) == {
        "cyber_audit",
        "cyber_review",
        "cyber_verify",
        "cyber_report",
        "cyber_status",
    }
    assert out["allowed"] == tuple(sorted(out["allowed"]))


def test_session_helper_narrowing_only_never_widens():
    # session allow requesting a withheld tool cannot widen the task subset
    out = tools_for_session(
        {"allow": ["cyber_audit", "cyber_extensions", "cyber_status"], "deny": []},
        "security-review",
    )
    assert "cyber_extensions" not in out["allowed"]
    assert set(out["allowed"]) == {"cyber_audit", "cyber_status"}


def test_session_helper_deny_and_unknown():
    out = tools_for_session(
        {"allow": ["cyber_audit", "cyber_review"], "deny": ["cyber_review"]},
        "security-review",
    )
    assert out["allowed"] == ("cyber_audit",)
    assert out["denied_with_reasons"]["cyber_review"] == "denied:cyber_review"

    out2 = tools_for_session({"allow": ["cyber_audit", "nope_tool"]}, "security-review")
    assert "nope_tool" not in out2["allowed"]
    assert out2["denied_with_reasons"]["nope_tool"] == "unknown-tool:nope_tool"


def test_session_helper_unknown_task_rejected():
    with pytest.raises(HostIntegrationError):
        tools_for_session(None, "unknown-kind")
    with pytest.raises(HostIntegrationError):
        tools_for_session(None, "  ")


def test_session_helper_bad_scope_rejected():
    with pytest.raises(HostIntegrationError):
        tools_for_session("not-a-scope", "security-review")
    with pytest.raises(HostIntegrationError):
        filter_tools(AVAILABLE, "cyber_audit")  # type: ignore[arg-type]
    with pytest.raises(HostIntegrationError):
        filter_tools(AVAILABLE, ["", "cyber_audit"])


def test_module_has_no_execution_or_socket():
    src = (
        Path(__file__).parent.parent.parent.parent
        / "src"
        / "emo_cyber_agent"
        / "subagent"
        / "tool_filter.py"
    ).read_text()
    for marker in (
        "import subprocess",
        "import socket",
        "os.system",
        "popen",
        "import urllib",
        "__import__",
        "exec(",
        "eval(",
    ):
        assert marker not in src, marker
    assert "allowlist" in (tool_filter.__doc__ or "").lower()
