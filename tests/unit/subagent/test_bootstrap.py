"""Host bootstrap readiness tests — POST-T018 (Agent 8A scope only)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent.bootstrap import (
    BootstrapCheck,
    BootstrapEvaluation,
    BootstrapStatus,
    bootstrap_profile,
    evaluate,
)

EXPECTED_ORDER = (
    "python-version",
    "package-installed",
    "core-importable",
    "policy-present",
    "mcp-adapter-present",
    "progress-recovery-present",
    "config-present",
    "resources-present",
)

EXPECTED_REQUIRED = {
    "python-version": True,
    "package-installed": True,
    "core-importable": True,
    "policy-present": True,
    "mcp-adapter-present": False,
    "progress-recovery-present": False,
    "config-present": False,
    "resources-present": True,
}


def _all_present_evidence(checks=tuple()) -> dict:
    return {name: True for name in EXPECTED_ORDER}


# --- profile shape --- #


def test_profile_has_eight_ordered_checks():
    checks = bootstrap_profile("test-host")
    assert isinstance(checks, tuple)
    assert [c.name for c in checks] == list(EXPECTED_ORDER)


def test_profile_check_fields_and_kinds():
    checks = bootstrap_profile("test-host")
    for check in checks:
        assert isinstance(check, BootstrapCheck)
        assert isinstance(check.name, str) and check.name.strip()
        assert isinstance(check.required, bool)
        assert check.required == EXPECTED_REQUIRED[check.name]
        assert check.check_kind.value in ("version-window", "presence")
    kinds = {c.name: c.check_kind.value for c in checks}
    assert kinds["python-version"] == "version-window"
    for name in EXPECTED_ORDER[1:]:
        assert kinds[name] == "presence"


def test_profile_names_unique():
    checks = bootstrap_profile("test-host")
    assert len({c.name for c in checks}) == len(checks) == 8


def test_profile_rejects_bad_host_id():
    import pytest

    for bad in ("", "UPPER", "has space", "a", "-lead", "trail-", "has_underscore"):
        with pytest.raises(ValueError):
            bootstrap_profile(bad)


def test_checks_round_trip():
    checks = bootstrap_profile("test-host")
    for check in checks:
        assert BootstrapCheck.from_dict(check.to_dict()) == check
        assert check.to_canonical_json() == check.to_canonical_json()


# --- evaluate: READY / BLOCKED / DEGRADED --- #


def test_all_present_ready():
    checks = bootstrap_profile("test-host")
    result = evaluate(checks, _all_present_evidence())
    assert result.status == BootstrapStatus.READY
    assert result.missing_required == ()
    assert result.warnings == ()


def test_empty_evidence_blocked_on_required():
    checks = bootstrap_profile("test-host")
    result = evaluate(checks, {})
    assert result.status == BootstrapStatus.BLOCKED
    assert list(result.missing_required) == [n for n in EXPECTED_ORDER if EXPECTED_REQUIRED[n]]
    assert list(result.warnings) == [n for n in EXPECTED_ORDER if not EXPECTED_REQUIRED[n]]


def test_missing_required_blocked():
    checks = bootstrap_profile("test-host")
    evidence = _all_present_evidence()
    evidence["policy-present"] = False
    result = evaluate(checks, evidence)
    assert result.status == BootstrapStatus.BLOCKED
    assert result.missing_required == ("policy-present",)
    assert result.warnings == ()


def test_missing_required_beats_warnings():
    checks = bootstrap_profile("test-host")
    evidence = _all_present_evidence()
    evidence["core-importable"] = False
    evidence["mcp-adapter-present"] = False
    evidence["config-present"] = False
    result = evaluate(checks, evidence)
    assert result.status == BootstrapStatus.BLOCKED
    assert result.missing_required == ("core-importable",)
    assert list(result.warnings) == ["mcp-adapter-present", "config-present"]


def test_missing_optional_only_degraded():
    checks = bootstrap_profile("test-host")
    evidence = _all_present_evidence()
    evidence["mcp-adapter-present"] = False
    evidence["config-present"] = False
    result = evaluate(checks, evidence)
    assert result.status == BootstrapStatus.DEGRADED
    assert result.missing_required == ()
    assert list(result.warnings) == ["mcp-adapter-present", "config-present"]


def test_single_optional_warning_degraded():
    checks = bootstrap_profile("test-host")
    evidence = _all_present_evidence()
    del evidence["config-present"]  # absent key counts as missing
    result = evaluate(checks, evidence)
    assert result.status == BootstrapStatus.DEGRADED
    assert result.warnings == ("config-present",)


def test_mapping_checks_coerced():
    raw = [
        {"name": "python-version", "required": True, "check_kind": "version-window"},
        {"name": "config-present", "required": False, "check_kind": "presence"},
    ]
    assert evaluate(raw, {"python-version": True, "config-present": True}).status == BootstrapStatus.READY
    assert evaluate(raw, {"python-version": True}).status == BootstrapStatus.DEGRADED
    assert evaluate(raw, {}).status == BootstrapStatus.BLOCKED


def test_evaluation_round_trip():
    checks = bootstrap_profile("test-host")
    result = evaluate(checks, {})
    assert BootstrapEvaluation.from_dict(result.to_dict()) == result
    assert result.to_canonical_json() == result.to_canonical_json()


# --- determinism --- #


def test_profile_deterministic():
    first = bootstrap_profile("test-host")
    for _ in range(5):
        assert bootstrap_profile("test-host") == first
    assert [c.to_canonical_json() for c in first] == [c.to_canonical_json() for c in bootstrap_profile("test-host")]


def test_evaluate_deterministic():
    checks = bootstrap_profile("test-host")
    evidence = _all_present_evidence()
    evidence["mcp-adapter-present"] = False
    first = evaluate(checks, evidence)
    for _ in range(5):
        assert evaluate(checks, evidence) == first
    # input checks order preserved in outputs (not re-sorted)
    rev = tuple(reversed(checks))
    rev_result = evaluate(rev, {})
    assert list(rev_result.missing_required) == [c.name for c in rev if c.required]
    assert list(rev_result.warnings) == [c.name for c in rev if not c.required]


# --- purity: data only, no execution --- #


def test_module_never_probes_the_system():
    import ast

    source = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "bootstrap.py").read_text()
    tree = ast.parse(source)
    forbidden_modules = {
        "subprocess", "os", "sys", "shutil", "socket", "platform",
        "importlib", "pathlib", "pty", "signal", "multiprocessing",
        "threading", "asyncio", "http", "urllib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in forbidden_modules, f"bootstrap.py must not import {alias.name!r}"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top not in forbidden_modules, f"bootstrap.py must not import from {node.module!r}"
    forbidden_calls = {"popen", "run", "call", "check_output", "system", "exec", "eval", "which", "getenv", "environ"}
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                called.add(func.attr)
            elif isinstance(func, ast.Name):
                called.add(func.id)
    overlap = forbidden_calls & {c.lower() for c in called}
    assert not overlap, f"bootstrap.py must not execute/probe: {overlap}"
