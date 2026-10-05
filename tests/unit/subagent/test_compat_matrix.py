"""Unit tests for the per-host compatibility matrix — POST-T018 (Agent 8C)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.mcp.protocol import SUPPORTED_PROTOCOL_VERSIONS
from emo_cyber_agent.subagent.compat_matrix import (
    HOST_MATRIX,
    HostMatrixEntry,
    SupportStatus,
    evaluate_compat,
    get_entry,
    list_hosts,
)
from emo_cyber_agent.subagent.hosts import CompatibilityVerdict
from emo_cyber_agent.subagent.trust import HostIntegrationError

EXPECTED_HOSTS = ("opencode", "pi", "hermes", "jan", "anythingllm", "generic-mcp")
USABLE = {
    CompatibilityVerdict.EXACT,
    CompatibilityVerdict.MINIMUM,
    CompatibilityVerdict.MAXIMUM,
    CompatibilityVerdict.COMPATIBLE_RANGE,
}


def test_matrix_covers_all_hosts():
    assert set(HOST_MATRIX) == set(EXPECTED_HOSTS)
    assert set(list_hosts()) == set(EXPECTED_HOSTS)


def test_matrix_shape_per_host():
    for host_id in EXPECTED_HOSTS:
        entry = HOST_MATRIX[host_id]
        assert isinstance(entry, HostMatrixEntry)
        assert entry.host_id == host_id
        assert entry.display_name.strip()
        assert entry.protocol_min and entry.protocol_max
        assert entry.transports, f"{host_id} must declare at least one transport"
        assert entry.tool_naming.strip()
        assert entry.lifecycle_notes.strip(), f"{host_id} must document lifecycle notes"
        assert entry.session_behavior.strip()
        assert isinstance(entry.known_limits, tuple) and len(entry.known_limits) >= 1
        assert any(s.strip() for s in entry.known_limits)
        d = entry.to_dict()
        for key in (
            "host_id",
            "protocol_min",
            "protocol_max",
            "transports",
            "tool_naming",
            "lifecycle_notes",
            "session_behavior",
            "known_limits",
            "support_status",
        ):
            assert key in d, f"{host_id} missing {key}"


def test_honest_status_labels():
    allowed = {s.value for s in SupportStatus}
    for host_id, entry in HOST_MATRIX.items():
        assert entry.support_status.value in allowed
    for host_id in ("opencode", "pi", "hermes", "jan", "anythingllm"):
        assert HOST_MATRIX[host_id].support_status == SupportStatus.NOT_TESTED
    baseline = HOST_MATRIX["generic-mcp"]
    assert baseline.support_status == SupportStatus.CONTRACT_TESTED
    assert baseline.support_evidence.strip()
    assert get_entry("generic-mcp") is baseline
    assert get_entry("no-such-host") is None


def test_version_window_supported_protocol_is_usable():
    for proto in SUPPORTED_PROTOCOL_VERSIONS:
        decision = evaluate_compat("generic-mcp", "1.2.3", proto, evaluated_at=7)
        assert decision.verdict in USABLE
        assert decision.host_version == "1.2.3"
        assert decision.evaluated_at == 7
        decision.assert_usable()  # must not raise


def test_version_window_unsupported_protocol_is_incompatible():
    decision = evaluate_compat("generic-mcp", "1.2.3", "1999-01-01")
    assert decision.verdict == CompatibilityVerdict.INCOMPATIBLE
    with pytest.raises(HostIntegrationError) as exc:
        decision.assert_usable()
    assert exc.value.quarantine is True


def test_unknown_host_quarantines():
    decision = evaluate_compat("no-such-host", "1.2.3", SUPPORTED_PROTOCOL_VERSIONS[0])
    assert decision.verdict == CompatibilityVerdict.UNKNOWN
    with pytest.raises(HostIntegrationError) as exc:
        decision.assert_usable()
    assert exc.value.quarantine is True


def test_malformed_versions_quarantine():
    bad_host = evaluate_compat("generic-mcp", "not-semver", SUPPORTED_PROTOCOL_VERSIONS[0])
    assert bad_host.verdict == CompatibilityVerdict.UNKNOWN
    with pytest.raises(HostIntegrationError):
        bad_host.assert_usable()
    bad_proto = evaluate_compat("generic-mcp", "1.2.3", "garbage")
    assert bad_proto.verdict == CompatibilityVerdict.UNKNOWN
    with pytest.raises(HostIntegrationError):
        bad_proto.assert_usable()


def test_short_alias_pi_evaluates_with_documented_decision_id():
    from emo_cyber_agent.subagent.compat_matrix import DECISION_HOST_IDS

    decision = evaluate_compat("pi", "1.0.0", SUPPORTED_PROTOCOL_VERSIONS[0])
    assert decision.verdict in USABLE
    assert decision.host_id == DECISION_HOST_IDS["pi"]
    assert any("pi" in r for r in decision.reasons)
    decision.assert_usable()  # must not raise


def test_determinism():
    first = evaluate_compat("opencode", "0.9.1", SUPPORTED_PROTOCOL_VERSIONS[-1], evaluated_at=42)
    second = evaluate_compat("opencode", "0.9.1", SUPPORTED_PROTOCOL_VERSIONS[-1], evaluated_at=42)
    assert first.to_canonical_json() == second.to_canonical_json()
    assert first == second
