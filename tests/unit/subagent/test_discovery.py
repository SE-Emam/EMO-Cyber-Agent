"""Discovery advertisement contract tests — POST-T018 (Agent 5A)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.mcp import protocol as mcp_protocol
from emo_cyber_agent.mcp import tools as mcp_tools
from emo_cyber_agent.subagent import discovery
from emo_cyber_agent.subagent.discovery import (
    KNOWN_TOOL_NAMES,
    PROTOCOL_VERSIONS,
    SERVER_NAME,
    SERVER_VERSION,
    SURFACE_VERSION,
    ServerAdvertisement,
    build_advertisement,
    describe_tool,
    list_tools,
    tools_for_task,
)
from emo_cyber_agent.subagent.negotiation import TASK_OFFERS
from emo_cyber_agent.subagent.trust import HostIntegrationError

EXPECTED_TOOLS = (
    "cyber_audit",
    "cyber_extensions",
    "cyber_report",
    "cyber_review",
    "cyber_status",
    "cyber_threat_intel",
    "cyber_verify",
)


def test_advertisement_shape():
    ad = build_advertisement()
    assert ad.server_name == SERVER_NAME
    assert ad.server_version == SERVER_VERSION
    assert ad.surface_version == SURFACE_VERSION
    assert isinstance(ad.protocol_versions, tuple) and len(ad.protocol_versions) >= 1
    assert ad.tool_names() == EXPECTED_TOOLS  # sorted, deterministic
    for tool in ad.tools:
        assert tool.name and tool.description
        assert isinstance(tool.capabilities, tuple)
        assert isinstance(tool.safe_default, bool)
    # round-trip
    assert ServerAdvertisement.from_dict(ad.to_dict()) == ad


def test_version_pinning_matches_canonical_mcp_surface():
    ad = build_advertisement()
    assert ad.server_name == mcp_protocol.SERVER_NAME
    assert ad.server_version == mcp_protocol.SERVER_VERSION
    assert tuple(ad.protocol_versions) == tuple(mcp_protocol.SUPPORTED_PROTOCOL_VERSIONS)
    assert tuple(ad.protocol_versions) == PROTOCOL_VERSIONS
    assert set(ad.tool_names()) == set(mcp_tools.TOOL_NAMES)
    assert set(KNOWN_TOOL_NAMES) == set(mcp_tools.TOOL_NAMES)


def test_filtered_subset_per_task_kind():
    ad = build_advertisement(task_kind="security-review")
    assert ad.tool_names() == tuple(sorted(ad.tool_names()))
    assert set(ad.tool_names()) <= set(KNOWN_TOOL_NAMES)
    assert "cyber_extensions" not in ad.tool_names()  # safe_default=False withheld
    assert "cyber_threat_intel" not in ad.tool_names()  # safe_default=False withheld
    assert set(ad.tool_names()) == {
        "cyber_audit",
        "cyber_review",
        "cyber_verify",
        "cyber_report",
        "cyber_status",
    }
    # task-kind key ties to negotiation offers
    assert "security-review" in TASK_OFFERS
    assert set(tools_for_task("security-review")) <= set(build_advertisement().tools)


def test_filtered_subset_narrowing_with_only():
    ad = build_advertisement(task_kind="security-review", only=["cyber_status", "cyber_report"])
    assert ad.tool_names() == ("cyber_report", "cyber_status")
    # narrowing outside the task subset cannot widen it
    with pytest.raises(HostIntegrationError):
        build_advertisement(task_kind="security-review", only=["cyber_extensions"])


def test_determinism():
    first = build_advertisement()
    second = build_advertisement()
    assert first == second
    assert first.to_canonical_json() == second.to_canonical_json()
    a = build_advertisement(task_kind="security-review")
    b = build_advertisement(task_kind="security-review")
    assert a.to_canonical_json() == b.to_canonical_json()
    assert list_tools() == KNOWN_TOOL_NAMES


def test_unknown_tool_rejection():
    with pytest.raises(HostIntegrationError):
        describe_tool("cyber_delete_everything")
    with pytest.raises(HostIntegrationError):
        describe_tool("  ")
    with pytest.raises(HostIntegrationError):
        build_advertisement(only=["cyber_audit", "nope_unknown"])
    with pytest.raises(HostIntegrationError):
        build_advertisement(task_kind="unknown-kind")
    with pytest.raises(HostIntegrationError):
        build_advertisement(only=[])


def test_safe_default_flag_present():
    ad = build_advertisement()
    flags = {t.name: t.safe_default for t in ad.tools}
    assert flags["cyber_extensions"] is False
    assert flags["cyber_threat_intel"] is False
    assert all(flags[n] is True for n in EXPECTED_TOOLS if n not in ("cyber_extensions", "cyber_threat_intel"))


def test_module_has_no_execution_or_socket():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "discovery.py").read_text()
    for marker in ("import subprocess", "import socket", "os.system", "popen", "import urllib", "__import__", "exec(", "eval("):
        assert marker not in src, marker
    assert "discovery" in discovery.__doc__.lower()
