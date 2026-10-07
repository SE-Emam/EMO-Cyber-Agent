"""Unit tests for the Pi host adapter — POST-T018 (Agent 9B)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.mcp import tools as mcp_tools
from emo_cyber_agent.subagent import discovery, hosts_pi
from emo_cyber_agent.subagent.compat_matrix import HOST_MATRIX, SupportStatus
from emo_cyber_agent.subagent.hosts_pi import (
    CAPABILITY_MAPPING,
    DISPLAY_NAME,
    HOST_ID,
    MCP_SERVER_KEY,
    OPT_IN_TOOLS,
    SAFE_DEFAULT_TOOLS,
    SUPPORT_STATUS,
    TOOL_NAME_MAPPING,
    TROUBLESHOOTING,
    TroubleshootingEntry,
    get_capability_mapping,
    get_project_config_http,
    get_project_config_stdio,
    get_registration_config,
    get_safe_default_tools,
    get_tool_mapping,
    get_troubleshooting,
    get_user_config_http,
    get_user_config_stdio,
    is_protocol_supported,
    negotiate_protocol_version,
)


def test_registration_stdio_variants_shape():
    import json

    for cfg in (get_user_config_stdio(), get_project_config_stdio()):
        assert set(cfg) == {"mcpServers"}
        server = cfg["mcpServers"][MCP_SERVER_KEY]
        assert server["command"] == "cyber-agent"
        assert server["args"] == ["mcp"]
        text = json.dumps(cfg)
        assert "secret" not in text.lower() and "token" not in text.lower()
    # fresh copies each call
    assert get_user_config_stdio() == get_project_config_stdio()
    assert get_user_config_stdio() is not get_user_config_stdio()
    assert get_project_config_stdio() is not get_project_config_stdio()


def test_registration_http_variants_shape():
    import json

    for cfg in (get_user_config_http(), get_project_config_http()):
        assert set(cfg) == {"mcpServers"}
        server = cfg["mcpServers"][MCP_SERVER_KEY]
        assert server["url"] == hosts_pi.SERVER_URL
        assert server["transport"] == "streamable-http"
        assert "command" not in server
        text = json.dumps(cfg)
        assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_user_config_http() is not get_user_config_http()


def test_registration_config_scope_transport_matrix():
    assert get_registration_config() == get_project_config_stdio()
    assert get_registration_config("user", "stdio") == get_user_config_stdio()
    assert get_registration_config("project", "stdio") == get_project_config_stdio()
    assert get_registration_config("user", "streamable-http") == get_user_config_http()
    assert get_registration_config("project", "streamable-http") == get_project_config_http()
    with pytest.raises(ValueError):
        get_registration_config("global", "stdio")
    with pytest.raises(ValueError):
        get_registration_config("project", "sse")


def test_project_scope_and_reload_notes():
    assert "scoped" in hosts_pi.PROJECT_SCOPE_NOTE.lower()
    assert "project" in hosts_pi.PROJECT_SCOPE_NOTE.lower()
    assert "reload" in hosts_pi.RELOAD_NOTE.lower()
    assert "exposure" in hosts_pi.EXPOSURE_CHANGE_NOTE.lower() or "cyber_extensions" in hosts_pi.EXPOSURE_CHANGE_NOTE
    assert set(hosts_pi.TRANSPORTS) == {"stdio", "streamable-http"}


def test_tool_mapping_completeness_identity():
    mapping = get_tool_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    assert set(mapping) == set(discovery.KNOWN_TOOL_NAMES)
    assert len(mapping) == 7  # 5 safe-default + 2 opt-in
    for server_name, host_name in mapping.items():
        assert server_name == host_name  # cyber_* as-is
        assert server_name in TOOL_NAME_MAPPING
    assert "namespace" in hosts_pi.PI_TOOL_NAMESPACE_NOTE.lower()


def test_safe_default_exposure():
    assert tuple(SAFE_DEFAULT_TOOLS) == tuple(get_safe_default_tools())
    assert len(SAFE_DEFAULT_TOOLS) == 5
    assert "cyber_extensions" not in SAFE_DEFAULT_TOOLS
    assert "cyber_threat_intel" not in SAFE_DEFAULT_TOOLS
    assert tuple(OPT_IN_TOOLS) == ("cyber_extensions", "cyber_threat_intel")
    assert len(OPT_IN_TOOLS) == 2
    assert set(SAFE_DEFAULT_TOOLS) | set(OPT_IN_TOOLS) == set(mcp_tools.TOOL_NAMES)
    assert set(SAFE_DEFAULT_TOOLS) & set(OPT_IN_TOOLS) == set()
    # opt-in identity mapping holds for both opt-in tools
    assert get_tool_mapping()["cyber_threat_intel"] == "cyber_threat_intel"


def test_capability_mapping_matches_discovery():
    mapping = get_capability_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    for tool in mcp_tools.TOOL_NAMES:
        assert tuple(mapping[tool]) == tuple(discovery.describe_tool(tool).capabilities)
        assert tuple(CAPABILITY_MAPPING[tool]) == tuple(mapping[tool])
    # 7th opt-in tool mirrors discovery capabilities exactly
    assert tuple(mapping["cyber_threat_intel"]) == ("evidence.read", "threatintel.read")
    assert discovery.describe_tool("cyber_threat_intel").safe_default is False


def test_negotiation_helper_explicit_no_hardcode():
    assert is_protocol_supported(discovery.PROTOCOL_VERSIONS[0]) is True
    assert is_protocol_supported("1999-01-01") is False
    assert is_protocol_supported("") is False
    assert negotiate_protocol_version(tuple(discovery.PROTOCOL_VERSIONS)) == discovery.PROTOCOL_VERSIONS[-1]
    assert negotiate_protocol_version([discovery.PROTOCOL_VERSIONS[0], "1999-01-01"]) == discovery.PROTOCOL_VERSIONS[0]
    assert negotiate_protocol_version(["1999-01-01"]) is None
    assert negotiate_protocol_version([]) is None
    assert negotiate_protocol_version("not-a-list") is None  # type: ignore[arg-type]
    chosen = negotiate_protocol_version(tuple(discovery.PROTOCOL_VERSIONS))
    assert chosen in tuple(discovery.build_advertisement().protocol_versions)
    assert "PROTOCOL_VERSIONS" in hosts_pi.PROTOCOL_NEGOTIATION_NOTE or "discovery" in hosts_pi.PROTOCOL_NEGOTIATION_NOTE


def test_honesty_labels_not_tested():
    assert SUPPORT_STATUS == SupportStatus.NOT_TESTED
    assert hosts_pi.SUPPORT_STATUS.value == "Not-tested"
    assert HOST_MATRIX[HOST_ID].support_status == SupportStatus.NOT_TESTED
    assert HOST_ID == "pi" and DISPLAY_NAME == "Pi"
    assert hosts_pi.SUPPORT_EVIDENCE.strip()


def test_troubleshooting_data():
    entries = get_troubleshooting()
    assert entries == TROUBLESHOOTING and len(entries) >= 3
    issues = {e.issue for e in entries}
    assert "project-scoped-server-not-visible" in issues
    assert "reload-required" in issues
    for entry in entries:
        assert isinstance(entry, TroubleshootingEntry)
        assert entry.issue.strip() and entry.symptom.strip() and entry.fix.strip()
        assert TroubleshootingEntry.from_dict(entry.to_dict()) == entry


def test_module_has_no_execution_or_policy():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "hosts_pi.py").read_text()
    for marker in ("import subprocess", "import socket", "os.system", "popen", "urllib", "__import__", "exec(", "eval("):
        assert marker not in src, marker
