"""Unit tests for the Jan host adapter — POST-T018 (Agent 9D)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.mcp import tools as mcp_tools
from emo_cyber_agent.subagent import discovery, hosts_jan
from emo_cyber_agent.subagent.compat_matrix import HOST_MATRIX, SupportStatus
from emo_cyber_agent.subagent.hosts_jan import (
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
    get_agent_cli_config_http,
    get_agent_cli_config_stdio,
    get_agent_config_http,
    get_agent_config_stdio,
    get_capability_mapping,
    get_desktop_config_http,
    get_desktop_config_stdio,
    get_http_config,
    get_registration_config,
    get_safe_default_tools,
    get_shared_config_http,
    get_shared_config_stdio,
    get_stdio_config,
    get_tool_mapping,
    get_troubleshooting,
    is_protocol_supported,
    negotiate_protocol_version,
)


def test_shared_stdio_snippet_shape():
    import json

    cfg = get_shared_config_stdio()
    assert set(cfg) == {"mcpServers"}
    server = cfg["mcpServers"][MCP_SERVER_KEY]
    assert server["command"] == "cyber-agent"
    assert server["args"] == ["mcp"]
    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_shared_config_stdio() == cfg and get_shared_config_stdio() is not cfg


def test_shared_http_snippet_shape():
    import json

    cfg = get_shared_config_http()
    assert set(cfg) == {"mcpServers"}
    server = cfg["mcpServers"][MCP_SERVER_KEY]
    assert server["url"] == hosts_jan.SERVER_URL
    assert server["transport"] == "streamable-http"
    assert "command" not in server
    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_shared_config_http() is not get_shared_config_http()


def test_desktop_and_agent_cli_share_config():
    assert get_desktop_config_stdio() == get_agent_config_stdio() == get_shared_config_stdio()
    assert get_desktop_config_http() == get_agent_config_http() == get_shared_config_http()
    assert get_agent_cli_config_stdio() == get_shared_config_stdio()
    assert get_agent_cli_config_http() == get_shared_config_http()
    assert get_stdio_config() == get_shared_config_stdio()
    assert get_http_config() == get_shared_config_http()
    assert "share" in hosts_jan.SHARED_CONFIG_NOTE.lower()
    assert "desktop" in hosts_jan.SHARED_CONFIG_NOTE.lower()


def test_registration_config_surface_transport_matrix():
    assert get_registration_config() == get_shared_config_stdio()
    assert get_registration_config("desktop", "stdio") == get_desktop_config_stdio()
    assert get_registration_config("desktop", "streamable-http") == get_desktop_config_http()
    assert get_registration_config("agent", "stdio") == get_agent_config_stdio()
    assert get_registration_config("agent-cli", "streamable-http") == get_agent_config_http()
    assert get_registration_config("cli", "stdio") == get_agent_config_stdio()
    assert get_registration_config("shared", "stdio") == get_shared_config_stdio()
    assert get_registration_config("shared", "http") == get_shared_config_http()
    with pytest.raises(ValueError):
        get_registration_config("mobile", "stdio")
    with pytest.raises(ValueError):
        get_registration_config("desktop", "sse")
    with pytest.raises(ValueError):
        get_registration_config("", "stdio")


def test_transports_cover_stdio_and_http():
    assert set(hosts_jan.TRANSPORTS) == {"stdio", "streamable-http"}


def test_tool_mapping_completeness_identity():
    mapping = get_tool_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    assert set(mapping) == set(discovery.KNOWN_TOOL_NAMES)
    for server_name, host_name in mapping.items():
        assert server_name == host_name  # cyber_* as-is
        assert server_name in TOOL_NAME_MAPPING
    assert "namespace" in hosts_jan.JAN_TOOL_NAMESPACE_NOTE.lower()


def test_safe_default_exposure():
    assert tuple(SAFE_DEFAULT_TOOLS) == tuple(get_safe_default_tools())
    assert len(SAFE_DEFAULT_TOOLS) == 5
    assert "cyber_extensions" not in SAFE_DEFAULT_TOOLS
    assert tuple(OPT_IN_TOOLS) == ("cyber_extensions",)
    assert set(SAFE_DEFAULT_TOOLS) | set(OPT_IN_TOOLS) == set(mcp_tools.TOOL_NAMES)


def test_capability_mapping_matches_discovery():
    mapping = get_capability_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    for tool in mcp_tools.TOOL_NAMES:
        assert tuple(mapping[tool]) == tuple(discovery.describe_tool(tool).capabilities)
        assert tuple(CAPABILITY_MAPPING[tool]) == tuple(mapping[tool])


def test_permission_filtering_routing_notes():
    assert "permission" in hosts_jan.TOOL_PERMISSION_NOTE.lower()
    assert "cyber_extensions" in hosts_jan.TOOL_PERMISSION_NOTE
    filtering = hosts_jan.TOOL_FILTERING_NOTE.lower()
    assert "filter" in filtering
    assert "cyber_extensions" in hosts_jan.TOOL_FILTERING_NOTE
    routing = hosts_jan.TOOL_ROUTING_NOTE.lower()
    assert "rout" in routing
    assert "abort" in routing


def test_approval_ui_boundary_note():
    note = hosts_jan.APPROVAL_UI_BOUNDARY_NOTE
    lowered = note.lower()
    assert "approval" in lowered
    assert "not part of" in lowered or "not part of the emo boundary" in lowered
    assert "emo enforces" in lowered or "emo" in lowered


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
    assert "PROTOCOL_VERSIONS" in hosts_jan.PROTOCOL_NEGOTIATION_NOTE or "discovery" in hosts_jan.PROTOCOL_NEGOTIATION_NOTE


def test_honesty_labels_not_tested():
    assert SUPPORT_STATUS == SupportStatus.NOT_TESTED
    assert hosts_jan.SUPPORT_STATUS.value == "Not-tested"
    assert HOST_MATRIX[HOST_ID].support_status == SupportStatus.NOT_TESTED
    assert HOST_ID == "jan" and DISPLAY_NAME == "Jan"
    assert hosts_jan.SUPPORT_EVIDENCE.strip()


def test_troubleshooting_data():
    entries = get_troubleshooting()
    assert entries == TROUBLESHOOTING and len(entries) >= 3
    issues = {e.issue for e in entries}
    assert "shared-config-not-visible" in issues
    assert "approval-ui-confusion" in issues
    assert "http-connection-refused" in issues
    for entry in entries:
        assert isinstance(entry, TroubleshootingEntry)
        assert entry.issue.strip() and entry.symptom.strip() and entry.fix.strip()
        assert TroubleshootingEntry.from_dict(entry.to_dict()) == entry


def test_module_has_no_execution_or_policy():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "hosts_jan.py").read_text()
    for marker in ("import subprocess", "import socket", "os.system", "popen", "urllib", "__import__", "exec(", "eval("):
        assert marker not in src, marker
