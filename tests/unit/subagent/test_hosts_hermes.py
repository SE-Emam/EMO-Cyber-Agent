"""Unit tests for the Hermes host adapter — POST-T018 (Agent 9C)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.mcp import tools as mcp_tools
from emo_cyber_agent.subagent import discovery, hosts_hermes
from emo_cyber_agent.subagent.compat_matrix import HOST_MATRIX, SupportStatus
from emo_cyber_agent.subagent.hosts_hermes import (
    CAPABILITY_MAPPING,
    DISPLAY_NAME,
    HOST_ID,
    MCP_SERVER_KEY,
    OPT_IN_TOOLS,
    SAFE_DEFAULT_TOOLS,
    SUPPORT_STATUS,
    TASK_ALLOWLISTS,
    TOOL_NAME_MAPPING,
    TROUBLESHOOTING,
    TroubleshootingEntry,
    get_capability_mapping,
    get_http_config,
    get_per_task_allowlists,
    get_registration_config,
    get_safe_default_tools,
    get_stdio_config,
    get_task_allowlist,
    get_tool_mapping,
    get_troubleshooting,
    is_protocol_supported,
    negotiate_protocol_version,
)


def test_registration_stdio_shape():
    import json

    cfg = get_stdio_config()
    # Adapter documents the camelCase input form; Hermes v0.21.4 (observed,
    # POST-T020 G1) persists the same entry under snake_case `mcp_servers`
    # (see HERMES_PERSISTED_CONFIG_KEY_NOTE).
    assert set(cfg) == {"mcpServers"}
    server = cfg["mcpServers"][MCP_SERVER_KEY]
    assert server["command"] == "cyber-agent"
    assert server["args"] == ["mcp"]
    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_stdio_config() == cfg and get_stdio_config() is not cfg


def test_persisted_config_key_note_snake_case():
    note = hosts_hermes.HERMES_PERSISTED_CONFIG_KEY_NOTE
    assert "mcp_servers" in note
    assert "mcpServers" in note  # input form documented alongside
    assert "0.21.4" in note


def test_registration_http_shape():
    import json

    cfg = get_http_config()
    assert set(cfg) == {"mcpServers"}
    server = cfg["mcpServers"][MCP_SERVER_KEY]
    assert server["url"] == hosts_hermes.SERVER_URL
    assert server["transport"] == "streamable-http"
    assert "command" not in server
    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_http_config() is not get_http_config()


def test_registration_config_transport_matrix():
    assert get_registration_config() == get_stdio_config()
    assert get_registration_config("stdio") == get_stdio_config()
    assert get_registration_config("streamable-http") == get_http_config()
    with pytest.raises(ValueError):
        get_registration_config("sse")
    with pytest.raises(ValueError):
        get_registration_config("")


def test_transports_cover_stdio_and_http():
    assert set(hosts_hermes.TRANSPORTS) == {"stdio", "streamable-http"}


def test_tool_mapping_completeness_identity():
    mapping = get_tool_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    assert set(mapping) == set(discovery.KNOWN_TOOL_NAMES)
    assert len(mapping) == 7  # 5 safe-default + 2 opt-in
    for server_name, host_name in mapping.items():
        assert server_name == host_name  # cyber_* as-is
        assert server_name in TOOL_NAME_MAPPING
    assert "namespace" in hosts_hermes.HERMES_TOOL_NAMESPACE_NOTE.lower()


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


def test_per_task_filtering_guidance_never_expose_all():
    allowlists = get_per_task_allowlists()
    assert allowlists == TASK_ALLOWLISTS and allowlists is not TASK_ALLOWLISTS
    assert set(allowlists) >= {"security-review", "status-only"}
    for task, tools in allowlists.items():
        assert tools and isinstance(tools, tuple)
        assert "cyber_extensions" not in tools
        assert "cyber_threat_intel" not in tools
        assert set(tools) <= set(mcp_tools.TOOL_NAMES)
    # recommended lists are strict subsets except the full safe-default task
    assert tuple(allowlists["security-review"]) == tuple(SAFE_DEFAULT_TOOLS)
    assert len(allowlists["status-only"]) < len(mcp_tools.TOOL_NAMES)
    guidance = hosts_hermes.FILTERING_GUIDANCE.lower()
    assert "never expose all" in guidance or "never expose" in guidance
    assert "allowlist" in guidance or "host-side filtering" in guidance
    assert "cyber_extensions" in hosts_hermes.FILTERING_GUIDANCE


def test_get_task_allowlist():
    assert get_task_allowlist("security-review") == TASK_ALLOWLISTS["security-review"]
    assert get_task_allowlist("status-only") == ("cyber_status",)
    with pytest.raises(ValueError):
        get_task_allowlist("unknown-task")
    with pytest.raises(ValueError):
        get_task_allowlist("")
    with pytest.raises(ValueError):
        get_task_allowlist(None)  # type: ignore[arg-type]


def test_server_discovery_notes():
    note = hosts_hermes.SERVER_DISCOVERY_NOTE.lower()
    assert "tools/list" in note
    assert "discovery" in note
    assert "allowlist" in note or "filter" in note


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
    assert "PROTOCOL_VERSIONS" in hosts_hermes.PROTOCOL_NEGOTIATION_NOTE or "discovery" in hosts_hermes.PROTOCOL_NEGOTIATION_NOTE


def test_honesty_labels_not_tested():
    assert SUPPORT_STATUS == SupportStatus.NOT_TESTED
    assert hosts_hermes.SUPPORT_STATUS.value == "Not-tested"
    assert HOST_MATRIX[HOST_ID].support_status == SupportStatus.NOT_TESTED
    assert HOST_ID == "hermes" and DISPLAY_NAME == "Hermes"
    assert hosts_hermes.SUPPORT_EVIDENCE.strip()


def test_troubleshooting_data():
    entries = get_troubleshooting()
    assert entries == TROUBLESHOOTING and len(entries) >= 3
    issues = {e.issue for e in entries}
    assert "over-exposed-tools" in issues
    assert "discovery-mismatch" in issues
    assert "http-connection-refused" in issues
    for entry in entries:
        assert isinstance(entry, TroubleshootingEntry)
        assert entry.issue.strip() and entry.symptom.strip() and entry.fix.strip()
        assert TroubleshootingEntry.from_dict(entry.to_dict()) == entry


def test_module_has_no_execution_or_policy():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "hosts_hermes.py").read_text()
    for marker in ("import subprocess", "import socket", "os.system", "popen", "urllib", "__import__", "exec(", "eval("):
        assert marker not in src, marker
