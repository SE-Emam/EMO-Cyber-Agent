"""Unit tests for the OpenCode host adapter — POST-T018 (Agent 9A)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.mcp import tools as mcp_tools
from emo_cyber_agent.subagent import discovery, hosts_opencode
from emo_cyber_agent.subagent.compat_matrix import HOST_MATRIX, SupportStatus
from emo_cyber_agent.subagent.hosts_opencode import (
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
    get_registration_config,
    get_safe_default_tools,
    get_tool_mapping,
    get_troubleshooting,
    is_protocol_supported,
    negotiate_protocol_version,
)


def test_registration_config_shape():
    cfg = get_registration_config()
    # Live shape observed against opencode 1.18.34 (POST-T020 G1):
    # {"mcp": {"<name>": {"type": "local", "command": [...], "enabled": true}}}
    assert set(cfg) == {"mcp"}
    assert "mcpServers" not in cfg  # legacy form yields zero servers live
    server = cfg["mcp"][MCP_SERVER_KEY]
    assert server["type"] == "local"
    assert server["command"] == ["cyber-agent", "mcp"]
    assert server["enabled"] is True
    # JSON-serializable stdio snippet, no credentials
    import json

    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    # fresh copy each call
    assert get_registration_config() == cfg and get_registration_config() is not cfg


def test_tool_mapping_completeness_identity():
    mapping = get_tool_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    assert set(mapping) == set(discovery.KNOWN_TOOL_NAMES)
    assert len(mapping) == 7  # 5 safe-default + 2 opt-in
    for server_name, host_name in mapping.items():
        assert server_name == host_name  # cyber_* as-is
        assert server_name in TOOL_NAME_MAPPING
    assert "opencode" in hosts_opencode.OPENCODE_TOOL_NAMESPACE_NOTE.lower() or "namespace" in hosts_opencode.OPENCODE_TOOL_NAMESPACE_NOTE.lower()
    # Live-observed host namespacing (opencode 1.18.34, POST-T020 G1):
    # tools are invoked as emo-cyber-agent_<tool>, not bare cyber_*.
    note = hosts_opencode.OPENCODE_TOOL_NAMESPACE_NOTE
    assert "emo-cyber-agent_" in note
    assert "1.18.34" in note


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
    # full overlap → latest advertised wins
    assert negotiate_protocol_version(tuple(discovery.PROTOCOL_VERSIONS)) == discovery.PROTOCOL_VERSIONS[-1]
    # partial overlap → latest common
    assert negotiate_protocol_version([discovery.PROTOCOL_VERSIONS[0], "1999-01-01"]) == discovery.PROTOCOL_VERSIONS[0]
    # no overlap / bad input → None (abort, no silent fallback)
    assert negotiate_protocol_version(["1999-01-01"]) is None
    assert negotiate_protocol_version([]) is None
    assert negotiate_protocol_version("not-a-list") is None  # type: ignore[arg-type]
    # result always comes from discovery advertisement, never hardcoded
    chosen = negotiate_protocol_version(tuple(discovery.PROTOCOL_VERSIONS))
    assert chosen in tuple(discovery.build_advertisement().protocol_versions)
    assert "PROTOCOL_VERSIONS" in hosts_opencode.PROTOCOL_NEGOTIATION_NOTE or "discovery" in hosts_opencode.PROTOCOL_NEGOTIATION_NOTE


def test_honesty_labels_not_tested():
    assert SUPPORT_STATUS == SupportStatus.NOT_TESTED
    assert hosts_opencode.SUPPORT_STATUS.value == "Not-tested"
    assert HOST_MATRIX[HOST_ID].support_status == SupportStatus.NOT_TESTED
    assert HOST_ID == "opencode" and DISPLAY_NAME == "OpenCode"
    assert hosts_opencode.SUPPORT_EVIDENCE.strip()


def test_troubleshooting_data():
    entries = get_troubleshooting()
    assert entries == TROUBLESHOOTING and len(entries) >= 3
    for entry in entries:
        assert isinstance(entry, TroubleshootingEntry)
        assert entry.issue.strip() and entry.symptom.strip() and entry.fix.strip()
        assert TroubleshootingEntry.from_dict(entry.to_dict()) == entry
    # server-not-found fix must point at the live `mcp` snippet shape
    # (legacy `mcpServers` form yields zero servers on opencode 1.18.34).
    by_issue = {entry.issue: entry for entry in entries}
    assert "mcp" in by_issue["server-not-found"].fix
    assert "mcpServers" not in by_issue["server-not-found"].fix


def test_module_has_no_execution_or_policy():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "hosts_opencode.py").read_text()
    for marker in ("import subprocess", "import socket", "os.system", "popen", "urllib", "__import__", "exec(", "eval("):
        assert marker not in src, marker
