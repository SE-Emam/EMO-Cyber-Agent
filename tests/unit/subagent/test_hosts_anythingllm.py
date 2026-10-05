"""Unit tests for the AnythingLLM host adapter — POST-T018 (Agent 9E)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.mcp import tools as mcp_tools
from emo_cyber_agent.subagent import discovery, hosts_anythingllm
from emo_cyber_agent.subagent.compat_matrix import HOST_MATRIX, SupportStatus
from emo_cyber_agent.subagent.hosts_anythingllm import (
    CAPABILITY_MAPPING,
    CONTENT_SOURCE_TRUST,
    DISPLAY_NAME,
    HOST_ID,
    MCP_SERVER_KEY,
    OPT_IN_TOOLS,
    SAFE_DEFAULT_TOOLS,
    SUPPORT_STATUS,
    TOOL_NAME_MAPPING,
    TROUBLESHOOTING,
    TroubleshootingEntry,
    build_context_trust,
    classify_content_source,
    get_agent_config_http,
    get_agent_config_stdio,
    get_agent_registration_config,
    get_boundary_notes,
    get_capability_mapping,
    get_content_source_trust,
    get_http_config,
    get_registration_config,
    get_safe_default_tools,
    get_stdio_config,
    get_tool_mapping,
    get_troubleshooting,
    is_protocol_supported,
    negotiate_protocol_version,
)
from emo_cyber_agent.subagent.trust import ContextClassification, ContextTrust


def test_stdio_snippet_shape():
    import json

    cfg = get_stdio_config()
    assert set(cfg) == {"mcpServers"}
    server = cfg["mcpServers"][MCP_SERVER_KEY]
    assert server["command"] == "cyber-agent"
    assert server["args"] == ["mcp"]
    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_stdio_config() == cfg and get_stdio_config() is not cfg


def test_http_snippet_shape():
    import json

    cfg = get_http_config()
    assert set(cfg) == {"mcpServers"}
    server = cfg["mcpServers"][MCP_SERVER_KEY]
    assert server["url"] == hosts_anythingllm.SERVER_URL
    assert server["transport"] == "streamable-http"
    assert "command" not in server
    text = json.dumps(cfg)
    assert "secret" not in text.lower() and "token" not in text.lower()
    assert get_http_config() is not get_http_config()


def test_agent_snippets_wrap_mcp_entry():
    stdio = get_agent_config_stdio()
    assert stdio["agent"] == {"mcpServers": [MCP_SERVER_KEY]}
    assert stdio["mcpServers"] == get_stdio_config()["mcpServers"]
    http = get_agent_config_http()
    assert http["agent"] == {"mcpServers": [MCP_SERVER_KEY]}
    assert http["mcpServers"] == get_http_config()["mcpServers"]


def test_registration_config_transport_matrix():
    assert get_registration_config() == get_stdio_config()
    assert get_registration_config("stdio") == get_stdio_config()
    assert get_registration_config("streamable-http") == get_http_config()
    assert get_registration_config("http") == get_http_config()
    assert get_agent_registration_config() == get_agent_config_stdio()
    assert get_agent_registration_config("stdio") == get_agent_config_stdio()
    assert get_agent_registration_config("streamable-http") == get_agent_config_http()
    assert get_agent_registration_config("http") == get_agent_config_http()
    with pytest.raises(ValueError):
        get_registration_config("sse")
    with pytest.raises(ValueError):
        get_registration_config("")
    with pytest.raises(ValueError):
        get_agent_registration_config("sse")


def test_transports_cover_stdio_and_http():
    assert set(hosts_anythingllm.TRANSPORTS) == {"stdio", "streamable-http"}


def test_tool_mapping_completeness_identity():
    mapping = get_tool_mapping()
    assert set(mapping) == set(mcp_tools.TOOL_NAMES)
    assert set(mapping) == set(discovery.KNOWN_TOOL_NAMES)
    for server_name, host_name in mapping.items():
        assert server_name == host_name  # cyber_* as-is
        assert server_name in TOOL_NAME_MAPPING
    assert "namespace" in hosts_anythingllm.ANYTHINGLLM_TOOL_NAMESPACE_NOTE.lower()


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


def test_boundary_notes_untrusted_default():
    notes = get_boundary_notes()
    assert tuple(notes) == tuple(hosts_anythingllm.BOUNDARY_NOTES)
    assert len(notes) >= 4
    blob = " ".join(notes).lower()
    assert "workspace" in blob
    assert "rag" in blob
    assert "memory" in blob
    assert "untrusted" in blob
    assert "trusted core path" in blob
    assert "workspace" in hosts_anythingllm.WORKSPACE_BOUNDARY_NOTE.lower()
    assert "untrusted" in hosts_anythingllm.WORKSPACE_BOUNDARY_NOTE.lower()
    assert "untrusted" in hosts_anythingllm.RAG_BOUNDARY_NOTE.lower()
    assert "untrusted" in hosts_anythingllm.MEMORY_BOUNDARY_NOTE.lower()
    assert "trusted core path" in hosts_anythingllm.TRUSTED_CORE_PATH_NOTE.lower()


def test_content_source_trust_map_untrusted_defaults():
    mapping = get_content_source_trust()
    assert mapping == CONTENT_SOURCE_TRUST and mapping is not CONTENT_SOURCE_TRUST
    assert mapping["workspace-docs"] == ContextClassification.UNTRUSTED
    assert mapping["rag-retrieval"] == ContextClassification.UNTRUSTED
    assert mapping["chat-memory"] == ContextClassification.UNTRUSTED
    assert mapping["agent-memory"] == ContextClassification.UNTRUSTED
    assert mapping["agent-output"] == ContextClassification.UNTRUSTED
    assert mapping["trusted-core-path"] == ContextClassification.TRUSTED
    # Only the trusted Core path escapes UNTRUSTED.
    untrusted = [k for k, v in mapping.items() if v == ContextClassification.UNTRUSTED]
    assert len(untrusted) == len(mapping) - 1


def test_classify_content_source():
    assert classify_content_source("workspace-docs") == ContextClassification.UNTRUSTED
    assert classify_content_source("rag-retrieval") == ContextClassification.UNTRUSTED
    assert classify_content_source("chat-memory") == ContextClassification.UNTRUSTED
    assert classify_content_source("agent-memory") == ContextClassification.UNTRUSTED
    assert classify_content_source("agent-output") == ContextClassification.UNTRUSTED
    assert classify_content_source("trusted-core-path") == ContextClassification.TRUSTED
    # Case/whitespace tolerant.
    assert classify_content_source("  Workspace-Docs ") == ContextClassification.UNTRUSTED
    assert classify_content_source("RAG-RETRIEVAL") == ContextClassification.UNTRUSTED
    # Fail-closed on unknown/empty/non-string.
    assert classify_content_source("workspace-files") == ContextClassification.UNTRUSTED
    assert classify_content_source("") == ContextClassification.UNTRUSTED
    assert classify_content_source("   ") == ContextClassification.UNTRUSTED
    assert classify_content_source(None) == ContextClassification.UNTRUSTED  # type: ignore[arg-type]
    assert classify_content_source(123) == ContextClassification.UNTRUSTED  # type: ignore[arg-type]
    assert "classify_content_source" in hosts_anythingllm.CONTEXT_CLASSIFICATION_NOTE


def test_build_context_trust():
    ctx = build_context_trust("rag-retrieval", "scope-1")
    assert isinstance(ctx, ContextTrust)
    assert ctx.classification == ContextClassification.UNTRUSTED
    assert ctx.source == "rag-retrieval"
    assert ctx.scope_ref == "scope-1"
    assert ctx.sanitized is False
    trusted = build_context_trust("trusted-core-path", "scope-1")
    assert trusted.classification == ContextClassification.TRUSTED
    unknown = build_context_trust("nope-source", "scope-1")
    assert unknown.classification == ContextClassification.UNTRUSTED
    sanitized = build_context_trust("workspace-docs", "scope-1", sanitized=True)
    assert sanitized.sanitized is True
    assert sanitized.classification == ContextClassification.UNTRUSTED
    with pytest.raises(Exception):
        build_context_trust("rag-retrieval", "")


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
    assert "PROTOCOL_VERSIONS" in hosts_anythingllm.PROTOCOL_NEGOTIATION_NOTE or "discovery" in hosts_anythingllm.PROTOCOL_NEGOTIATION_NOTE


def test_honesty_labels_not_tested():
    assert SUPPORT_STATUS == SupportStatus.NOT_TESTED
    assert hosts_anythingllm.SUPPORT_STATUS.value == "Not-tested"
    assert HOST_MATRIX[HOST_ID].support_status == SupportStatus.NOT_TESTED
    assert HOST_ID == "anythingllm" and DISPLAY_NAME == "AnythingLLM"
    assert hosts_anythingllm.SUPPORT_EVIDENCE.strip()


def test_troubleshooting_data():
    entries = get_troubleshooting()
    assert entries == TROUBLESHOOTING and len(entries) >= 3
    issues = {e.issue for e in entries}
    assert "agent-not-listing-tools" in issues
    assert "workspace-context-mistrusted" in issues
    assert "rag-poisoning-suspected" in issues
    for entry in entries:
        assert isinstance(entry, TroubleshootingEntry)
        assert entry.issue.strip() and entry.symptom.strip() and entry.fix.strip()
        assert TroubleshootingEntry.from_dict(entry.to_dict()) == entry


def test_module_has_no_execution_or_policy():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "hosts_anythingllm.py").read_text()
    for marker in ("import subprocess", "import socket", "os.system", "popen", "urllib", "__import__", "exec(", "eval("):
        assert marker not in src, marker
