"""Hermes host adapter — POST-T018 (Agent 9C).

Data-only adapter metadata for the Hermes subagent host. No execution,
no network, no subprocess, no policy logic: this module only describes
registration config, tool naming, safe-default exposure, capability
mapping, per-server filtering guidance, server discovery notes,
protocol-negotiation guidance, and troubleshooting data.

Honesty: Hermes interop is NOT live-verified; compat status is
``Not-tested`` (see ``compat_matrix.HOST_MATRIX["hermes"]``).
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.subagent import discovery
from emo_cyber_agent.subagent.compat_matrix import SupportStatus

HOST_ID = "hermes"
DISPLAY_NAME = "Hermes"
TRANSPORTS: tuple[str, ...] = ("stdio", "streamable-http")
TOOL_NAMING = "kebab-case"
SESSION_BEHAVIOR = "server-managed"

SUPPORT_STATUS: SupportStatus = SupportStatus.NOT_TESTED
SUPPORT_EVIDENCE = (
    "No contract or environment test names this host; default Not-tested. "
    "See compat_matrix.HOST_MATRIX['hermes']."
)

# Hermes addresses MCP tools under its own tool namespace; server-side
# cyber_* names are passed through as-is (identity mapping, no rename).
HERMES_TOOL_NAMESPACE_NOTE = (
    "Hermes invokes MCP tools under its host tool namespace; "
    "cyber_* server tool names are exposed as-is with no rename."
)

SERVER_COMMAND = "cyber-agent"
SERVER_ARGS: tuple[str, ...] = ("mcp",)
MCP_SERVER_KEY = "emo-cyber-agent"
# Config-key spelling note (live-observed, Hermes v0.21.4, POST-T020 G1):
# get_stdio_config() documents the camelCase ``mcpServers`` input form, but
# Hermes persists the registration under snake_case ``mcp_servers`` in
# config.yaml (same server/command/args content, different key spelling).
HERMES_PERSISTED_CONFIG_KEY_NOTE = (
    "Hermes v0.21.4 (observed) persists stdio registrations under "
    "snake_case 'mcp_servers' in config.yaml; the adapter's "
    "get_stdio_config() documents the camelCase 'mcpServers' input form "
    "with the same server/command/args content."
)
# Placeholder URL for the Streamable HTTP variant (data only; the server
# must be started separately with an HTTP transport before use).
SERVER_URL = "http://localhost:8000/mcp"

SAFE_DEFAULT_TOOLS: tuple[str, ...] = (
    "cyber_audit",
    "cyber_review",
    "cyber_verify",
    "cyber_report",
    "cyber_status",
)
OPT_IN_TOOLS: tuple[str, ...] = ("cyber_extensions", "cyber_threat_intel")

TOOL_NAME_MAPPING: dict[str, str] = {
    "cyber_audit": "cyber_audit",
    "cyber_review": "cyber_review",
    "cyber_verify": "cyber_verify",
    "cyber_report": "cyber_report",
    "cyber_status": "cyber_status",
    "cyber_extensions": "cyber_extensions",
    "cyber_threat_intel": "cyber_threat_intel",
}

CAPABILITY_MAPPING: dict[str, tuple[str, ...]] = {
    "cyber_audit": ("repo.read", "codeintel.read", "evidence.read"),
    "cyber_review": ("repo.read", "codeintel.read", "evidence.read"),
    "cyber_verify": ("verification.safe", "evidence.read"),
    "cyber_report": ("report.generate", "evidence.read"),
    "cyber_status": (),
    "cyber_extensions": ("evidence.read",),
    "cyber_threat_intel": ("evidence.read", "threatintel.read"),
}

# Recommended per-task allowlists leveraging host-side filtering.
# Never expose all tools by default: each Hermes server registration
# should enable only the subset its task needs. ``cyber_extensions`` and
# ``cyber_threat_intel`` are opt-in and appear in no recommended allowlist.
TASK_ALLOWLISTS: dict[str, tuple[str, ...]] = {
    "security-review": (
        "cyber_audit",
        "cyber_review",
        "cyber_verify",
        "cyber_report",
        "cyber_status",
    ),
    "verify-only": (
        "cyber_verify",
        "cyber_status",
    ),
    "report-only": (
        "cyber_report",
        "cyber_status",
    ),
    "status-only": ("cyber_status",),
}

FILTERING_GUIDANCE = (
    "Hermes servers should be registered per task with a host-side tool "
    "allowlist limited to TASK_ALLOWLISTS[task]; never expose all tools by "
    "default. Apply the allowlist with host-side filtering (the Hermes "
    "server/tool filter config), then confirm the visible set via "
    "tools/list. cyber_extensions and cyber_threat_intel stay opt-in and are excluded from every "
    "recommended allowlist; adding either requires an explicit config edit plus "
    "a host reload and re-list. Unknown task kinds must abort, not fall "
    "back to the full tool set."
)

SERVER_DISCOVERY_NOTE = (
    "Discover the emo-cyber-agent server via the standard MCP lifecycle: "
    "initialize → notifications/initialized → tools/list → tools/call "
    "(see discovery.build_advertisement() for the server-advertised "
    "identity, protocol versions, and tool table). After registering the "
    "Hermes server entry, list tools from the host and compare against "
    "discovery.KNOWN_TOOL_NAMES filtered by the task allowlist; any "
    "advertised tool outside the allowlist must stay hidden by host-side "
    "filtering. Re-run discovery after exposure changes."
)

PROTOCOL_NEGOTIATION_NOTE = (
    "Negotiate the MCP protocol version explicitly via discovery: intersect "
    "the host-offered versions with the server-advertised versions from "
    "discovery.build_advertisement() (discovery.PROTOCOL_VERSIONS) and use "
    "the latest common version. Never assume a version; no common version "
    "means the host must abort, not fall back silently."
)


class TroubleshootingEntry(BaseModel):
    """Frozen troubleshooting datum: symptom + fix. Data only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    issue: str = Field(min_length=1, max_length=120)
    symptom: str = Field(min_length=1, max_length=500)
    fix: str = Field(min_length=1, max_length=500)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)


TROUBLESHOOTING: tuple[TroubleshootingEntry, ...] = (
    TroubleshootingEntry(
        issue="server-not-found",
        symptom="Hermes reports the emo-cyber-agent MCP server is missing or the command fails to start.",
        fix="Verify 'cyber-agent' is installed and on PATH ('cyber-agent --help'); check the stdio registration snippet from get_stdio_config().",
    ),
    TroubleshootingEntry(
        issue="tool-not-visible",
        symptom="cyber_* tools do not appear in Hermes, or cyber_extensions is unexpectedly present/absent.",
        fix="Confirm default exposure is the 5 safe tools only; cyber_extensions and cyber_threat_intel are opt-in. Check the host tool namespace view and re-list via tools/list.",
    ),
    TroubleshootingEntry(
        issue="over-exposed-tools",
        symptom="More tools are visible in Hermes than the task needs (e.g. the full seven-tool set for a status-only task).",
        fix="Apply the per-task allowlist from get_task_allowlist(task) via host-side filtering so only the recommended subset is exposed; never expose all by default. Re-list via tools/list to confirm.",
    ),
    TroubleshootingEntry(
        issue="protocol-version-mismatch",
        symptom="initialize fails or the host reports an unsupported protocol version.",
        fix="Re-run explicit version negotiation via negotiate_protocol_version(); use the latest common version from discovery output; abort if none exists.",
    ),
    TroubleshootingEntry(
        issue="http-connection-refused",
        symptom="The Streamable HTTP variant fails to connect or the URL is unreachable.",
        fix="Confirm the server is actually serving Streamable HTTP at the configured URL, the URL matches the registration snippet from get_http_config(), and Hermes was reloaded after the change.",
    ),
    TroubleshootingEntry(
        issue="discovery-mismatch",
        symptom="The host tool list does not match discovery.build_advertisement() filtered by the task allowlist.",
        fix="Re-run server discovery (initialize → tools/list), compare against discovery.KNOWN_TOOL_NAMES and get_task_allowlist(task), and tighten host-side filtering until only the allowlisted tools are visible.",
    ),
)


def get_stdio_config() -> dict[str, Any]:
    """Return the Hermes stdio registration snippet as data.

    Documents the camelCase ``mcpServers`` input form; Hermes v0.21.4
    (observed, POST-T020 G1) persists the same entry under snake_case
    ``mcp_servers`` — see ``HERMES_PERSISTED_CONFIG_KEY_NOTE``.
    """
    return {
        "mcpServers": {
            MCP_SERVER_KEY: {
                "command": SERVER_COMMAND,
                "args": list(SERVER_ARGS),
            }
        }
    }


def get_http_config() -> dict[str, Any]:
    """Return the Hermes Streamable HTTP registration snippet as data."""
    return {
        "mcpServers": {
            MCP_SERVER_KEY: {
                "url": SERVER_URL,
                "transport": "streamable-http",
            }
        }
    }


def get_registration_config(transport: str = "stdio") -> dict[str, Any]:
    """Return a registration snippet for a transport.

    Pure data helper: ``transport`` is ``"stdio"`` or
    ``"streamable-http"``. Unknown values raise ``ValueError``
    (no silent fallback).
    """
    if transport not in ("stdio", "streamable-http"):
        raise ValueError(f"unknown transport: {transport!r} (expected 'stdio' or 'streamable-http')")
    if transport == "stdio":
        return get_stdio_config()
    return get_http_config()


def get_tool_mapping() -> dict[str, str]:
    """Return a copy of the cyber_* identity tool-name mapping."""
    return dict(TOOL_NAME_MAPPING)


def get_safe_default_tools() -> tuple[str, ...]:
    """Return the 5 safe tools exposed by default (cyber_extensions + cyber_threat_intel opt-in)."""
    return SAFE_DEFAULT_TOOLS


def get_capability_mapping() -> dict[str, tuple[str, ...]]:
    """Return a copy of the tool → capability-token mapping (metadata only)."""
    return {tool: tuple(caps) for tool, caps in CAPABILITY_MAPPING.items()}


def get_per_task_allowlists() -> dict[str, tuple[str, ...]]:
    """Return a copy of the recommended per-task host-side allowlists."""
    return {task: tuple(tools) for task, tools in TASK_ALLOWLISTS.items()}


def get_task_allowlist(task_kind: str) -> tuple[str, ...]:
    """Return the recommended allowlist for a task kind.

    Pure data helper: unknown/empty task kinds raise ``ValueError``
    (no silent fallback to the full tool set).
    """
    if not isinstance(task_kind, str) or not task_kind.strip():
        raise ValueError("task_kind must be a non-empty string")
    key = task_kind.strip()
    if key not in TASK_ALLOWLISTS:
        raise ValueError(f"unknown task kind: {key!r}")
    return TASK_ALLOWLISTS[key]


def get_troubleshooting() -> tuple[TroubleshootingEntry, ...]:
    """Return the troubleshooting entries (data only)."""
    return TROUBLESHOOTING


def is_protocol_supported(version: str) -> bool:
    """Explicit version check against discovery-advertised versions.

    No hardcoded assumption: membership is tested against
    ``discovery.PROTOCOL_VERSIONS`` at call time.
    """
    return isinstance(version, str) and version in tuple(discovery.PROTOCOL_VERSIONS)


def negotiate_protocol_version(host_versions: tuple[str, ...] | list[str]) -> str | None:
    """Intersect host-offered versions with discovery versions; latest common wins.

    Pure helper (no I/O): returns the highest common protocol version, or
    ``None`` when there is no overlap (caller must abort, never silently
    fall back). Unknown/empty input yields ``None``.
    """
    if not isinstance(host_versions, (tuple, list)):
        return None
    offered = [v for v in host_versions if isinstance(v, str) and v.strip()]
    common = [v for v in discovery.PROTOCOL_VERSIONS if v in set(offered)]
    if not common:
        return None
    return common[-1]
