"""Jan host adapter — POST-T018 (Agent 9D).

Data-only adapter metadata for the Jan subagent host. No execution,
no network, no subprocess, no policy logic: this module only describes
registration config, tool naming, safe-default exposure, capability
mapping, tool-permission/filtering/routing guidance, protocol-negotiation
guidance, and troubleshooting data.

Honesty: Jan interop is NOT live-verified; compat status is
``Not-tested`` (see ``compat_matrix.HOST_MATRIX["jan"]``).
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.subagent import discovery
from emo_cyber_agent.subagent.compat_matrix import SupportStatus

HOST_ID = "jan"
DISPLAY_NAME = "Jan"
TRANSPORTS: tuple[str, ...] = ("stdio", "streamable-http")
TOOL_NAMING = "kebab-case"
SESSION_BEHAVIOR = "server-managed"

SUPPORT_STATUS: SupportStatus = SupportStatus.NOT_TESTED
SUPPORT_EVIDENCE = (
    "No contract or environment test names this host; default Not-tested. "
    "See compat_matrix.HOST_MATRIX['jan']."
)

# Jan addresses MCP tools under its own tool namespace; server-side
# cyber_* names are passed through as-is (identity mapping, no rename).
JAN_TOOL_NAMESPACE_NOTE = (
    "Jan invokes MCP tools under its host tool namespace; "
    "cyber_* server tool names are exposed as-is with no rename."
)

SERVER_COMMAND = "cyber-agent"
SERVER_ARGS: tuple[str, ...] = ("mcp",)
MCP_SERVER_KEY = "emo-cyber-agent"
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

SHARED_CONFIG_NOTE = (
    "Jan Desktop and the Jan Agent/CLI share the same mcpServers "
    "registration snippet: the stdio snippet (command + args) and the "
    "Streamable HTTP snippet (url + transport) below are valid in both "
    "surfaces. Register once per surface, then reload that surface and "
    "re-list tools to confirm the visible set."
)

TOOL_PERMISSION_NOTE = (
    "Jan tool permissions are host-side metadata only: grant each cyber_* "
    "tool the minimum permission the task needs and keep cyber_extensions "
    "denied unless explicitly opted in. Permission grants in Jan never "
    "widen EMO enforcement — EMO applies its own tool filter, capability "
    "checks, and trust boundary regardless of host-side grants."
)

TOOL_FILTERING_NOTE = (
    "Filter the visible tool set on the Jan side to the task at hand: "
    "expose only the safe-default subset (or a narrower per-task subset) "
    "via host-side tool filtering, then confirm the visible set with "
    "tools/list. cyber_extensions stays opt-in and must remain filtered "
    "out by default; adding it requires an explicit config edit plus a "
    "host reload and re-list."
)

FILTERING_NOTE = TOOL_FILTERING_NOTE

TOOL_ROUTING_NOTE = (
    "Route each task to the smallest sufficient tool subset (e.g. "
    "status-only tasks to cyber_status; verify tasks to cyber_verify plus "
    "cyber_status; full reviews to the 5 safe-default tools). Unknown or "
    "unscoped tasks must abort, not fall back to the full tool set; "
    "re-run discovery after exposure or routing changes."
)

ROUTING_NOTE = TOOL_ROUTING_NOTE

APPROVAL_UI_BOUNDARY_NOTE = (
    "Jan approval UI is NOT part of the EMO boundary: Jan-side approval "
    "prompts, allowlists, or click-throughs do not substitute for EMO "
    "enforcement. EMO enforces its own trust boundary, tool filtering, "
    "and capability checks server-side regardless of what the Jan "
    "approval UI displays or permits."
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
        symptom="Jan reports the emo-cyber-agent MCP server is missing or the command fails to start.",
        fix="Verify 'cyber-agent' is installed and on PATH ('cyber-agent --help'); check the shared mcpServers registration snippet from get_shared_config_stdio().",
    ),
    TroubleshootingEntry(
        issue="shared-config-not-visible",
        symptom="The server works in Jan Desktop but does not appear in the Jan Agent/CLI, or vice versa.",
        fix="Registration is per surface even though the snippet is shared: apply the same shared-config snippet in both Jan Desktop and the Jan Agent/CLI config, then reload each surface and re-list tools.",
    ),
    TroubleshootingEntry(
        issue="tool-not-visible",
        symptom="cyber_* tools do not appear in Jan, or cyber_extensions is unexpectedly present/absent.",
        fix="Confirm default exposure is the 5 safe tools only; cyber_extensions and cyber_threat_intel are opt-in. Check the host tool namespace view and re-list via tools/list.",
    ),
    TroubleshootingEntry(
        issue="over-permissioned-tools",
        symptom="More tools or broader permissions are granted in Jan than the task needs.",
        fix="Tighten Jan tool permissions and host-side filtering to the smallest sufficient subset per TOOL_PERMISSION_NOTE and TOOL_FILTERING_NOTE, then re-list via tools/list to confirm.",
    ),
    TroubleshootingEntry(
        issue="approval-ui-confusion",
        symptom="A Jan approval prompt allowed or blocked an action and the operator assumes EMO follows it.",
        fix="Remember the approval-UI boundary: Jan approval UI is NOT part of the EMO boundary. EMO enforces its own checks regardless; verify outcomes via EMO evidence (audit/verify/report), not the host prompt state.",
    ),
    TroubleshootingEntry(
        issue="protocol-version-mismatch",
        symptom="initialize fails or the host reports an unsupported protocol version.",
        fix="Re-run explicit version negotiation via negotiate_protocol_version(); use the latest common version from discovery output; abort if none exists.",
    ),
    TroubleshootingEntry(
        issue="http-connection-refused",
        symptom="The Streamable HTTP variant fails to connect or the URL is unreachable.",
        fix="Confirm the server is actually serving Streamable HTTP at the configured URL, the URL matches the registration snippet from get_shared_config_http(), and Jan was reloaded after the change.",
    ),
)


def get_shared_config_stdio() -> dict[str, Any]:
    """Return the shared (Desktop + Agent/CLI) stdio snippet as data."""
    return {
        "mcpServers": {
            MCP_SERVER_KEY: {
                "command": SERVER_COMMAND,
                "args": list(SERVER_ARGS),
            }
        }
    }


def get_shared_config_http() -> dict[str, Any]:
    """Return the shared (Desktop + Agent/CLI) Streamable HTTP snippet as data."""
    return {
        "mcpServers": {
            MCP_SERVER_KEY: {
                "url": SERVER_URL,
                "transport": "streamable-http",
            }
        }
    }


def get_desktop_config_stdio() -> dict[str, Any]:
    """Return the Jan Desktop stdio registration snippet as data."""
    return get_shared_config_stdio()


def get_desktop_config_http() -> dict[str, Any]:
    """Return the Jan Desktop Streamable HTTP registration snippet as data."""
    return get_shared_config_http()


def get_agent_config_stdio() -> dict[str, Any]:
    """Return the Jan Agent/CLI stdio registration snippet as data."""
    return get_shared_config_stdio()


def get_agent_config_http() -> dict[str, Any]:
    """Return the Jan Agent/CLI Streamable HTTP registration snippet as data."""
    return get_shared_config_http()


def get_agent_cli_config_stdio() -> dict[str, Any]:
    """Alias for the Jan Agent/CLI stdio snippet (shared config)."""
    return get_shared_config_stdio()


def get_agent_cli_config_http() -> dict[str, Any]:
    """Alias for the Jan Agent/CLI Streamable HTTP snippet (shared config)."""
    return get_shared_config_http()


def get_stdio_config() -> dict[str, Any]:
    """Return the Jan stdio registration snippet as data (surface-agnostic)."""
    return get_shared_config_stdio()


def get_http_config() -> dict[str, Any]:
    """Return the Jan Streamable HTTP registration snippet as data."""
    return get_shared_config_http()


_SURFACE_ALIASES: dict[str, str] = {
    "desktop": "desktop",
    "agent": "agent",
    "agent-cli": "agent",
    "cli": "agent",
    "shared": "shared",
}

_TRANSPORT_ALIASES: dict[str, str] = {
    "stdio": "stdio",
    "streamable-http": "streamable-http",
    "http": "streamable-http",
}


def get_registration_config(
    surface: str = "desktop",
    transport: str = "stdio",
) -> dict[str, Any]:
    """Return a registration snippet for a surface × transport combination.

    Pure data helper: ``surface`` is ``"desktop"``, ``"agent"`` /
    ``"agent-cli"`` / ``"cli"`` (all Agent/CLI aliases), or ``"shared"``;
    ``transport`` is ``"stdio"`` or ``"streamable-http"`` (``"http"`` is
    accepted as an alias). Desktop and Agent/CLI share the same snippet
    content. Unknown values raise ``ValueError`` (no silent fallback).
    """
    if not isinstance(surface, str) or surface.strip().lower() not in _SURFACE_ALIASES:
        raise ValueError(
            f"unknown surface: {surface!r} "
            "(expected 'desktop', 'agent', 'agent-cli', 'cli', or 'shared')"
        )
    if not isinstance(transport, str) or transport.strip().lower() not in _TRANSPORT_ALIASES:
        raise ValueError(
            f"unknown transport: {transport!r} (expected 'stdio' or 'streamable-http')"
        )
    normalized_transport = _TRANSPORT_ALIASES[transport.strip().lower()]
    if normalized_transport == "stdio":
        return get_shared_config_stdio()
    return get_shared_config_http()


def get_tool_mapping() -> dict[str, str]:
    """Return a copy of the cyber_* identity tool-name mapping."""
    return dict(TOOL_NAME_MAPPING)


def get_safe_default_tools() -> tuple[str, ...]:
    """Return the 5 safe tools exposed by default (cyber_extensions + cyber_threat_intel opt-in)."""
    return SAFE_DEFAULT_TOOLS


def get_capability_mapping() -> dict[str, tuple[str, ...]]:
    """Return a copy of the tool → capability-token mapping (metadata only)."""
    return {tool: tuple(caps) for tool, caps in CAPABILITY_MAPPING.items()}


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
