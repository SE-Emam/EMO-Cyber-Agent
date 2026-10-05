"""Prompt injection analysis — POST-RC-010.

Deterministic trust-transition rules: untrusted content reaching
a context the model consumes as instruction-like content, where
the agent can reach a privileged sink, is an injection SURFACE
hypothesis — never proof of successful hijacking.
"""

from __future__ import annotations

from typing import Any

UNTRUSTED_SOURCE_KINDS: tuple[str, ...] = (
    "repository", "issue", "pr-description", "commit-message",
    "documentation", "web-content", "database-content",
    "mcp-resource", "mcp-tool-result", "memory", "rag-content",
    "user-input",
)

PRIVILEGED_SINK_KINDS: tuple[str, ...] = (
    "tool-call", "mcp-call", "credential-use", "external-request",
    "data-export", "state-change", "subagent-delegation",
)


def analyze_prompt_injection(
    sources: tuple[Any, ...],
    sinks: tuple[Any, ...],
    *,
    privileged_tools: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Return injection-surface hypotheses from declared sources/sinks."""
    findings: list[dict[str, Any]] = []
    untrusted = [s for s in sources if getattr(s, "trust", "untrusted") == "untrusted" and getattr(s, "kind", "") in UNTRUSTED_SOURCE_KINDS]
    privileged = [t for t in sinks if getattr(t, "kind", "") in PRIVILEGED_SINK_KINDS]
    for source in sorted(untrusted, key=lambda s: getattr(s, "source_id", "")):
        for sink in sorted(privileged, key=lambda t: getattr(t, "sink_id", getattr(t, "tool_id", ""))):
            source_id = getattr(source, "source_id", "unknown-source")
            sink_id = getattr(sink, "sink_id", getattr(sink, "tool_id", "unknown-sink"))
            findings.append({
                "signal": "INJECTION_SURFACE",
                "source_id": source_id, "sink_id": sink_id,
                "detail": f"untrusted {getattr(source, 'kind', '?')} content may reach privileged {getattr(sink, 'kind', '?')}; instruction-like text here is a surface hypothesis, not proof of hijacking",
            })
    _ = privileged_tools
    return findings
