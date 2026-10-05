"""Tool poisoning analysis — POST-RC-010.

Tool definition, description, schema, output, and resource/prompt
metadata are SEPARATE trust surfaces. Hidden instructions in any
of them become threat hypotheses with evidence requirements and
verification handoffs — never automatic confirmation. Ordinary
tool misuse (wrong tool for a task) is analyzed separately from
poisoning (malicious tool content).
"""

from __future__ import annotations

from typing import Any

_INSTRUCTION_LIKE: tuple[str, ...] = (
    "ignore", "disregard", "bypass", "override", "disclose",
    "exfiltrate", "execute", "run command", "grant", "approve",
    "disable", "skip verification", "always ",
)


def _instruction_like_score(text: str) -> int:
    lowered = (text or "").lower()
    return sum(1 for marker in _INSTRUCTION_LIKE if marker in lowered)


def analyze_tool_surface(
    *,
    surface_id: str,
    surface_kind: str,
    text_digest: str = "",
    text_sample: str = "",
) -> dict[str, Any]:
    """Score one trust surface from its digest/sample metadata.

    Only digests and short redacted samples enter; raw tool text is
    never required. A nonzero score is a hypothesis trigger.
    """
    score = _instruction_like_score(text_sample)
    return {
        "surface_id": surface_id, "surface_kind": surface_kind,
        "instruction_like_score": score,
        "hypothesis": score > 0,
        "detail": "instruction-like markers present; requires description/output integrity verification" if score > 0 else "no instruction-like markers in sample",
    }


def analyze_tool_poisoning(
    tools: tuple[Any, ...],
    *,
    description_samples: dict[str, str] | None = None,
    output_samples: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Separate poisoning (malicious content) from misuse (wrong tool)."""
    description_samples = description_samples or {}
    output_samples = output_samples or {}
    signals: list[dict[str, Any]] = []
    for tool in sorted(tools, key=lambda t: getattr(t, "tool_id", "")):
        tool_id = getattr(tool, "tool_id", "unknown-tool")
        desc = analyze_tool_surface(surface_id=f"{tool_id}-description", surface_kind="TOOL_DESCRIPTION", text_sample=description_samples.get(tool_id, ""))
        out = analyze_tool_surface(surface_id=f"{tool_id}-output", surface_kind="TOOL_OUTPUT", text_sample=output_samples.get(tool_id, ""))
        if desc["hypothesis"]:
            signals.append({"signal": "TOOL_POISONING", "tool_id": tool_id, "surface": "description", "detail": str(desc["detail"])})
        if out["hypothesis"]:
            signals.append({"signal": "TOOL_POISONING", "tool_id": tool_id, "surface": "output", "detail": str(out["detail"])})
    return signals


def analyze_tool_misuse(bindings: tuple[Any, ...], *, allowed: dict[str, tuple[str, ...]] | None = None) -> list[dict[str, Any]]:
    """Wrong-tool-for-task shapes. Content-independent; no poisoning claim."""
    allowed = allowed or {}
    signals: list[dict[str, Any]] = []
    for binding in sorted(bindings, key=lambda b: (getattr(b, "agent_id", ""), getattr(b, "tool_id", ""))):
        permitted = allowed.get(getattr(binding, "agent_id", ""), ())
        if permitted and getattr(binding, "tool_id", "") not in permitted:
            signals.append({"signal": "TOOL_MISUSE", "agent_id": getattr(binding, "agent_id", ""), "tool_id": getattr(binding, "tool_id", ""), "detail": "tool outside the agent's allowlisted set"})
    return signals
