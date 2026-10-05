"""Deterministic agent threat rules — POST-RC-010.

Pure functions over declared facts. Each rule emits scenario
seeds (category, subject, preconditions, goal, evidence needs,
limitations) — never verdicts, never severity. Rules are data-
driven hypotheses with explicit coverage notes.
"""

from __future__ import annotations

from typing import Any


def _slug(text: str) -> str:
    import re as _re

    return _re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:80] or "unnamed"


def rule_unprotected_state_changes(system: Any, surface: Any) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    stateful = [e for e in (getattr(surface, "elements", ()) or ()) if e.category == "STATE_CHANGE"]
    guarded = set()
    for boundary in getattr(system, "boundaries", ()) or ():
        guarded.update(boundary.protects)
    for element in sorted(stateful, key=lambda e: e.element_id):
        seeds.append({
            "category": "PRIVILEGE_ABUSE", "subject": element.element_id,
            "preconditions": ("state-changing surface reachable",),
            "attack_goal": f"invoke {element.element_id} outside authorization",
            "required_evidence": ("boundary-record", "entry-record"),
            "limitations": ("guard presence decided from recorded boundaries only",),
        })
    return seeds


def rule_untrusted_context_to_privileged_tool(system: Any) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    untrusted = [c for c in (getattr(system, "context_sources", ()) or ()) if getattr(c, "trust", "untrusted") == "untrusted"]
    tools = sorted(getattr(system, "mcp_tools", ()) or (), key=lambda t: t.tool_id)
    for source in sorted(untrusted, key=lambda s: s.source_id):
        for tool in tools:
            seeds.append({
                "category": "INDIRECT_PROMPT_INJECTION",
                "subject": f"{source.source_id}-to-{tool.tool_id}",
                "preconditions": (f"untrusted context {source.source_id} retrievable", f"tool {tool.tool_id} callable"),
                "attack_goal": f"influence tool {tool.tool_id} through context {source.source_id}",
                "required_evidence": ("context-record", "tool-record", "ingestion-record"),
                "limitations": ("influence is a surface hypothesis, not proof of hijacking",),
            })
    return seeds


def rule_credential_reach(system: Any) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    for flow in sorted(getattr(system, "credential_flows", ()) or (), key=lambda f: f.flow_id):
        seeds.append({
            "category": "CREDENTIAL_EXPOSURE", "subject": flow.flow_id,
            "preconditions": (f"credential flow {flow.flow_id} exists",),
            "attack_goal": f"observe credential material along {flow.flow_id}",
            "required_evidence": ("flow-record", "redaction-record", "boundary-record"),
            "limitations": ("material is referenced by digest only; exposure needs downstream proof",),
        })
    return seeds


def rule_delegation_widening(signals: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    for signal in sorted(signals, key=lambda s: (s.get("signal", ""), s.get("delegation_id", ""))):
        if signal.get("signal") in ("SCOPE_WIDENING", "PRIVILEGE_INHERITANCE", "UNSCOPED_DELEGATION"):
            seeds.append({
                "category": "INSECURE_DELEGATION", "subject": signal.get("delegation_id", "unknown-delegation"),
                "preconditions": (signal.get("detail", ""),),
                "attack_goal": "operate beyond the delegated scope",
                "required_evidence": ("delegation-record", "scope-record"),
                "limitations": ("declared metadata only; effective enforcement verified downstream",),
            })
    return seeds


def rule_memory_poisoning(signals: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    for signal in sorted(signals, key=lambda s: (s.get("signal", ""), s.get("source_id", ""))):
        if signal.get("signal") in ("MEMORY_POISONING", "CROSS_AUDIT_MEMORY", "CROSS_PROJECT_MEMORY"):
            seeds.append({
                "category": "MEMORY_POISONING", "subject": signal.get("source_id", signal.get("digest", "memory")),
                "preconditions": (signal.get("detail", ""),),
                "attack_goal": "persist attacker-influenced content into trusted context",
                "required_evidence": ("memory-record", "provenance-record"),
                "limitations": ("content is data; influence on decisions needs separate proof",),
            })
    return seeds


def rule_tool_poisoning(signals: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    for signal in sorted(signals, key=lambda s: (s.get("signal", ""), s.get("tool_id", ""))):
        if signal.get("signal") == "TOOL_POISONING":
            seeds.append({
                "category": "TOOL_POISONING", "subject": f"{signal.get('tool_id', 'tool')}-{signal.get('surface', 'surface')}",
                "preconditions": (signal.get("detail", ""),),
                "attack_goal": "steer agent behavior through poisoned tool content",
                "required_evidence": ("tool-record", "integrity-record"),
                "limitations": ("markers are heuristic; influence needs downstream proof",),
            })
    return seeds


def rule_scope_signals(signals: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    mapping = {"SCOPE_WIDENING": "SCOPE_CREEP", "EXCESSIVE_AGENCY": "EXCESSIVE_AGENCY"}
    seeds: list[dict[str, Any]] = []
    for signal in sorted(signals, key=lambda s: (s.get("signal", ""), str(s.get("detail", ""))[:80])):
        category = mapping.get(str(signal.get("signal", "")))
        if category is None:
            continue
        seeds.append({
            "category": category, "subject": signal.get("subject_id", "scope"),
            "preconditions": (signal.get("detail", ""),),
            "attack_goal": "operate beyond the declared scope",
            "required_evidence": ("scope-record", "capability-record"),
            "limitations": ("declared-vs-effective comparison only; enforcement verified downstream",),
        })
    return seeds


ALL_RULES: tuple[str, ...] = (
    "rule_unprotected_state_changes",
    "rule_untrusted_context_to_privileged_tool",
    "rule_credential_reach",
    "rule_delegation_widening",
    "rule_memory_poisoning",
    "rule_tool_poisoning",
    "rule_scope_signals",
)
