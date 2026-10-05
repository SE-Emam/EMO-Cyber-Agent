"""STRIDE elicitation engine — POST-RC-009.

Deterministic per-element prompts over the system model: each
STRIDE category declares applicable subjects, and every emitted
candidate carries required evidence, limitations, and no severity.
STRIDE classification never produces severity, confirmation, or
priority — it only structures which questions get asked.
"""

from __future__ import annotations

from typing import Any

STRIDE_SPEC: dict[str, dict[str, Any]] = {
    "SPOOFING": {
        "applicable_subjects": ("entry",),
        "required_evidence": ("entry-record", "boundary-record"),
        "limitations": ("spoofing needs identity-proof evidence; entry presence alone proves nothing",),
    },
    "TAMPERING": {
        "applicable_subjects": ("entry", "flow"),
        "required_evidence": ("entry-record", "flow-record", "state-change-record"),
        "limitations": ("modification requires a demonstrated write path, not a graph edge",),
    },
    "REPUDIATION": {
        "applicable_subjects": ("entry",),
        "required_evidence": ("entry-record", "audit-control-record"),
        "limitations": ("absence of an observed audit control is a gap, not proof of deniability",),
    },
    "INFORMATION_DISCLOSURE": {
        "applicable_subjects": ("flow",),
        "required_evidence": ("flow-record", "boundary-crossing-record", "asset-record"),
        "limitations": ("exposure needs a demonstrated read path to an unauthorized party",),
    },
    "DENIAL_OF_SERVICE": {
        "applicable_subjects": ("entry",),
        "required_evidence": ("entry-record", "rate-control-record"),
        "limitations": ("exhaustion cannot be shown statically; public reachability is only a precondition",),
    },
    "ELEVATION_OF_PRIVILEGE": {
        "applicable_subjects": ("entry",),
        "required_evidence": ("entry-record", "boundary-record", "privilege-record"),
        "limitations": ("crossing needs a demonstrated privilege transition, not proximity",),
    },
}

_GOALS = {
    "SPOOFING": "assume another identity through the subject",
    "TAMPERING": "modify data or behavior through the subject",
    "REPUDIATION": "act through the subject without audit trace",
    "INFORMATION_DISCLOSURE": "read data through the subject beyond authorization",
    "DENIAL_OF_SERVICE": "exhaust resources through the subject",
    "ELEVATION_OF_PRIVILEGE": "cross a privilege boundary through the subject",
}


def elicit_stride(system: Any, *, categories: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """Deterministic elicitation. Returns candidate dicts (not scenarios)."""
    selected = [c for c in (categories or tuple(STRIDE_SPEC)) if c in STRIDE_SPEC]
    candidates: list[dict[str, Any]] = []
    entries = sorted(system.entries, key=lambda e: e.entry_id)
    flows = sorted(system.flows, key=lambda f: f.flow_id)
    for category in selected:
        spec = STRIDE_SPEC[category]
        if "entry" in spec["applicable_subjects"]:
            for entry in entries:
                if category == "DENIAL_OF_SERVICE" and not _is_public(entry):
                    continue
                candidates.append({
                    "method": "stride", "category": category, "subject": entry.entry_id,
                    "subject_kind": "entry",
                    "preconditions": (f"entry {entry.method} {entry.path} reachable",),
                    "attack_goal": _GOALS[category],
                    "required_evidence": tuple(spec["required_evidence"]),
                    "limitations": tuple(spec["limitations"]),
                })
        if "flow" in spec["applicable_subjects"]:
            for flow in flows:
                candidates.append({
                    "method": "stride", "category": category, "subject": flow.flow_id,
                    "subject_kind": "flow",
                    "preconditions": (f"flow {flow.source} -> {flow.target}",),
                    "attack_goal": _GOALS[category],
                    "required_evidence": tuple(spec["required_evidence"]),
                    "limitations": tuple(spec["limitations"]),
                })
    return candidates


def _is_public(entry: Any) -> bool:
    path = (entry.path or "").lower()
    return bool(path) and "admin" not in path and "internal" not in path
