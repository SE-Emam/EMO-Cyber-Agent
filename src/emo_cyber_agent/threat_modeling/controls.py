"""Security controls — POST-RC-009.

Observed controls recorded from facts; expected controls derived
from threat categories; effectiveness NEVER decided here. A
control-looking construct is data until Verification says
otherwise — status stays OBSERVED/EXPECTED/UNVERIFIED.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.spec import ControlCoverage, SecurityControl

# Deterministic threat-category → relevant controls → evidence and
# verification requirements. Decides nothing about effectiveness.
CATEGORY_CONTROLS: dict[str, dict[str, tuple[str, ...]]] = {
    "SPOOFING": {"controls": ("AUTHENTICATION",), "evidence": ("boundary-record", "identity-record"), "verification": ("static_confirmation",)},
    "TAMPERING": {"controls": ("AUTHORIZATION", "VALIDATION", "AUDITING"), "evidence": ("boundary-record", "flow-record"), "verification": ("static_confirmation",)},
    "REPUDIATION": {"controls": ("AUDITING",), "evidence": ("audit-control-record",), "verification": ("static_confirmation",)},
    "INFORMATION_DISCLOSURE": {"controls": ("AUTHORIZATION", "ENCRYPTION", "OUTPUT_ENCODING"), "evidence": ("flow-record", "asset-record"), "verification": ("static_confirmation",)},
    "DENIAL_OF_SERVICE": {"controls": ("RATE_LIMITING", "NETWORK_ISOLATION"), "evidence": ("entry-record", "rate-control-record"), "verification": ("static_confirmation",)},
    "ELEVATION_OF_PRIVILEGE": {"controls": ("AUTHORIZATION", "AUDITING"), "evidence": ("boundary-record", "privilege-record"), "verification": ("static_confirmation",)},
}

_BOUNDARY_TO_CONTROL = {
    "decorator": "AUTHORIZATION",
    "middleware": "AUTHORIZATION",
    "policy-check": "AUTHORIZATION",
    "role-check": "AUTHORIZATION",
    "ownership-check": "AUTHORIZATION",
    "tenant-check": "AUTHORIZATION",
    "rls": "AUTHORIZATION",
    "login": "AUTHENTICATION",
    "session": "AUTHENTICATION",
    "token": "AUTHENTICATION",
    "mfa": "AUTHENTICATION",
}


def observe_controls(code_graph: Any) -> list[SecurityControl]:
    """Record observed control-looking constructs. Presence only."""
    controls: list[SecurityControl] = []
    if code_graph is None:
        return controls
    import re as _re

    for bid, boundary in sorted((getattr(code_graph, "boundaries", {}) or {}).items()):
        slug = _re.sub(r"[^a-z0-9]+", "-", bid.lower()).strip("-") or "boundary"
        mechanism = (boundary.mechanism or "").lower()
        kind = "AUTHORIZATION"
        for hint, mapped in sorted(_BOUNDARY_TO_CONTROL.items()):
            if hint in mechanism or hint in bid.lower():
                kind = mapped
                break
        controls.append(SecurityControl(
            control_id=f"control-{slug}", kind=kind, status="OBSERVED_CONTROL",
            protects=(boundary.protects_id,) if boundary.protects_id else (),
            provenance={"code_boundary_id": bid, "mechanism": boundary.mechanism},
        ))
    return controls


def expected_controls(categories: tuple[str, ...]) -> list[SecurityControl]:
    controls: list[SecurityControl] = []
    for category in sorted(set(categories)):
        for kind in CATEGORY_CONTROLS.get(category, {}).get("controls", ()):
            cid = f"expected-{category.lower().replace('_', '-')}-{kind.lower().replace('_', '-')}"
            if any(c.control_id == cid for c in controls):
                continue
            controls.append(SecurityControl(control_id=cid, kind=kind, status="EXPECTED_CONTROL", provenance={"derived_from": category}))
    return controls


def coverage_for(category: str) -> ControlCoverage:
    spec = CATEGORY_CONTROLS.get(category, {"controls": (), "evidence": (), "verification": ()})
    return ControlCoverage(
        category=category, relevant_controls=tuple(f"expected-{category.lower().replace('_', '-')}-{c.lower().replace('_', '-')}" for c in spec["controls"]),
        evidence_requirements=tuple(spec["evidence"]), verification_requirements=tuple(spec["verification"]),
    )
