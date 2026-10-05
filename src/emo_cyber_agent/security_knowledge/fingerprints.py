"""Canonical fingerprinting — POST-RC-011.

Identity digests built only from stable security-identity
components. Wall-clock, random IDs, message ordering, stdout
formatting, report formatting, and model wording never enter
identity. Three semantics with explicit, different scope rules:
SNAPSHOT_IDENTITY (one snapshot), STRUCTURAL_IDENTITY
(snapshot-agnostic structure), REGRESSION_IDENTITY (comparison
across two snapshots).
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.spec import canonical_digest


def snapshot_identity(
    *,
    project_id: str,
    object_type: str,
    object_identity: str,
    snapshot_id: str,
    source: str,
    security_property: str,
    facts: dict[str, Any] | None = None,
) -> str:
    return canonical_digest({
        "kind": "SNAPSHOT_IDENTITY",
        "project": project_id, "object_type": object_type, "object_identity": object_identity,
        "snapshot": snapshot_id, "source": source, "property": security_property,
        "facts": facts or {},
    })


def structural_identity(
    *,
    project_id: str,
    object_type: str,
    object_identity: str,
    source: str,
    security_property: str,
    facts: dict[str, Any] | None = None,
) -> str:
    return canonical_digest({
        "kind": "STRUCTURAL_IDENTITY",
        "project": project_id, "object_type": object_type, "object_identity": object_identity,
        "source": source, "property": security_property,
        "facts": facts or {},
    })


def regression_identity(
    *,
    project_id: str,
    object_type: str,
    object_identity: str,
    base_snapshot_id: str,
    target_snapshot_id: str,
    source: str,
    security_property: str,
    facts: dict[str, Any] | None = None,
) -> str:
    return canonical_digest({
        "kind": "REGRESSION_IDENTITY",
        "project": project_id, "object_type": object_type, "object_identity": object_identity,
        "base": base_snapshot_id, "target": target_snapshot_id,
        "source": source, "property": security_property,
        "facts": facts or {},
    })


def regression_key_for(
    *,
    object_type: str,
    object_identity: str,
    security_property: str,
) -> str:
    """Normalized structural regression key (human-stable, not a digest)."""
    import re as _re

    parts = [_re.sub(r"[^a-z0-9]+", "-", str(p).lower()).strip("-") or "unknown" for p in (object_type, object_identity, security_property)]
    return "regression:" + ":".join(parts)


def route_property_key(route: str, security_property: str) -> str:
    return regression_key_for(object_type="route", object_identity=route, security_property=security_property)


def symbol_sink_key(symbol: str, sink: str, security_property: str = "dataflow") -> str:
    return regression_key_for(object_type="symbol-sink", object_identity=f"{symbol}->{sink}", security_property=security_property)


def package_property_key(package: str, security_property: str) -> str:
    return regression_key_for(object_type="package", object_identity=package, security_property=security_property)


def tool_capability_key(tool: str, capability: str) -> str:
    return regression_key_for(object_type="tool-capability", object_identity=f"{tool}->{capability}", security_property="capability")


def boundary_relation_key(boundary: str, relation: str) -> str:
    return regression_key_for(object_type="boundary-relation", object_identity=f"{boundary}->{relation}", security_property="trust")


def asset_control_key(asset: str, control: str) -> str:
    return regression_key_for(object_type="asset-control", object_identity=f"{asset}->{control}", security_property="control")
