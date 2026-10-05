"""Regression comparison — POST-RC-011.

Structural before/after comparison with closed states. A missing
observation becomes DISAPPEARED or INDETERMINATE — never a Finding
transition. Current evidence always outranks history; history is
kept and labeled, never deleted by comparison.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.spec import (
    SecurityRegressionRecord,
)
from emo_cyber_agent.threat_modeling.spec import canonical_digest


def compare_regression(
    *,
    audit_id: str,
    project_id: str,
    regression_key: str,
    base_snapshot_id: str = "",
    target_snapshot_id: str = "",
    before_digest: str = "",
    after_digest: str = "",
    before_present: bool = True,
    after_present: bool = True,
    comparable: bool = True,
    coverage: str = "complete",
    prior_digests: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    provenance: Any = None,
) -> SecurityRegressionRecord:
    if not comparable:
        state = "NOT_COMPARABLE"
    elif before_present and not after_present:
        state = "DISAPPEARED" if coverage == "complete" else "INDETERMINATE"
    elif not before_present and after_present:
        if after_digest and after_digest in prior_digests:
            state = "REINTRODUCED"
        else:
            state = "NEW"
    elif before_digest == after_digest:
        state = "PERSISTING"
    else:
        state = "CHANGED"
    digest = canonical_digest({
        "audit": audit_id, "project": project_id, "key": regression_key,
        "base": base_snapshot_id, "target": target_snapshot_id,
        "before": before_digest, "after": after_digest, "state": state,
    })
    return SecurityRegressionRecord(
        regression_id=f"rg-{digest[:24]}", audit_id=audit_id, project_id=project_id,
        base_snapshot_id=base_snapshot_id, target_snapshot_id=target_snapshot_id,
        regression_key=regression_key, before_digest=before_digest, after_digest=after_digest,
        state=state, evidence_ids=tuple(evidence_ids), provenance=provenance, digest=digest,
    )


def evaluate_precedence(
    *,
    historical_digest: str,
    current_digest: str,
    historical_snapshot_id: str = "",
    current_snapshot_id: str = "",
) -> str:
    """Current evidence outranks history. History is labeled, not deleted."""
    if historical_snapshot_id and current_snapshot_id and historical_snapshot_id != current_snapshot_id:
        if not current_digest:
            return "STALE"
        if historical_digest and current_digest and historical_digest != current_digest:
            return "SUPERSEDED"
        return "STALE"
    if historical_digest and current_digest and historical_digest != current_digest:
        return "CONTRADICTED"
    return "CURRENT"


def evaluate_staleness(
    *,
    record_snapshot_id: str = "",
    record_schema_version: str = "1.0",
    current_snapshot_id: str = "",
    current_schema_version: str = "1.0",
    versions: dict[str, str] | None = None,
) -> str:
    """Deterministic staleness from snapshot and component versions."""
    versions = versions or {}
    mismatched = [k for k, v in versions.items() if v == "mismatch"]
    if mismatched:
        return "INCOMPATIBLE"
    unknown = [k for k, v in versions.items() if v == "unknown"]
    if unknown:
        return "UNKNOWN"
    if record_schema_version != current_schema_version:
        return "INCOMPATIBLE"
    if record_snapshot_id and current_snapshot_id and record_snapshot_id != current_snapshot_id:
        return "STALE"
    if not record_snapshot_id or not current_snapshot_id:
        return "UNKNOWN"
    return "FRESH_FOR_SCOPE"
