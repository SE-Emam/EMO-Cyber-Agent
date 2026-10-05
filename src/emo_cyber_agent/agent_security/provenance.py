"""Agent security provenance — POST-RC-010.

Built by Core-owned code from analysis records, never from agent
config text, tool descriptions, memory content, or model
suggestions. Those stay DATA.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_agent_provenance(
    *,
    audit_id: str,
    project_id: str,
    snapshot_id: str,
    source: str = "agent-security",
    source_version: str = "1.0",
    subject_id: str = "",
    model_digest: str = "",
    coverage: str = "complete",
) -> dict[str, Any]:
    return {
        "source": source,
        "source_version": source_version,
        "audit_id": audit_id,
        "project_id": project_id,
        "snapshot_id": snapshot_id,
        "subject_id": subject_id,
        "model_digest": model_digest,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "coverage": coverage,
    }
