"""Change provenance — POST-RC-008.

Built by Core-owned code from comparison records, never from diff
text, commit messages, or source content. Those stay DATA.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_change_provenance(
    *,
    audit_id: str,
    project_id: str,
    base_snapshot_id: str,
    target_snapshot_id: str,
    source: str = "change-analysis",
    source_version: str = "1.0",
    changed_object: str = "",
    change_digest: str = "",
    coverage: str = "complete",
) -> dict[str, Any]:
    return {
        "source": source,
        "source_version": source_version,
        "audit_id": audit_id,
        "project_id": project_id,
        "base_snapshot_id": base_snapshot_id,
        "target_snapshot_id": target_snapshot_id,
        "changed_object": changed_object,
        "change_digest": change_digest,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "coverage": coverage,
    }
