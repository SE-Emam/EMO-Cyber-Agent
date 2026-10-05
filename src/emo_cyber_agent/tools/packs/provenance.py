"""Tool provenance — POST-RC-007.

Every normalized result carries complete, forgery-proof provenance:
built by Core-owned code from execution records, never from tool
output. Tool output strings are DATA and never enter provenance.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def build_tool_provenance(
    *,
    tool_id: str,
    tool_version: str,
    adapter: str,
    pack_id: str,
    pack_version: str,
    invocation_id: str,
    audit_id: str,
    project_id: str,
    snapshot_id: str,
    argv_digest: str,
    raw_digest: str,
    policy_version: str,
    network: str = "network_none",
    coverage: str = "complete",
    limitations: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "source": tool_id,
        "tool_version": tool_version,
        "adapter": adapter,
        "pack_id": pack_id,
        "pack_version": pack_version,
        "invocation_id": invocation_id,
        "audit_id": audit_id,
        "project_id": project_id,
        "snapshot_id": snapshot_id,
        "argv_digest": argv_digest,
        "raw_digest": raw_digest,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": policy_version,
        "network": network,
        "coverage": coverage,
        "limitations": list(limitations),
    }
