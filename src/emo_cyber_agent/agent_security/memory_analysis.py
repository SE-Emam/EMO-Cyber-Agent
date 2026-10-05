"""Memory / RAG analysis — POST-RC-010.

Memory and retrieval are untrusted data sources. This module
detects poisoning shapes, stale authorization context,
cross-project contamination, cross-audit leakage, and
instruction-bearing content — as signals. No global security
memory is created here or anywhere in this task.
"""

from __future__ import annotations

from typing import Any

_INSTRUCTION_MARKERS: tuple[str, ...] = (
    "ignore", "disregard", "bypass", "always ", "permanently",
    "approved", "unrestricted", "exfiltrate", "disclose",
)


def _instruction_like(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _INSTRUCTION_MARKERS)


def check_memory_isolation(entries: tuple[Any, ...]) -> list[dict[str, Any]]:
    """Audit A memory must never appear in audit B context."""
    signals: list[dict[str, Any]] = []
    by_digest: dict[str, list[Any]] = {}
    for entry in entries:
        by_digest.setdefault(getattr(entry, "digest", ""), []).append(entry)
    for digest, group in sorted(by_digest.items()):
        audits = sorted({getattr(e, "audit_id", "") for e in group})
        projects = sorted({getattr(e, "project_id", "") for e in group})
        snapshots = sorted({getattr(e, "snapshot_id", "") for e in group})
        if len([a for a in audits if a]) > 1:
            signals.append({"signal": "CROSS_AUDIT_MEMORY", "digest": digest, "detail": f"same memory digest in audits: {','.join(audits)}"})
        if len([p for p in projects if p]) > 1:
            signals.append({"signal": "CROSS_PROJECT_MEMORY", "digest": digest, "detail": f"same memory digest in projects: {','.join(projects)}"})
        if len([s for s in snapshots if s]) > 1:
            signals.append({"signal": "CROSS_SNAPSHOT_MEMORY", "digest": digest, "detail": f"same memory digest across snapshots: {','.join(snapshots)}"})
    return signals


def analyze_retrieval_trust(
    sources: tuple[Any, ...],
    *,
    content_samples: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Retrieved content is data. Instruction-bearing samples are flagged."""
    content_samples = content_samples or {}
    signals: list[dict[str, Any]] = []
    for source in sorted(sources, key=lambda s: getattr(s, "source_id", "")):
        source_id = getattr(source, "source_id", "unknown-source")
        if getattr(source, "trust", "untrusted") != "untrusted":
            signals.append({"signal": "TRUSTED_RETRIEVAL_CLAIM", "source_id": source_id, "detail": "retrieval source claims non-untrusted status; treated as untrusted pending verification"})
        sample = content_samples.get(source_id, "")
        if sample and _instruction_like(sample):
            signals.append({"signal": "MEMORY_POISONING", "source_id": source_id, "detail": "instruction-bearing retrieved content; hypothesis only, not proof of poisoning"})
    return signals
