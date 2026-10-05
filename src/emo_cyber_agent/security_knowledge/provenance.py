"""Knowledge provenance — POST-RC-011.

Complete, traceable chains: origin → collector → normalization →
evidence → knowledge record → regression comparison. Provenance
documents history; it never proves content correctness by itself.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.spec import KnowledgeProvenance


def build_knowledge_provenance(
    *,
    origin: str,
    collector: str = "",
    normalization_version: str = "1.0",
    schema_version: str = "1.0",
    evidence_ids: tuple[str, ...] = (),
    parent_digests: tuple[str, ...] = (),
) -> KnowledgeProvenance:
    return KnowledgeProvenance(
        origin=origin, collector=collector, normalization_version=normalization_version,
        schema_version=schema_version, evidence_ids=tuple(evidence_ids),
        parent_digests=tuple(parent_digests),
    )


def extend_provenance(provenance: KnowledgeProvenance, *, parent_digest: str) -> KnowledgeProvenance:
    return provenance.model_copy(update={"parent_digests": (*provenance.parent_digests, parent_digest)})


def trace_chain(record: Any) -> list[str]:
    """Human-readable origin chain for audit display."""
    provenance = getattr(record, "provenance", None)
    if provenance is None:
        return []
    chain = [f"origin:{provenance.origin}"]
    if provenance.collector:
        chain.append(f"collector:{provenance.collector}")
    chain.append(f"normalization:{provenance.normalization_version}")
    chain.extend(f"evidence:{eid}" for eid in provenance.evidence_ids)
    chain.extend(f"parent:{digest[:16]}" for digest in provenance.parent_digests)
    return chain
