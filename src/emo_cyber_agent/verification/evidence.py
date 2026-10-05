"""Verification evidence — POST-RC-012.

Normalized, provenance-carrying evidence produced by every
verification outcome. Content is redacted and summarized: raw
sensitive output never persists, and no result can rewrite the
source it came from.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.threat_modeling.spec import canonical_digest
from emo_cyber_agent.verification.errors import StrategyError, StrategyErrorCode

EVIDENCE_SCHEMA_VERSION = "1.0"


class EvidenceOracle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str
    subject: str
    operator: str
    expected: str = ""
    assertion: str = ""
    outcome: str = Field(..., min_length=1, max_length=40)
    reason_code: str = Field(default="", max_length=80)


class EvidenceCriteria(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    success: str = Field(..., min_length=1, max_length=500)
    refutation: str = Field(..., min_length=1, max_length=500)


class VerificationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str = Field(..., min_length=1, max_length=120)
    strategy_id: str = Field(..., min_length=1, max_length=80)
    strategy_version: str = Field(..., min_length=1, max_length=40)
    adapter_id: str = Field(default="", max_length=80)
    adapter_version: str = Field(default="", max_length=40)
    target_kind: str = Field(..., min_length=1, max_length=60)
    target_identity: str = Field(..., min_length=1, max_length=400)
    snapshot_id: str = Field(..., min_length=1, max_length=160)
    audit_id: str = Field(..., min_length=1, max_length=120)
    project_id: str = Field(..., min_length=1, max_length=200)
    observed_result: str = Field(default="", max_length=500)
    oracle: EvidenceOracle
    criteria: EvidenceCriteria
    provenance: dict[str, Any] = Field(default_factory=dict)
    coverage: str = Field(default="complete", max_length=24)
    limitations: tuple[str, ...] = ()
    data_flags: tuple[str, ...] = ()
    schema_version: str = Field(default=EVIDENCE_SCHEMA_VERSION, max_length=40)
    digest: str = Field(default="", max_length=128)

    @field_validator("coverage")
    @classmethod
    def _coverage(cls, v: str) -> str:
        if v not in ("complete", "partial", "limited", "unknown"):
            raise ValueError(f"coverage not allowed: {v}")
        return v

    def model_post_init(self, __context: Any, /) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", canonical_digest(self.model_dump(mode="json", exclude={"digest"})))


def build_evidence(
    *,
    verification_id: str,
    strategy_id: str,
    strategy_version: str,
    adapter_id: str,
    adapter_version: str,
    target_kind: str,
    target_identity: str,
    snapshot_id: str,
    audit_id: str,
    project_id: str,
    observed: str,
    oracle: EvidenceOracle,
    criteria: EvidenceCriteria,
    coverage: str = "complete",
    limitations: tuple[str, ...] = (),
    data_flags: tuple[str, ...] = (),
    provenance: dict[str, Any] | None = None,
) -> VerificationEvidence:
    """Atomic build: redact, bound, digest. Sensitive output is
    replaced and the replacement is recorded as a limitation."""
    from emo_cyber_agent.core.repository import redact_credentials

    text = observed or ""
    clean = redact_credentials(text)[:500]
    notes = list(limitations)
    if (clean != text[: len(clean)] or (text and redact_credentials(text) != text)) and redact_credentials(text) != text:
        notes.append("sensitive-output-redacted")
        clean = redact_credentials(text)[:500]
    if not audit_id or not project_id or not snapshot_id:
        raise StrategyError(StrategyErrorCode.SCOPE_DENIED, "evidence requires audit, project, and snapshot identity")
    try:
        return VerificationEvidence(
            verification_id=verification_id, strategy_id=strategy_id, strategy_version=strategy_version,
            adapter_id=adapter_id, adapter_version=adapter_version,
            target_kind=target_kind, target_identity=target_identity,
            snapshot_id=snapshot_id, audit_id=audit_id, project_id=project_id,
            observed_result=clean, oracle=oracle, criteria=criteria,
            provenance=dict(provenance or {}), coverage=coverage,
            limitations=tuple(dict.fromkeys(notes)), data_flags=tuple(data_flags),
        )
    except ValueError as e:
        raise StrategyError(StrategyErrorCode.NO_EVIDENCE, str(e)) from e


def to_evidence_item(evidence: VerificationEvidence, *, asset_id: str | None = None) -> Any:
    """Project into the shared core EvidenceItem (store-facing)."""
    from emo_cyber_agent.domain.models import EvidenceItem

    return EvidenceItem(
        source_tool=f"verification:{evidence.strategy_id}",
        source_version=evidence.strategy_version,
        target_asset_id=asset_id,
        location=f"{evidence.target_kind}:{evidence.target_identity}",
        content_hash=evidence.digest[:64],
        content_summary=f"[{evidence.oracle.outcome}] {evidence.observed_result or 'no observation'}"[:500],
        provenance={
            "verification_id": evidence.verification_id,
            "strategy": f"{evidence.strategy_id}@{evidence.strategy_version}",
            "adapter": f"{evidence.adapter_id}@{evidence.adapter_version}" if evidence.adapter_id else "",
            "snapshot_id": evidence.snapshot_id,
            "coverage": evidence.coverage,
            "limitations": list(evidence.limitations),
            "labels": ("verification-evidence",),
        },
    )


def historical_label(*, evidence_snapshot_id: str, current_snapshot_id: str) -> str:
    """verified@N stays historical context until re-run on the current
    target. Nothing is relabelled by reuse."""
    if not evidence_snapshot_id or not current_snapshot_id:
        return "UNKNOWN"
    return "CURRENT" if evidence_snapshot_id == current_snapshot_id else "HISTORICAL"
