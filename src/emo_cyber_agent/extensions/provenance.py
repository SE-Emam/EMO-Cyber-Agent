"""Extension provenance — POST-RC-014.

Provenance answers *where did this artifact come from and how was it
built*. It never answers *may this extension be trusted*: a signed,
published artifact is still an untrusted extension until the trust
process says otherwise. SLSA-style provenance is used as a design
principle — verifiable links from artifact to source — without making
any attestation format a hard dependency here.

Cryptographic verification is deliberately optional, separated from
basic metadata parsing, and never implemented by extension-loaded code.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.spec import (
    ExtensionArtifact,
    ExtensionProvenance,
    ProvenanceStatus,
    manifest_identity_digest,
)

__all__ = [
    "ProvenanceAssessment",
    "artifact_digest_of",
    "assess_provenance",
    "provenance_digest",
    "verify_artifact_digest",
]


class ProvenanceAssessment(BaseModel):
    """How complete the provenance record is. Never a trust verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ProvenanceStatus = ProvenanceStatus.MISSING
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    evidence: tuple[str, ...] = Field(default_factory=tuple)


def artifact_digest_of(data: str | bytes) -> str:
    """SHA-256 over bytes. Used by hosts, never by manifest self-claims."""
    payload = data.encode("utf-8", errors="replace") if isinstance(data, str) else bytes(data)
    return hashlib.sha256(payload).hexdigest()


def verify_artifact_digest(declared: str, actual: str) -> bool:
    """Constant-time-ish comparison of two hex digests.

    Optional: metadata parsing works without it, and no extension code
    participates in the comparison."""
    if not declared or not actual:
        return False
    if len(declared) != len(actual):
        return False
    result = 0
    for left, right in zip(declared, actual):
        result |= ord(left) ^ ord(right)
    return result == 0


def provenance_digest(provenance: ExtensionProvenance) -> str:
    """Deterministic digest of the provenance record itself."""
    return manifest_identity_digest(provenance.model_dump(mode="json"))


def assess_provenance(
    provenance: ExtensionProvenance,
    *,
    artifact: ExtensionArtifact | None = None,
    actual_digest: str = "",
) -> ProvenanceAssessment:
    """Classify how much provenance exists (missing/partial/present).

    Signature and attestation metadata count as *evidence present*, never
    as *verified*: verification is an optional, host-run step."""
    reasons: list[str] = []
    evidence: list[str] = []

    if not provenance.distribution_name:
        reasons.append("missing:distribution_name")
    if not provenance.distribution_version:
        reasons.append("missing:distribution_version")
    if not provenance.publisher_identity:
        reasons.append("missing:publisher_identity")
    if not provenance.source_revision and not provenance.source_url:
        reasons.append("missing:source_reference")
    if not provenance.license:
        reasons.append("missing:license")

    if provenance.distribution_name:
        evidence.append(f"distribution:{provenance.distribution_name}@{provenance.distribution_version or '?'}")
    if provenance.publisher_identity:
        evidence.append(f"publisher:{provenance.publisher_identity}")
    if provenance.source_revision:
        evidence.append(f"revision:{provenance.source_revision}")
    if provenance.build_provenance:
        evidence.append("build-provenance-recorded")
    for item in provenance.dependency_provenance:
        evidence.append(f"dependency:{item}")

    if artifact is not None:
        if artifact.artifact_digest:
            evidence.append("artifact-digest-recorded")
        if artifact.manifest_digest:
            evidence.append("manifest-digest-recorded")
        if artifact.signature_metadata:
            evidence.append("signature-metadata-present")
        if artifact.attestation_metadata:
            evidence.append("attestation-metadata-present")

    if actual_digest and provenance.artifact_digest:
        if verify_artifact_digest(provenance.artifact_digest, actual_digest):
            evidence.append("artifact-digest-verified")
        else:
            reasons.append("artifact-digest-mismatch")

    if not evidence:
        status = ProvenanceStatus.MISSING
    elif reasons:
        status = ProvenanceStatus.PARTIAL
    else:
        status = ProvenanceStatus.PRESENT

    return ProvenanceAssessment(status=status, reasons=tuple(reasons), evidence=tuple(evidence))
