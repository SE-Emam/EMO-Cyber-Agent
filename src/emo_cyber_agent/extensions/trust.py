"""Extension trust model — POST-RC-014.

Trust is a *host evaluation outcome*, never a manifest field. The rules
are deliberately boring:

* built-in content is trusted because Core ships it;
* official external content is trusted only when the publisher identity
  is on the host-maintained allowlist;
* third-party and local content starts ``UNTRUSTED`` — and stays there
  until a *host* verification process supplies evidence;
* anything failing validation, compatibility, dependency or provenance
  gates is ``QUARANTINED`` or ``REJECTED``, never merely downgraded.

No path here reads a trust value out of a manifest: the manifest model
does not even have such a field (``extra="forbid"``), and raw documents
that try are refused as authority declarations before evaluation starts.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.extensions.provenance import ProvenanceAssessment
from emo_cyber_agent.extensions.spec import (
    TRUSTED_STATES,
    ExtensionManifest,
    ExtensionSourceClass,
    ExtensionTrust,
    ExtensionTrustState,
)
from emo_cyber_agent.extensions.validator import ExtensionValidation

__all__ = [
    "OFFICIAL_PUBLISHERS",
    "TrustInputs",
    "evaluate_trust",
    "provenance_complete",
    "trust_allows_load",
    "trust_allows_registration",
]

#: Host-maintained allowlist. Adding a publisher is a host decision.
OFFICIAL_PUBLISHERS: frozenset[str] = frozenset(
    {
        "emo-cyber-agent",
        "emo-security",
        "emo-official",
    }
)

#: Evidence tokens a host verification process may supply. Their meaning
#: is fixed by this module, never by the extension under evaluation.
_VERIFICATION_EVIDENCE: frozenset[str] = frozenset(
    {
        "artifact-digest-verified",
        "signature-verified",
        "attestation-verified",
        "publisher-verified",
    }
)


class TrustInputs(BaseModel):
    """Everything the trust process considers. All host-side."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_class: ExtensionSourceClass
    validation: ExtensionValidation
    compatibility_ok: bool = True
    provenance: ProvenanceAssessment | None = None
    verification: tuple[str, ...] = Field(default_factory=tuple)
    official_publishers: tuple[str, ...] = tuple(sorted(OFFICIAL_PUBLISHERS))


def evaluate_trust(
    manifest: ExtensionManifest,
    *,
    source_class: ExtensionSourceClass,
    validation: ExtensionValidation,
    compatibility_ok: bool = True,
    provenance: ProvenanceAssessment | None = None,
    verification: tuple[str, ...] = (),
    official_publishers: tuple[str, ...] | None = None,
) -> ExtensionTrust:
    """Deterministic trust evaluation. Same inputs → same state."""
    inputs = TrustInputs(
        source_class=source_class,
        validation=validation,
        compatibility_ok=compatibility_ok,
        provenance=provenance,
        verification=tuple(sorted(set(verification))),
        official_publishers=official_publishers or tuple(sorted(OFFICIAL_PUBLISHERS)),
    )
    return _evaluate(manifest, inputs)


def _evaluate(manifest: ExtensionManifest, inputs: TrustInputs) -> ExtensionTrust:
    reasons: list[str] = []
    evidence: list[str] = list(inputs.provenance.evidence) if inputs.provenance else []

    if not inputs.validation.valid:
        if inputs.validation.authority_rejection:
            return ExtensionTrust(
                state=ExtensionTrustState.REJECTED,
                source_class=inputs.source_class,
                reasons=tuple(["authority-declaration", *inputs.validation.errors[:4]]),
                evidence=tuple(evidence),
            )
        return ExtensionTrust(
            state=ExtensionTrustState.QUARANTINED,
            source_class=inputs.source_class,
            reasons=tuple(["validation-failed", *inputs.validation.errors[:4]]),
            evidence=tuple(evidence),
        )

    if not inputs.compatibility_ok:
        return ExtensionTrust(
            state=ExtensionTrustState.QUARANTINED,
            source_class=inputs.source_class,
            reasons=("incompatible-with-host",),
            evidence=tuple(evidence),
        )

    accepted = [item for item in inputs.verification if item in _VERIFICATION_EVIDENCE]
    unknown = [item for item in inputs.verification if item not in _VERIFICATION_EVIDENCE]
    if unknown:
        reasons.append(f"verification-evidence-unknown:{','.join(sorted(unknown))}")
    if accepted:
        evidence.extend(sorted(accepted))

    if inputs.source_class is ExtensionSourceClass.BUILTIN:
        state = ExtensionTrustState.BUILTIN_TRUSTED
        reasons.append("builtin-content")
    elif inputs.source_class is ExtensionSourceClass.OFFICIAL_EXTERNAL:
        publisher = manifest.source_provenance.publisher_identity
        if publisher and publisher in inputs.official_publishers:
            state = ExtensionTrustState.OFFICIAL_TRUSTED
            reasons.append(f"official-publisher:{publisher}")
        else:
            state = ExtensionTrustState.UNTRUSTED
            reasons.append(f"publisher-not-allowlisted:{publisher or 'unset'}")
    else:
        if accepted and provenance_complete(inputs.provenance):
            state = ExtensionTrustState.VERIFIED_EXTERNAL
            reasons.append("host-verification-evidence")
        else:
            state = ExtensionTrustState.UNTRUSTED
            reasons.append("external-content-starts-untrusted")
            if not provenance_complete(inputs.provenance):
                reasons.append("provenance-incomplete")

    if manifest.dataset_classification.value == "holdout":
        evidence.append("holdout-classification")
    if manifest.dataset_classification.value == "blind":
        evidence.append("blind-classification")

    return ExtensionTrust(
        state=state,
        source_class=inputs.source_class,
        reasons=tuple(dict.fromkeys(reasons)),
        evidence=tuple(dict.fromkeys(evidence)),
    )


def provenance_complete(provenance: ProvenanceAssessment | None) -> bool:
    """Host-side convenience: a present (not merely partial) record."""
    from emo_cyber_agent.extensions.spec import ProvenanceStatus

    return provenance is not None and provenance.status is ProvenanceStatus.PRESENT


def trust_allows_registration(trust: ExtensionTrust) -> bool:
    """Registry admits everything except rejected content (fail-closed)."""
    return trust.state is not ExtensionTrustState.REJECTED


def trust_allows_load(trust: ExtensionTrust) -> bool:
    """Only host-evaluated trusted states may ever be loaded."""
    return trust.state.value in TRUSTED_STATES
