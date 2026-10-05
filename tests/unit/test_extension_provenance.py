"""POST-RC-014 — provenance answers where from, never may-it-be-trusted.

Provenance completeness, artifact digests and host verification evidence
are three separate things. A fully signed, fully attested third-party
extension is still ``untrusted`` until the *host* supplies verification
evidence; only official-source content with an allowlisted publisher
reaches ``official_trusted``.
"""

from __future__ import annotations

from pathlib import Path


from emo_cyber_agent.extensions import (
    ExtensionProvenance,
    ExtensionSourceClass,
    ExtensionTrustState,
    ProvenanceStatus,
    artifact_digest_of,
    assess_provenance,
    compute_manifest_digest,
    evaluate_trust,
    load_manifest_file,
    provenance_complete,
    provenance_digest,
    validate_manifest,
    verify_artifact_digest,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"


def redigest(m):
    """Re-bind the identity digest after a semantic edit (test helper)."""
    raw = m.model_dump(mode="json")
    raw.pop("digest", None)
    return m.model_copy(update={"digest": compute_manifest_digest(raw)})


def official(ext_id: str):
    return load_manifest_file(OFFICIAL / ext_id / "manifest.extension.yaml")


def third(ext_id: str):
    return load_manifest_file(THIRD / ext_id / "manifest.extension.yaml")


def verdict_for(manifest):
    return validate_manifest(manifest, raw=manifest.model_dump(mode="json"))


def empty_provenance(**overrides) -> ExtensionProvenance:
    base = {
        "distribution_name": "",
        "distribution_version": "",
        "artifact_digest": "",
        "source_url": "",
        "source_revision": "",
        "build_provenance": "",
        "publisher_identity": "",
        "released_at": "",
        "license": "",
        "dependency_provenance": (),
    }
    base.update(overrides)
    return ExtensionProvenance(**base)


# ---------------- digests ----------------

def test_artifact_digest_is_sha256_and_stable():
    digest = artifact_digest_of("payload")
    assert len(digest) == 64
    assert digest == artifact_digest_of("payload") == artifact_digest_of(b"payload")
    assert digest != artifact_digest_of("payload ")


def test_artifact_digest_comparison_fails_closed():
    digest = artifact_digest_of("payload")
    assert verify_artifact_digest(digest, digest)
    assert not verify_artifact_digest(digest, artifact_digest_of("tampered"))
    assert not verify_artifact_digest("", digest)
    assert not verify_artifact_digest(digest, "")
    assert not verify_artifact_digest(digest, digest[:-1])


def test_provenance_digest_is_deterministic_and_field_sensitive():
    manifest = official("official-tool-pack")
    first = provenance_digest(manifest.source_provenance)
    assert first == provenance_digest(manifest.source_provenance)
    changed = manifest.source_provenance.model_copy(update={"publisher_identity": "other"})
    assert provenance_digest(changed) != first


# ---------------- completeness classification ----------------

def test_missing_provenance_is_missing_not_partial():
    assessment = assess_provenance(empty_provenance())
    assert assessment.status is ProvenanceStatus.MISSING
    assert assessment.evidence == ()
    assert any(reason.startswith("missing:") for reason in assessment.reasons)
    assert not provenance_complete(assessment)


def test_partial_provenance_lists_every_gap():
    assessment = assess_provenance(empty_provenance(distribution_name="pkg"))
    assert assessment.status is ProvenanceStatus.PARTIAL
    assert assessment.evidence == ("distribution:pkg@?",)
    assert {"missing:distribution_version", "missing:publisher_identity"} <= set(assessment.reasons)
    assert not provenance_complete(assessment)


def test_complete_provenance_is_present_and_verifiable():
    manifest = official("official-tool-pack")
    assessment = assess_provenance(
        manifest.source_provenance, artifact=manifest.artifact_identity
    )
    assert assessment.status is ProvenanceStatus.PRESENT
    assert provenance_complete(assessment)
    assert "artifact-digest-recorded" in assessment.evidence
    assert "publisher:emo-cyber-agent" in assessment.evidence


def test_artifact_digest_verification_is_an_evidence_step_not_a_verdict():
    manifest = official("official-tool-pack")
    actual = manifest.artifact_identity.artifact_digest
    assert actual  # official fixtures carry a bound artifact digest
    verified = assess_provenance(
        manifest.source_provenance, artifact=manifest.artifact_identity, actual_digest=actual
    )
    assert "artifact-digest-verified" in verified.evidence

    tampered = assess_provenance(
        manifest.source_provenance,
        artifact=manifest.artifact_identity,
        actual_digest=artifact_digest_of("something else"),
    )
    assert "artifact-digest-mismatch" in tampered.reasons
    assert tampered.status is ProvenanceStatus.PARTIAL


def test_signature_and_attestation_metadata_are_evidence_not_trust():
    manifest = official("official-tool-pack")
    signed = manifest.artifact_identity.model_copy(
        update={
            "signature_metadata": {"alg": "ed25519", "signer": "vendor"},
            "attestation_metadata": {"predicate": "slsa"},
        }
    )
    assessment = assess_provenance(manifest.source_provenance, artifact=signed)
    assert "signature-metadata-present" in assessment.evidence
    assert "attestation-metadata-present" in assessment.evidence
    # complete provenance + signatures still does not authorize anything
    trust = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.THIRD_PARTY,
        validation=verdict_for(manifest),
        provenance=assessment,
    )
    assert trust.state is ExtensionTrustState.UNTRUSTED
    assert "external-content-starts-untrusted" in trust.reasons


# ---------------- trust inputs stay host-side ----------------

def test_third_party_with_complete_provenance_stays_untrusted_without_host_evidence():
    manifest = third("valid-third-party")
    assessment = assess_provenance(manifest.source_provenance)
    trust = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.THIRD_PARTY,
        validation=verdict_for(manifest),
        provenance=assessment,
    )
    assert trust.state is ExtensionTrustState.UNTRUSTED


def test_third_party_earns_verified_external_only_with_host_evidence():
    manifest = third("valid-third-party")
    assessment = assess_provenance(manifest.source_provenance, artifact=manifest.artifact_identity)
    trust = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.THIRD_PARTY,
        validation=verdict_for(manifest),
        provenance=assessment,
        verification=("signature-verified",),
    )
    assert trust.state is ExtensionTrustState.VERIFIED_EXTERNAL
    assert "host-verification-evidence" in trust.reasons
    assert "signature-verified" in trust.evidence
    assert trust.state.value in {"verified_external"}  # not official, not builtin


def test_unknown_verification_tokens_are_reported_and_never_grant_alone():
    manifest = third("valid-third-party")
    assessment = assess_provenance(manifest.source_provenance, artifact=manifest.artifact_identity)

    alone = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.THIRD_PARTY,
        validation=verdict_for(manifest),
        provenance=assessment,
        verification=("i-trust-this",),
    )
    assert alone.state is ExtensionTrustState.UNTRUSTED
    assert any(reason.startswith("verification-evidence-unknown:") for reason in alone.reasons)
    assert not any(reason == "host-verification-evidence" for reason in alone.reasons)

    mixed = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.THIRD_PARTY,
        validation=verdict_for(manifest),
        provenance=assessment,
        verification=("i-trust-this", "signature-verified"),
    )
    # the unknown token is still surfaced: the host must not lose the signal
    assert any(reason.startswith("verification-evidence-unknown:") for reason in mixed.reasons)
    assert "signature-verified" in mixed.evidence


def test_official_source_with_allowlisted_publisher_is_official_trusted():
    manifest = official("official-tool-pack")
    assessment = assess_provenance(manifest.source_provenance, artifact=manifest.artifact_identity)
    trust = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL,
        validation=verdict_for(manifest),
        provenance=assessment,
        verification=("publisher-verified",),
    )
    assert trust.state is ExtensionTrustState.OFFICIAL_TRUSTED
    assert "official-publisher:emo-cyber-agent" in trust.reasons
    assert "publisher-verified" in trust.evidence


def test_official_source_with_a_stranger_publisher_is_not_official():
    base = official("official-tool-pack")
    stranger = base.model_copy(
        update={
            "source_provenance": base.source_provenance.model_copy(
                update={"publisher_identity": "acme-labs"}
            )
        }
    )
    stranger = redigest(stranger)
    trust = evaluate_trust(
        stranger,
        source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL,
        validation=verdict_for(stranger),
        provenance=assess_provenance(stranger.source_provenance),
    )
    assert trust.state is ExtensionTrustState.UNTRUSTED
    assert "publisher-not-allowlisted:acme-labs" in trust.reasons


def test_builtin_source_needs_no_provenance():
    manifest = official("official-skill")
    trust = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.BUILTIN,
        validation=verdict_for(manifest),
    )
    assert trust.state is ExtensionTrustState.BUILTIN_TRUSTED
    assert "builtin-content" in trust.reasons


def test_holdout_dataset_records_its_classification_as_evidence():
    manifest = official("official-evaluation-dataset")
    assert manifest.dataset_classification.value == "holdout"
    trust = evaluate_trust(
        manifest,
        source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL,
        validation=verdict_for(manifest),
        provenance=assess_provenance(manifest.source_provenance),
    )
    assert "holdout-classification" in trust.evidence
    assert trust.state is ExtensionTrustState.OFFICIAL_TRUSTED


def test_artifact_fields_must_agree_across_identity_and_provenance():
    manifest = official("official-tool-pack")
    inconsistent = manifest.model_copy(
        update={
            "artifact_identity": manifest.artifact_identity.model_copy(
                update={"artifact_digest": "f" * 64}
            )
        }
    )
    verdict = validate_manifest(inconsistent, raw=inconsistent.model_dump(mode="json"))
    assert not verdict.valid
    assert "artifact-digest-inconsistent:artifact_identity vs source_provenance" in verdict.errors
