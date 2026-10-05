"""POST-RC-014 — compatibility is an explicit, deterministic contract.

No "latest compatible guess": the host profile and the manifest must
agree on API window, schema version, Python, platform, features,
entry-point contract major and the declared runtime profile — or the
extension is refused before anything is registered as loadable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from emo_cyber_agent.extensions import (
    CONTRACT_VERSION,
    SCHEMA_VERSION,
    CompatibilityResult,
    ExtensionLoader,
    ExtensionRegistry,
    ExtensionSourceClass,
    ExtensionValidator,
    HostProfile,
    check_compatibility,
    compute_manifest_digest,
    host_profile,
    load_manifest_file,
    python_satisfies,
    satisfies,
    supports_api,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"


def manifest(ext_id: str):
    return load_manifest_file(OFFICIAL / ext_id / "manifest.extension.yaml")


def redigest(m):
    """Re-bind the identity digest after a semantic edit (test helper)."""
    raw = m.model_dump(mode="json")
    raw.pop("digest", None)
    return m.model_copy(update={"digest": compute_manifest_digest(raw)})


# ---------------- constraint helpers ----------------

@pytest.mark.parametrize(
    ("version", "constraint", "expected"),
    [
        ("1.2.3", ">=1.0.0,<2.0.0", True),
        ("2.0.0", ">=1.0.0,<2.0.0", False),
        ("1.0.0", "", True),
        ("1.0.0", "*", True),
        ("1.0.0", "==1.0.0", True),
        ("1.0.1", "==1.0.0", False),
        ("1.5.0", "~=1.2", True),
        ("2.0.0", "~=1.2", False),
        ("1.0.0", "!=1.0.0", False),
        ("not-a-version", ">=1.0", False),
        ("1.0.0", "spin", False),
    ],
)
def test_satisfies_is_deterministic(version: str, constraint: str, expected: bool):
    assert satisfies(version, constraint) is expected


@pytest.mark.parametrize(
    ("current", "specifier", "expected"),
    [
        ("3.11.0", ">=3.11", True),
        ("3.10.0", ">=3.11", False),
        ("3.14.1", ">=3.11,<4", True),
        ("4.0.0", ">=3.11,<4", False),
        ("3.14.1", "", True),
        ("bad", ">=3.11", False),
    ],
)
def test_python_satisfies_subset(current: str, specifier: str, expected: bool):
    assert python_satisfies(current, specifier) is expected


def test_supports_api_honours_the_declared_window():
    m = manifest("official-skill")
    assert supports_api("1.0", m)
    assert supports_api("1.9", m)
    assert not supports_api("0.9", m)
    assert not supports_api("garbage", m)

    capped = m.model_copy(update={"compatibility": m.compatibility.model_copy(update={"emo_api_max": "1.4"})})
    assert supports_api("1.4", capped)
    assert not supports_api("1.5", capped)


def test_host_profile_is_supplied_not_self_declared():
    profile = HostProfile()
    assert profile.emo_api_version == "1.0"
    assert profile.schema_version == SCHEMA_VERSION
    assert profile.contract_version == CONTRACT_VERSION
    with pytest.raises(Exception):
        profile.emo_api_version = "9.9"  # frozen: type: ignore[misc]


# ---------------- full compatibility verdict ----------------

def test_official_extensions_are_compatible_with_the_current_host():
    current = host_profile()
    for path in sorted(OFFICIAL.rglob("*.extension.yaml")):
        result = check_compatibility(load_manifest_file(path), current)
        assert isinstance(result, CompatibilityResult)
        assert result.compatible, (path, result.reasons)
        assert "api-window" not in " ".join(result.reasons)


def test_host_below_the_api_window_is_refused_with_a_machine_reason():
    m = manifest("official-skill")
    result = check_compatibility(m, HostProfile(emo_api_version="0.1"))
    assert not result.compatible
    assert any(reason.startswith("api-window:needs>=1.0") for reason in result.reasons)


def test_python_platform_and_schema_disagreements_are_reported_individually():
    m = manifest("official-skill")

    python_host = HostProfile(python_version="3.9.0")
    result = check_compatibility(m, python_host)
    assert not result.compatible
    assert any(reason.startswith("python-not-satisfied:") for reason in result.reasons)

    platform_host = HostProfile(platform="plan9")
    result = check_compatibility(m, platform_host)
    assert not result.compatible
    assert any(reason.startswith("platform-unsupported:") for reason in result.reasons)

    schema_host = HostProfile(schema_version="9999")
    result = check_compatibility(m, schema_host)
    assert not result.compatible
    assert any(reason.startswith("schema-version-unsupported:") for reason in result.reasons)


def test_missing_required_feature_is_refused_not_ignored():
    m = manifest("official-skill")
    with_feature = m.model_copy(
        update={
            "compatibility": m.compatibility.model_copy(
                update={"required_features": ("CODEINTEL.DATA_FLOW",)}
            ),
            "requires": ("CODEINTEL.DATA_FLOW",),
        }
    )
    assert not check_compatibility(with_feature, HostProfile()).compatible
    assert not check_compatibility(
        with_feature, HostProfile(features=("SOMETHING.ELSE",))
    ).compatible
    assert check_compatibility(
        with_feature, HostProfile(features=("CODEINTEL.DATA_FLOW",))
    ).compatible


def test_feature_negotiation_never_grants_authority():
    m = manifest("official-skill")
    with_feature = redigest(
        m.model_copy(
            update={
                "compatibility": m.compatibility.model_copy(
                    update={"required_features": ("CODEINTEL.DATA_FLOW",)}
                ),
                "requires": ("CODEINTEL.DATA_FLOW",),
            }
        )
    )
    verdict = ExtensionValidator().validate(with_feature, raw=with_feature.model_dump(mode="json"))
    # declaring a feature requirement is data: it is not a capability claim
    assert verdict.valid, verdict.errors
    assert not verdict.authority_rejection
    assert with_feature.provides.declares == m.provides.declares


def test_entrypoint_contract_major_must_match_the_host():
    m = manifest("official-verification-adapter")
    assert m.entrypoint_metadata.kind.value == "implementation"
    assert check_compatibility(m, HostProfile()).compatible

    host = HostProfile()
    mismatched = m.model_copy(
        update={
            "entrypoint_metadata": m.entrypoint_metadata.model_copy(
                update={"contract": "verification-adapter.9"}
            )
        }
    )
    result = check_compatibility(mismatched, host)
    assert not result.compatible
    assert any(reason.startswith("contract-major-mismatch:") for reason in result.reasons)


def test_required_network_is_never_satisfied_during_loading():
    m = manifest("official-skill")
    demanding = m.model_copy(
        update={
            "security_metadata": m.security_metadata.model_copy(
                update={"declared_network": "required"}
            )
        }
    )
    result = check_compatibility(demanding, HostProfile())
    assert not result.compatible
    assert "runtime-incompatible:network=required is never satisfied during offline loading" in result.reasons


def test_requires_must_equal_required_features():
    m = manifest("official-skill")
    mismatched = m.model_copy(update={"requires": ("SOME.FEATURE",)})
    verdict = ExtensionValidator().validate(mismatched, raw=mismatched.model_dump(mode="json"))
    assert not verdict.valid
    assert "requires-mismatch:requires != compatibility.required_features" in verdict.errors


# ---------------- end-to-end: incompatible fixtures are quarantined ----------------

def test_incompatible_third_party_fixture_is_quarantined_not_loadable():
    loader = ExtensionLoader(ExtensionRegistry())
    reports = loader.ingest_directory(
        THIRD / "incompatible-third-party", source_class=ExtensionSourceClass.THIRD_PARTY
    )
    report = reports[0]
    assert report.compatibility is not None
    assert not report.compatibility.compatible
    assert report.trust_state == "quarantined"
    assert report.registered is True  # visible for inspection
    entry = loader.registry.get("incompatible-third-party", "1.0.0")
    assert entry.lifecycle.value == "quarantined"
    assert entry.health.status.value == "degraded"

    from emo_cyber_agent.extensions import ExtensionResolver, ResolutionRequest

    resolution = ExtensionResolver(loader.registry).resolve(
        ResolutionRequest(extension_id="incompatible-third-party")
    )
    assert not resolution.eligible
    assert any(note.startswith("lifecycle-not-loadable:") for note in resolution.notes)
