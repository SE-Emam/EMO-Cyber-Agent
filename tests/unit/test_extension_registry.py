"""POST-RC-014 — registry: versioned, isolated, observable, non-executing.

The registry stores *descriptions*: manifests, trust evaluations,
lifecycle and health. It never imports code, never decides a security
verdict on its own, and never lets rejected content appear at all —
while quarantine stays visible and non-resolvable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from emo_cyber_agent.extensions import (
    ExtensionError,
    ExtensionErrorCode,
    ExtensionHealth,
    ExtensionHealthStatus,
    ExtensionLifecycle,
    ExtensionLoader,
    ExtensionRegistry,
    ExtensionSourceClass,
    ExtensionTrustState,
    ExtensionType,
)
from emo_cyber_agent.extensions.discovery import discover_manifest_file

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"


def load_pair() -> ExtensionLoader:
    loader = ExtensionLoader(ExtensionRegistry())
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    loader.ingest_directory(THIRD, source_class=ExtensionSourceClass.THIRD_PARTY)
    return loader


def test_official_content_is_registered_loadable_and_trusted():
    loader = load_pair()
    entry = loader.registry.get("official-skill", "1.0.0")
    assert entry.trust.state is ExtensionTrustState.OFFICIAL_TRUSTED
    assert entry.lifecycle is ExtensionLifecycle.LOADABLE
    assert entry.trust.source_class is ExtensionSourceClass.OFFICIAL_EXTERNAL
    assert "official-publisher:emo-cyber-agent" in entry.trust.reasons


def test_third_party_content_starts_untrusted_and_not_loadable():
    loader = load_pair()
    entry = loader.registry.get("valid-third-party", "1.0.0")
    assert entry.trust.state is ExtensionTrustState.UNTRUSTED
    assert entry.lifecycle is ExtensionLifecycle.REGISTERED
    assert entry.lifecycle is not ExtensionLifecycle.LOADABLE


def test_two_versions_of_one_extension_coexist():
    loader = load_pair()
    registry = loader.registry
    assert registry.versions("valid-third-party") == ["1.0.0", "1.1.0"]
    assert registry.get("valid-third-party", "1.1.0").version == "1.1.0"
    with pytest.raises(ExtensionError) as exc:
        registry.get("valid-third-party", "2.0.0")
    assert exc.value.code is ExtensionErrorCode.NOT_FOUND


def test_quarantined_content_is_visible_but_never_loadable():
    loader = load_pair()
    registry = loader.registry
    entry = registry.get("incompatible-third-party", "1.0.0")
    assert entry.trust.state is ExtensionTrustState.QUARANTINED
    assert entry.lifecycle is ExtensionLifecycle.QUARANTINED
    assert entry.health.status is ExtensionHealthStatus.DEGRADED
    assert "quarantined" in entry.health.checks


def test_rejected_content_is_absent_from_the_registry_entirely():
    loader = load_pair()
    with pytest.raises(ExtensionError) as exc:
        loader.registry.get("malicious-third-party", "1.0.0")
    assert exc.value.code is ExtensionErrorCode.NOT_FOUND
    assert not any(
        entry.extension_id == "malicious-third-party" for entry in loader.registry.list()
    )


def test_rejection_is_still_observable_through_the_ingest_report():
    loader = ExtensionLoader(ExtensionRegistry())
    source = discover_manifest_file(THIRD / "malicious-third-party" / "manifest.extension.yaml")
    report = loader.ingest(source)
    assert report.registered is False
    assert report.trust_state == ExtensionTrustState.REJECTED.value
    assert report.reason.startswith("declaration-forbidden:")
    assert ExtensionLifecycle.REJECTED in report.trail


def test_list_by_type_is_exact():
    registry = load_pair().registry
    adapters = registry.list_by_type(ExtensionType.VERIFICATION_ADAPTER)
    assert {entry.extension_id for entry in adapters} == {
        "official-verification-adapter",
        "conflicting-third-party",
    }
    assert registry.list_by_type("no_such_type") == []


def test_provides_index_covers_declared_capabilities_and_features():
    registry = load_pair().registry
    index = registry.provides_index()
    assert "verification_adapter" in index
    assert "official-tool-pack@1.0.0" in index["tool_pack"]
    assert registry.provider_conflicts()


def test_health_and_provenance_are_read_only_projections():
    registry = load_pair().registry
    health = registry.get_health("official-tool-pack", "1.0.0")
    assert isinstance(health, ExtensionHealth)
    provenance = registry.get_provenance("official-tool-pack", "1.0.0")
    assert provenance.distribution_name == "official-tool-pack-extension"
    assert provenance.publisher_identity == "emo-cyber-agent"


def test_set_health_and_quarantine_are_host_side_transitions():
    loader = ExtensionLoader(ExtensionRegistry())
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    registry = loader.registry
    registry.set_health(
        "official-skill",
        "1.0.0",
        ExtensionHealth(status=ExtensionHealthStatus.DEGRADED, checks=("probe-failed",)),
    )
    assert registry.get_health("official-skill").status is ExtensionHealthStatus.DEGRADED
    entry = registry.quarantine("official-skill", "1.0.0", "host-pause")
    assert entry.lifecycle is ExtensionLifecycle.QUARANTINED
    # quarantined -> loadable is not an allowed transition
    with pytest.raises(ExtensionError) as exc:
        registry.advance("official-skill", "1.0.0", ExtensionLifecycle.LOADABLE)
    assert exc.value.code is ExtensionErrorCode.LIFECYCLE_INVALID


def test_unregister_removes_one_version_only():
    registry = load_pair().registry
    registry.unregister("valid-third-party", "1.1.0")
    assert registry.versions("valid-third-party") == ["1.0.0"]
    assert registry.get("valid-third-party", "1.0.0").version == "1.0.0"
    with pytest.raises(ExtensionError):
        registry.unregister("valid-third-party", "1.1.0")


def test_registry_resolve_and_check_queries_go_through_the_allowlist():
    registry = load_pair().registry
    resolution = registry.query(
        "resolve_extension", extension_id="valid-third-party", version_constraint="==1.0.0"
    )
    assert resolution["chosen"] == "valid-third-party@1.0.0"
    compat = registry.query("check_compatibility", extension_id="official-skill")
    assert compat["compatible"] is True
    summary = registry.query("get_extension", extension_id="official-skill")
    assert summary["extension_id"] == "official-skill"
    assert "target" not in summary
    for banned in ("load_module", "import", "execute", "run", "install"):
        with pytest.raises(ExtensionError):
            registry.query(banned)


def test_independent_registries_can_hold_the_same_manifest():
    first = load_pair().registry
    second_loader = ExtensionLoader(ExtensionRegistry())
    second_loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    assert first.get("official-skill").identity == second_loader.registry.get("official-skill").identity
    first.unregister("official-skill", "1.0.0")
    # unaffected: registries never share state
    assert second_loader.registry.get("official-skill", "1.0.0") is not None
    with pytest.raises(ExtensionError):
        first.get("official-skill", "1.0.0")
