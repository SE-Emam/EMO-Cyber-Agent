"""POST-RC-014 — extension spec, manifest, validation, registry, resolver.

Unit-level contract tests: closed vocabularies, frozen models, digest
binding, authority scanning, fail-closed queries and deterministic
resolution. Hostile-content handling lives in the discovery and
adversarial files; this file proves the contracts themselves.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from emo_cyber_agent.extensions import (
    ALLOWED_TRANSITIONS,
    DECLARATIVE_TYPES,
    DatasetClassification,
    EXECUTABLE_TYPES,
    EXTENSION_API_VERSION,
    ExtensionDeclaredCapability,
    ExtensionEntrypointKind,
    ExtensionError,
    ExtensionErrorCode,
    ExtensionLifecycle,
    ExtensionLoader,
    ExtensionManifest,
    ExtensionRegistry,
    ExtensionResolver,
    ExtensionSourceClass,
    ExtensionTrustState,
    ExtensionType,
    FORBIDDEN_DECLARATIONS,
    READ_ACTIONS,
    ResolutionRequest,
    TRUSTED_STATES,
    VersionPolicy,
    compute_manifest_digest,
    evaluate_trust,
    find_self_declared_trust,
    flag_authority_language,
    load_manifest_file,
    manifest_from_dict,
    satisfies,
    validate_manifest,
)
from emo_cyber_agent.extensions.discovery import discover_manifest_file

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"
TEMPLATE = ROOT.parent / "templates" / "extensions" / "EXTENSION-MANIFEST-TEMPLATE.yaml"


def official(ext_id: str) -> ExtensionManifest:
    return load_manifest_file(OFFICIAL / ext_id / "manifest.extension.yaml")


def raw_of(manifest: ExtensionManifest) -> dict:
    return manifest.model_dump(mode="json")


def ingest(manifest_dir: Path, source_class: ExtensionSourceClass) -> ExtensionRegistry:
    loader = ExtensionLoader(ExtensionRegistry())
    loader.ingest_directory(manifest_dir, source_class=source_class)
    return loader.registry


# ---------------- closed vocabularies ----------------

def test_extension_type_vocabulary_is_closed_and_eleven():
    values = sorted(item.value for item in ExtensionType)
    assert len(values) == 11
    assert sorted(DECLARATIVE_TYPES) == [
        "evaluation_dataset",
        "playbook",
        "report_template",
        "skill",
        "skill_pack",
        "task",
        "threat_method",
        "threat_ruleset",
    ]
    assert sorted(EXECUTABLE_TYPES) == [
        "tool_pack",
        "verification_adapter",
        "verification_strategy",
    ]
    assert set(DECLARATIVE_TYPES) | set(EXECUTABLE_TYPES) == set(values)


def test_trust_states_are_closed_and_trusted_states_are_a_subset():
    values = sorted(state.value for state in ExtensionTrustState)
    assert values == [
        "builtin_trusted",
        "official_trusted",
        "quarantined",
        "rejected",
        "untrusted",
        "verified_external",
    ]
    assert set(TRUSTED_STATES) <= set(values)
    assert "quarantined" not in TRUSTED_STATES
    assert "rejected" not in TRUSTED_STATES


def test_unknown_extension_type_is_refused_at_parse_time():
    raw = raw_of(official("official-skill"))
    raw["extension_type"] = "plugin_pack"
    with pytest.raises(ExtensionError) as exc:
        manifest_from_dict(raw)
    assert exc.value.code is ExtensionErrorCode.MANIFEST_INVALID


def test_unknown_manifest_key_is_refused():
    raw = raw_of(official("official-skill"))
    raw["install_command"] = "curl | sh"
    with pytest.raises(ExtensionError) as exc:
        manifest_from_dict(raw)
    assert exc.value.code is ExtensionErrorCode.MANIFEST_INVALID


def test_manifest_models_are_frozen():
    manifest = official("official-skill")
    with pytest.raises(ValidationError):
        manifest.name = "renamed"  # type: ignore[misc]


def test_api_version_is_fixed():
    assert EXTENSION_API_VERSION == "1.0"
    assert official("official-skill").api_version == "1.0"


# ---------------- digest binding ----------------

def test_identity_digest_is_stable_and_covers_content():
    first = official("official-tool-pack").identity_digest
    assert first == official("official-tool-pack").identity_digest
    changed = official("official-tool-pack").model_copy(update={"description": "different"})
    assert changed.identity_digest != first


def test_computed_digest_matches_declared_digest_on_every_official_manifest():
    for path in sorted(OFFICIAL.rglob("*.extension.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        declared = raw.pop("digest")
        assert declared, path
        assert compute_manifest_digest(raw) == declared, path
        assert official(path.parent.name).digest == declared, path


def test_digest_mismatch_is_an_error_not_a_warning():
    manifest = official("official-skill")
    tampered = manifest.model_copy(update={"digest": "0" * 64})
    verdict = validate_manifest(tampered, raw=raw_of(tampered))
    assert not verdict.valid
    assert any(err.startswith("digest-mismatch:") for err in verdict.errors)


def test_digest_unbound_is_only_a_warning():
    manifest = official("official-skill")
    unbound = manifest.model_copy(update={"digest": ""})
    verdict = validate_manifest(unbound, raw=raw_of(unbound))
    assert verdict.valid
    assert any(warn.startswith("digest-unbound") for warn in verdict.warnings)


# ---------------- authority + capability scanning ----------------

def test_authority_scan_is_identifier_aware():
    assert flag_authority_language("calls code.execute on the target") == ()
    assert flag_authority_language("reads repo/write markers only") == ()
    assert "grant" in flag_authority_language("this extension will grant write access")
    assert "shell" in flag_authority_language("spawns a shell session")


def test_self_declared_trust_keys_are_located_not_trusted():
    raw = raw_of(official("official-skill"))
    raw["trusted"] = True
    hits = find_self_declared_trust(raw)
    assert hits and all(hit.endswith("trusted") for hit in hits)
    with pytest.raises(ExtensionError) as exc:
        manifest_from_dict(raw)
    assert exc.value.code is ExtensionErrorCode.AUTHORITY_DECLARED


def test_every_forbidden_declaration_token_is_rejected():
    assert len(FORBIDDEN_DECLARATIONS) >= 14
    base = official("official-tool-pack")
    for token in sorted(FORBIDDEN_DECLARATIONS):
        manifest = base.model_copy(update={"description": f"provides {token} capabilities"})
        verdict = validate_manifest(manifest, raw=raw_of(manifest))
        assert not verdict.valid, token
        assert any(
            err.startswith("declaration-forbidden:") and token in err for err in verdict.errors
        ), token
        assert verdict.authority_rejection, token


def test_capability_declaration_cannot_exceed_extension_type():
    base = official("official-tool-pack")
    manifest = base.model_copy(
        update={
            "provides": base.provides.model_copy(
                update={"declares": (ExtensionDeclaredCapability.VERIFICATION_ADAPTER,)}
            )
        }
    )
    verdict = validate_manifest(manifest, raw=raw_of(manifest))
    assert not verdict.valid
    assert any("capability-for-type:tool_pack:verification_adapter" in err for err in verdict.errors)
    assert verdict.authority_rejection


def test_declarative_type_must_not_ship_code():
    base = official("official-skill")
    manifest = base.model_copy(
        update={
            "entrypoint_metadata": base.entrypoint_metadata.model_copy(
                update={
                    "kind": ExtensionEntrypointKind.IMPLEMENTATION,
                    "target": "os:system",
                    "contract": "skill.1",
                }
            )
        }
    )
    verdict = validate_manifest(manifest, raw=raw_of(manifest))
    assert not verdict.valid
    assert any("entrypoint-invalid" in err for err in verdict.errors)


def test_verification_adapter_requires_an_implementation_entrypoint():
    base = official("official-verification-adapter")
    manifest = base.model_copy(
        update={
            "entrypoint_metadata": base.entrypoint_metadata.model_copy(
                update={"kind": ExtensionEntrypointKind.DECLARATIVE, "target": "", "contract": ""}
            )
        }
    )
    verdict = validate_manifest(manifest, raw=raw_of(manifest))
    assert not verdict.valid
    assert any("requires an implementation" in err for err in verdict.errors)


def test_holdout_classification_is_refused_outside_evaluation_datasets():
    base = official("official-skill")
    manifest = base.model_copy(update={"dataset_classification": DatasetClassification.HOLDOUT})
    verdict = validate_manifest(manifest, raw=raw_of(manifest))
    assert not verdict.valid
    assert any(err.startswith("classification-not-applicable:skill:holdout") for err in verdict.errors)


def test_official_fixtures_validate_cleanly():
    checked = 0
    for path in sorted(OFFICIAL.rglob("*.extension.yaml")):
        manifest = load_manifest_file(path)
        verdict = validate_manifest(manifest, raw=raw_of(manifest))
        assert verdict.valid, (path, verdict.errors)
        assert verdict.digest_bound, path
        checked += 1
    assert checked == 11


# ---------------- registry ----------------

def test_registry_registers_once_and_reports_duplicates():
    loader = ExtensionLoader(ExtensionRegistry())
    source = discover_manifest_file(OFFICIAL / "official-skill" / "manifest.extension.yaml")
    assert source.manifest is not None
    loader.ingest(source)
    with pytest.raises(ExtensionError) as exc:
        loader.registry.register(source.manifest, trust=loader.registry.trust_of("official-skill"))
    assert exc.value.code is ExtensionErrorCode.DUPLICATE


def test_registry_summary_never_projects_an_entrypoint_target():
    registry = ingest(OFFICIAL, ExtensionSourceClass.OFFICIAL_EXTERNAL)
    summaries = [entry.summary() for entry in registry.list()]
    assert len(summaries) == 11
    for summary in summaries:
        assert "target" not in summary
        assert "entrypoint" not in summary
        assert set(summary) == {
            "extension_id",
            "version",
            "name",
            "extension_type",
            "trust",
            "source_class",
            "lifecycle",
            "health",
            "digest",
            "origin",
        }


def test_registry_query_surface_is_allowlisted():
    registry = ingest(OFFICIAL, ExtensionSourceClass.OFFICIAL_EXTERNAL)
    assert registry.query("list_extensions")
    with pytest.raises(ExtensionError) as exc:
        registry.query("import_module", module="os")
    assert exc.value.code is ExtensionErrorCode.QUERY_UNKNOWN


def test_lifecycle_transitions_are_enforced():
    registry = ingest(OFFICIAL, ExtensionSourceClass.OFFICIAL_EXTERNAL)
    entry = registry.advance("official-skill", "1.0.0", ExtensionLifecycle.LOADED)
    assert entry.lifecycle is ExtensionLifecycle.LOADED
    with pytest.raises(ExtensionError) as exc:
        registry.advance("official-skill", "1.0.0", ExtensionLifecycle.DISCOVERED)
    assert exc.value.code is ExtensionErrorCode.LIFECYCLE_INVALID
    assert ExtensionLifecycle.LOADABLE in ALLOWED_TRANSITIONS[ExtensionLifecycle.REGISTERED]
    assert ExtensionLifecycle.LOADED in ALLOWED_TRANSITIONS[ExtensionLifecycle.LOADABLE]
    assert ExtensionLifecycle.REGISTERED not in ALLOWED_TRANSITIONS[ExtensionLifecycle.LOADABLE]
    assert ALLOWED_TRANSITIONS[ExtensionLifecycle.REJECTED] == ()


def test_registries_are_isolated_no_global_state():
    first = ingest(OFFICIAL, ExtensionSourceClass.OFFICIAL_EXTERNAL)
    second = ExtensionRegistry()
    assert len(first.list()) == 11
    assert second.list() == []
    assert second.identities() == []
    with pytest.raises(ExtensionError):
        second.get("official-skill", "1.0.0")


def test_rejected_content_cannot_be_registered():
    manifest = load_manifest_file(THIRD / "malicious-third-party" / "manifest.extension.yaml")
    verdict = validate_manifest(manifest, raw=raw_of(manifest))
    assert not verdict.valid
    assert verdict.authority_rejection
    trust = evaluate_trust(
        manifest, source_class=ExtensionSourceClass.THIRD_PARTY, validation=verdict
    )
    assert trust.state is ExtensionTrustState.REJECTED
    with pytest.raises(ExtensionError) as exc:
        ExtensionRegistry().register(manifest, trust=trust)
    assert exc.value.code is ExtensionErrorCode.REJECTED


# ---------------- resolver ----------------

def test_resolver_resolves_a_single_candidate():
    registry = ingest(OFFICIAL, ExtensionSourceClass.OFFICIAL_EXTERNAL)
    resolution = ExtensionResolver(registry).resolve(ResolutionRequest(extension_id="official-skill"))
    assert resolution.resolved
    assert resolution.chosen == "official-skill@1.0.0"
    assert resolution.trust == "official_trusted"
    assert resolution.eligible


def test_resolver_reports_ambiguity_for_two_versions_without_policy():
    registry = ingest(THIRD / "valid-third-party", ExtensionSourceClass.THIRD_PARTY)
    resolver = ExtensionResolver(registry)
    ambiguous = resolver.resolve(ResolutionRequest(extension_id="valid-third-party"))
    assert any(c.kind.value == "version_ambiguous" for c in ambiguous.conflicts)
    assert ambiguous.chosen == ""
    pinned = resolver.resolve(
        ResolutionRequest(extension_id="valid-third-party", version_constraint="==1.0.0")
    )
    assert pinned.chosen == "valid-third-party@1.0.0"
    highest = resolver.resolve(
        ResolutionRequest(extension_id="valid-third-party", policy=VersionPolicy.HIGHEST_COMPATIBLE)
    )
    assert highest.chosen == "valid-third-party@1.1.0"


def test_resolver_never_elects_an_untrusted_provider():
    registry = ingest(THIRD / "valid-third-party", ExtensionSourceClass.THIRD_PARTY)
    resolution = ExtensionResolver(registry).resolve(
        ResolutionRequest(extension_id="valid-third-party", policy=VersionPolicy.HIGHEST_COMPATIBLE)
    )
    assert resolution.chosen.endswith("@1.1.0")
    assert not resolution.eligible
    assert any(note.startswith("trust-not-loadable:untrusted") for note in resolution.notes)


def test_provider_conflict_has_no_winner():
    loader = ExtensionLoader(ExtensionRegistry())
    loader.ingest_directory(OFFICIAL, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL)
    loader.ingest_directory(
        THIRD / "conflicting-third-party", source_class=ExtensionSourceClass.THIRD_PARTY
    )
    resolution = ExtensionResolver(loader.registry).resolve(
        ResolutionRequest(provide="verification_adapter")
    )
    assert not resolution.resolved
    assert resolution.chosen == ""
    assert any(c.kind.value == "provider_conflict" for c in resolution.conflicts)
    assert resolution.alternatives == (
        "conflicting-third-party@1.0.0",
        "official-verification-adapter@1.0.0",
    )


def test_missing_extension_is_reported_not_guessed():
    resolution = ExtensionResolver(ExtensionRegistry()).resolve(
        ResolutionRequest(extension_id="does-not-exist")
    )
    assert not resolution.resolved
    assert any(c.kind.value == "dependency_missing" for c in resolution.conflicts)
    assert "candidate-absent" in resolution.notes


# ---------------- authoring template + surface ----------------

def test_authoring_template_parses_and_carries_no_self_trust():
    assert TEMPLATE.is_file()
    doc = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
    assert isinstance(doc, dict) and "extension" in doc
    body = doc["extension"]
    assert body["extension_type"] in set(ExtensionType)
    assert body["api_version"] == "1.0"
    assert find_self_declared_trust(body) == ()
    assert flag_authority_language(body.get("description", "")) == ()


def test_read_actions_surface_is_closed():
    assert READ_ACTIONS == ("list", "describe", "resolve", "check")


def test_satisfies_contract_helpers():
    assert satisfies("1.2.3", ">=1.0.0,<2.0.0")
    assert not satisfies("2.0.0", ">=1.0.0,<2.0.0")
    assert satisfies("1.0.0", "")
