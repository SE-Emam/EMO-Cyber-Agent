"""POST-RC-014 — extension discovery is metadata-first and never imports.

Discovery reads documents and distribution metadata only. The proof is
behavioral: hostile modules referenced by discovered content stay out of
``sys.modules``, entry points are listed without ``load()``, and the
report's ``imported`` counter is structurally zero.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from emo_cyber_agent.extensions import (
    ENTRY_POINT_GROUP,
    MANIFEST_GLOBS,
    DiscoveredSource,
    ExtensionSourceClass,
    discover_directory,
    discover_distributions,
    discover_entry_points,
    discover_manifest_file,
    parse_entry_target,
    source_from_dict,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"
MALICIOUS = THIRD / "malicious-third-party" / "manifest.extension.yaml"
ADAPTER_DIR = OFFICIAL / "official-verification-adapter"
HOSTILE_DIR = THIRD / "malicious-third-party"


def test_manifest_globs_only_match_manifest_files():
    assert MANIFEST_GLOBS == ("*.extension.yaml", "*.extension.yml", "*.extension.json")


def test_entry_point_group_is_ours():
    assert ENTRY_POINT_GROUP == "emo_cyber_agent.extensions"


def test_discover_one_manifest_file_reads_metadata_only():
    source = discover_manifest_file(OFFICIAL / "official-skill" / "manifest.extension.yaml")
    assert source.ok
    assert source.manifest is not None
    assert source.manifest.extension_id == "official-skill"
    assert source.manifest_source == "manifest_file"
    assert "official_adapter_impl" not in sys.modules


def test_source_class_is_chosen_by_the_host_not_by_the_document():
    claimed = discover_manifest_file(
        MALICIOUS, source_class=ExtensionSourceClass.OFFICIAL_EXTERNAL
    )
    assert claimed.source_class is ExtensionSourceClass.OFFICIAL_EXTERNAL
    default = discover_manifest_file(MALICIOUS)
    assert default.source_class is ExtensionSourceClass.THIRD_PARTY


def test_missing_and_broken_manifests_become_errors_not_exceptions():
    missing = discover_manifest_file(OFFICIAL / "official-skill" / "nope.yaml")
    assert missing.manifest is None and missing.errors
    assert missing.errors[0].startswith("EXTENSION_MANIFEST_MISSING")

    content = OFFICIAL / "official-skill" / "content" / "skill.yaml"  # valid yaml, not a manifest
    source = discover_manifest_file(content)
    assert source.manifest is None and source.errors
    assert source.errors[0].startswith("EXTENSION_MANIFEST_INVALID")


def test_unreadable_manifest_is_reported_not_raised(tmp_path: Path):
    broken = tmp_path / "broken.extension.yaml"
    broken.write_text("extension:\n  - not: a mapping\n", encoding="utf-8")
    source = discover_manifest_file(broken)
    assert source.manifest is None
    assert source.errors and source.errors[0].startswith("EXTENSION_")


def test_directory_scan_imports_nothing():
    report = discover_directory(FIXTURES, source_class=ExtensionSourceClass.THIRD_PARTY)
    assert report.imported == 0
    assert report.scanned == len(report.sources) >= 17
    assert "hostile_impl" not in sys.modules
    assert "official_adapter_impl" not in sys.modules


def test_directory_scan_finds_every_manifest_and_ignores_content_files():
    report = discover_directory(FIXTURES, source_class=ExtensionSourceClass.THIRD_PARTY)
    identities = sorted(source.identity for source in report.sources)
    assert "valid-third-party@1.0.0" in identities
    assert "valid-third-party@1.1.0" in identities
    assert "official-tool-pack@1.0.0" in identities
    # content files (pack.yaml, skill.yaml, method.yaml) are never parsed as manifests
    assert not any(identity.endswith("skill@1.0.0") and "official-skill@" not in identity for identity in identities)
    assert len(identities) == 17


def test_content_files_outside_the_manifest_globs_are_not_sources():
    report = discover_directory(OFFICIAL / "official-skill-pack", source_class=ExtensionSourceClass.THIRD_PARTY)
    assert len(report.sources) == 1
    assert report.sources[0].manifest is not None


def test_every_discovered_source_is_frozen_and_explicit():
    report = discover_directory(THIRD, source_class=ExtensionSourceClass.THIRD_PARTY)
    assert report.sources
    for source in report.sources:
        assert source.origin and source.source_class is ExtensionSourceClass.THIRD_PARTY
        assert source.manifest is not None or source.errors


class _ExplodingEntryPoint:
    """Any call to ``load()`` would explode: discovery must never call it."""

    def __init__(self) -> None:
        self.loaded = False
        self.dist = SimpleNamespace(name="evil-pkg", version="9.9.9")

    name = "evil_extension"
    value = "hostile_impl:boom"
    group = ENTRY_POINT_GROUP

    def load(self):  # pragma: no cover - must never run
        self.loaded = True
        raise AssertionError("discovery must not load entry points")


def test_entry_points_are_listed_without_loading():
    ref = _ExplodingEntryPoint()
    refs = discover_entry_points(entry_points=[ref])
    assert ref.loaded is False
    assert len(refs) == 1
    assert refs[0].name == "evil_extension"
    assert refs[0].value == "hostile_impl:boom"
    assert refs[0].distribution_name == "evil-pkg"
    assert refs[0].deferred is True
    assert "hostile_impl" not in sys.modules


def test_broken_environment_returns_empty_not_a_crash():
    assert discover_entry_points(entry_points=[]) == ()


def test_parse_entry_target_is_strict():
    assert parse_entry_target("pkg.module:build") == ("pkg.module", "build")
    assert parse_entry_target("pkg.module:build.thing") == ("pkg.module", "build.thing")
    assert parse_entry_target("pkg.module") is None
    assert parse_entry_target("pkg.module:build:extra") is None
    assert parse_entry_target("../etc:passwd") is None
    assert parse_entry_target("") is None


def test_distribution_discovery_is_metadata_only():
    dist = SimpleNamespace(
        metadata={"Name": "evil-pkg", "Version": "9.9.9"},
        entry_points=(
            SimpleNamespace(name="x", value="hostile_impl:boom", group=ENTRY_POINT_GROUP),
        ),
    )
    records = discover_distributions(distributions=[dist])
    assert len(records) == 1
    assert records[0].distribution_name == "evil-pkg"
    assert records[0].distribution_version == "9.9.9"
    assert records[0].entry_points[0].value == "hostile_impl:boom"
    assert records[0].entry_points[0].deferred is True
    assert "hostile_impl" not in sys.modules


def test_source_from_dict_builds_a_frozen_record():
    from emo_cyber_agent.extensions import load_manifest_file

    data = load_manifest_file(
        OFFICIAL / "official-skill" / "manifest.extension.yaml"
    ).model_dump(mode="json")
    source = source_from_dict(
        data,
        source_class=ExtensionSourceClass.THIRD_PARTY,
        origin="inline:1",
    )
    assert isinstance(source, DiscoveredSource)
    assert source.manifest is not None
    assert source.identity == "official-skill@1.0.0"
    assert source.manifest_source == "distribution_metadata"
    assert source.ok
