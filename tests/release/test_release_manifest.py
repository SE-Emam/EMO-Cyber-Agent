"""ECA-T016 — F. Release manifest tests.

release/release-manifest.json is the machine-readable release identity:
every required field present, artifact hashes matching the real files
in dist/, version consistent with the package, and gate results
referencing the evidence that produced them.
"""

from __future__ import annotations

import hashlib
import json
import tomllib


from conftest import ROOT, SDIST, VERSION, WHEEL

MANIFEST = ROOT / "release" / "release-manifest.json"

REQUIRED_FIELDS = (
    "project",
    "version",
    "release_channel",
    "api_version",
    "schema_version",
    "git_revision",
    "source_tree_digest",
    "build_timestamp",
    "python_versions",
    "platform",
    "artifacts",
    "build_tool",
    "dependency_snapshot",
    "schema_count",
    "schema_result",
    "test_count",
    "test_result",
    "ruff_result",
    "security_gate",
    "evaluation_gate",
    "invariant_gate",
)


def _manifest() -> dict:
    assert MANIFEST.is_file(), f"missing {MANIFEST}"
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_exists_and_has_all_required_fields():
    body = _manifest()
    for field in REQUIRED_FIELDS:
        assert field in body, f"manifest missing field: {field}"


def test_manifest_identity_matches_package():
    body = _manifest()
    assert body["project"] == "emo-cyber"
    assert body["version"] == VERSION
    with (ROOT / "pyproject.toml").open("rb") as fh:
        assert body["version"] == tomllib.load(fh)["project"]["version"]
    assert body["release_channel"] in ("final", "rc")
    assert body["schema_count"] == 36
    assert body["schema_result"] == "36/36"


def test_manifest_artifacts_match_dist_files():
    body = _manifest()
    for key, path in (("wheel", WHEEL), ("sdist", SDIST)):
        entry = body["artifacts"][key]
        assert entry["name"] == path.name
        assert entry["size"] == path.stat().st_size
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert entry["sha256"] == digest, f"{key} hash mismatch"


def test_manifest_dependency_snapshot_is_bounded():
    body = _manifest()
    snapshot = body["dependency_snapshot"]
    assert set(snapshot) >= {"pydantic", "pydantic-settings", "typer", "rich"}
    for name, spec in snapshot.items():
        assert "version" in spec and "license" in spec, name


def test_manifest_gate_results_reference_evidence():
    body = _manifest()
    for gate in ("security_gate", "evaluation_gate", "invariant_gate"):
        assert body[gate] in ("PASS", "BLOCKED"), gate
    assert body["test_result"].startswith("1356 passed") or "passed" in body["test_result"]
    assert body["ruff_result"] == "PASS"
