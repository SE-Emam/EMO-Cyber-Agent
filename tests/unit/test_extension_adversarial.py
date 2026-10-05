"""POST-RC-014 — adversarial surface and E2E acceptance.

Hostile manifests fail closed at parse time; the malicious fixture is
rejected without importing its payload; the adapters expose only a
bounded, read-only view (there is no install/trust/execute verb to
reach); and all five content types materialize through the existing
trusted loaders.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from emo_cyber_agent.cli.main import EXIT_DOMAIN_FAILURE, EXIT_INVALID_INPUT, app
from emo_cyber_agent.extensions import (
    ExtensionError,
    ExtensionErrorCode,
    ExtensionLoader,
    ExtensionRegistry,
    ExtensionSourceClass,
    SELF_DECLARED_TRUST_KEYS,
    find_self_declared_trust,
    load_manifest_file,
    load_manifest_text,
    manifest_from_dict,
    materialize_content,
    materialize_evaluation_dataset,
    materialize_skill_pack,
    materialize_threat_method,
    materialize_tool_pack,
    materialize_verification_adapter,
    read_extensions,
)
from emo_cyber_agent.mcp.delegate import dispatch
from emo_cyber_agent.mcp.tools import InvalidInput, validate_arguments

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "extensions"
OFFICIAL = FIXTURES / "official"
THIRD = FIXTURES / "third_party"

runner = CliRunner()


def _raw(ext_id: str = "official-tool-pack") -> dict:
    path = OFFICIAL / ext_id / "manifest.extension.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def _read(action: str, **kwargs) -> dict:
    kwargs.setdefault("extra_roots", (str(FIXTURES),))
    return read_extensions(action, **kwargs)


# ---------------------------------------------------------------------------
# Hostile manifests fail closed at parse time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(SELF_DECLARED_TRUST_KEYS))
def test_self_declared_trust_key_is_rejected_as_authority(key: str):
    data = _raw()
    data[key] = "trusted"
    with pytest.raises(ExtensionError) as excinfo:
        manifest_from_dict(data)
    assert excinfo.value.code is ExtensionErrorCode.AUTHORITY_DECLARED
    assert key in str(excinfo.value)


def test_nested_self_declared_trust_is_found_too():
    data = _raw()
    data["security_metadata"] = dict(data["security_metadata"], trusted=True)
    hits = find_self_declared_trust(data)
    assert any(hit.endswith(".trusted") for hit in hits)
    with pytest.raises(ExtensionError) as excinfo:
        manifest_from_dict(data)
    assert excinfo.value.code is ExtensionErrorCode.AUTHORITY_DECLARED


def test_unknown_extra_keys_are_rejected_not_ignored():
    data = _raw()
    data["install_path"] = "/usr/local/bin"
    data["auto_trust"] = True
    with pytest.raises(ExtensionError) as excinfo:
        manifest_from_dict(data)
    assert excinfo.value.code is ExtensionErrorCode.MANIFEST_INVALID


def test_lifecycle_self_escalation_cannot_be_declared():
    data = _raw()
    data["lifecycle"] = "loaded"
    with pytest.raises(ExtensionError) as excinfo:
        manifest_from_dict(data)
    assert excinfo.value.code is ExtensionErrorCode.MANIFEST_INVALID

    data = _raw()
    data["trust_state"] = "official_trusted"
    with pytest.raises(ExtensionError) as excinfo:
        manifest_from_dict(data)
    assert excinfo.value.code is ExtensionErrorCode.AUTHORITY_DECLARED


def test_non_mapping_manifest_root_is_rejected():
    with pytest.raises(ExtensionError) as excinfo:
        load_manifest_text("- just\n- a list\n", source="hostile.yaml")
    assert excinfo.value.code is ExtensionErrorCode.MANIFEST_INVALID
    assert "mapping" in str(excinfo.value)


def test_malformed_yaml_is_a_content_failure_not_a_crash():
    with pytest.raises(ExtensionError) as excinfo:
        load_manifest_text("extension_id: [unterminated\n", source="broken.yaml")
    assert excinfo.value.code is ExtensionErrorCode.MANIFEST_INVALID
    assert "parse failed" in str(excinfo.value)


def test_empty_manifest_text_is_missing():
    with pytest.raises(ExtensionError) as excinfo:
        load_manifest_text("   \n", source="empty.yaml")
    assert excinfo.value.code is ExtensionErrorCode.MANIFEST_MISSING


# ---------------------------------------------------------------------------
# The malicious fixture: rejected, unregistered, never imported
# ---------------------------------------------------------------------------


def test_malicious_fixture_is_rejected_without_importing_its_payload():
    loader = ExtensionLoader(ExtensionRegistry())
    reports = loader.ingest_directory(
        THIRD / "malicious-third-party", source_class=ExtensionSourceClass.THIRD_PARTY
    )
    assert len(reports) == 1
    report = reports[0]
    assert report.trust_state == "rejected"
    assert report.registered is False
    assert "hostile_impl" not in sys.modules

    assert report.validation is not None
    errors = " ".join(report.validation.errors)
    assert "declaration-forbidden:capability-for-type:tool_pack:verification_adapter" in errors
    assert "declaration-forbidden:text:grant" in errors
    assert "declaration-forbidden:text:write" in errors

    with pytest.raises(ExtensionError) as excinfo:
        loader.registry.get("malicious-third-party", "1.0.0")
    assert excinfo.value.code is ExtensionErrorCode.NOT_FOUND


def test_rejected_content_stays_observable_but_never_resolvable():
    view = _read("describe", extension_id="malicious-third-party")["extension"]
    assert view["registered"] is False
    assert view["resolvable"] is False
    assert view["trust"] == "rejected"
    assert view["lifecycle"] == "rejected"
    assert any("declaration-forbidden" in error for error in view["errors"])

    resolution = _read("resolve", extension_id="malicious-third-party")["resolution"]
    assert resolution["eligible"] is False
    assert resolution["resolved"] is False


# ---------------------------------------------------------------------------
# Read surface: no install / trust / load / execute verb exists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["install", "trust", "load", "execute", "approve", ""])
def test_cli_has_no_authority_verb(action: str):
    result = runner.invoke(app, ["extensions", "--action", action, "--path", str(FIXTURES)])
    assert result.exit_code == EXIT_INVALID_INPUT


def test_cli_rejects_bad_format_and_bad_path():
    assert runner.invoke(app, ["extensions", "--format", "xml"]).exit_code == EXIT_INVALID_INPUT
    assert (
        runner.invoke(app, ["extensions", "--path", str(FIXTURES / "missing-dir")]).exit_code
        == EXIT_INVALID_INPUT
    )


def test_cli_list_scans_metadata_only_and_reports_conflicts():
    result = runner.invoke(
        app, ["extensions", "--action", "list", "--path", str(FIXTURES), "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["action"] == "list"
    assert body["code_load"] == "disabled"
    assert body["discovered"] == 17
    assert body["registered"] == 16  # malicious never enters the registry
    assert body["count"] == 16

    ids = {entry["extension_id"] for entry in body["entries"]}
    assert "malicious-third-party" not in ids
    assert {"valid-third-party", "incompatible-third-party", "official-tool-pack"} <= ids
    assert body["trust_counts"].get("quarantined", 0) >= 1
    assert all(entry["trust"]["state"] in {"untrusted", "quarantined"} for entry in body["entries"])

    conflicts = {conflict["kind"] for conflict in body["conflicts"]}
    assert "provider_conflict" in conflicts
    adapter_conflict = next(
        conflict
        for conflict in body["conflicts"]
        if conflict["subject"] == "verification_adapter"
    )
    assert set(adapter_conflict["candidates"]) == {
        "conflicting-third-party@1.0.0",
        "official-verification-adapter@1.0.0",
    }


def test_cli_human_list_never_shows_code_load_enabled():
    result = runner.invoke(app, ["extensions", "--action", "list", "--path", str(FIXTURES)])
    assert result.exit_code == 0
    assert "action: list" in result.stdout
    assert "code_load: disabled" in result.stdout
    assert "install" not in result.stdout.lower().replace("disallowed", "")


def test_cli_resolve_conflict_has_no_winner():
    result = runner.invoke(
        app,
        [
            "extensions",
            "--action",
            "resolve",
            "--provide",
            "verification_adapter",
            "--path",
            str(FIXTURES),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    resolution = json.loads(result.stdout)["resolution"]
    assert resolution["eligible"] is False
    assert resolution["resolved"] is False
    assert set(resolution["alternatives"]) == {
        "conflicting-third-party@1.0.0",
        "official-verification-adapter@1.0.0",
    }
    assert any(conflict["kind"] == "provider_conflict" for conflict in resolution["conflicts"])


def test_cli_unknown_id_is_domain_failure():
    result = runner.invoke(
        app, ["extensions", "--action", "describe", "--extension-id", "does-not-exist"]
    )
    assert result.exit_code == EXIT_DOMAIN_FAILURE


def test_cli_oversized_id_is_truncated_not_echoed():
    marker = "A" * 5000
    result = runner.invoke(
        app,
        ["extensions", "--action", "describe", "--extension-id", marker, "--path", str(THIRD)],
    )
    assert result.exit_code == EXIT_DOMAIN_FAILURE
    assert "A" * 200 not in result.stdout


def test_cli_run_imports_no_extension_code():
    for command in (
        ["extensions", "--action", "list", "--path", str(FIXTURES)],
        ["extensions", "--action", "describe", "--extension-id", "valid-third-party", "--path", str(FIXTURES)],
        ["extensions", "--action", "check", "--extension-id", "official-tool-pack", "--path", str(FIXTURES)],
    ):
        assert runner.invoke(app, command).exit_code == 0
    assert "hostile_impl" not in sys.modules
    assert "official_adapter_impl" not in sys.modules


# ---------------------------------------------------------------------------
# MCP adapter: bounded schema, read-only, typed error mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {"action": "list", "capability": "verification_adapter"},
        {"action": "list", "command": "rm -rf /"},
        {"action": "list", "policy": "bypass"},
        {"action": "list", "version": "1.0.0"},
        {"action": "install"},
        ["list"],
        "list",
    ],
)
def test_mcp_extensions_rejects_hostile_shapes(arguments):
    with pytest.raises(InvalidInput):
        validate_arguments("cyber_extensions", arguments)


def test_mcp_extensions_rejects_oversized_id():
    with pytest.raises(InvalidInput):
        validate_arguments("cyber_extensions", {"action": "describe", "extension_id": "x" * 81})


def test_mcp_extensions_dispatch_is_metadata_only():
    result = dispatch("cyber_extensions", {"action": "list"})
    assert result["status"] == "ok"
    assert result["tool"] == "cyber_extensions"
    body = result["result"]
    assert body["action"] == "list"
    assert body["code_load"] == "disabled"
    assert isinstance(body["entries"], list)


def test_mcp_extensions_unknown_id_maps_to_not_found():
    result = dispatch("cyber_extensions", {"action": "describe", "extension_id": "nope-missing"})
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert payload["code"] == "NOT_FOUND"
    assert payload["tool"] == "cyber_extensions"


def test_mcp_dispatch_never_imports_extension_code():
    dispatch("cyber_extensions", {"action": "list"})
    assert "hostile_impl" not in sys.modules
    assert "official_adapter_impl" not in sys.modules


# ---------------------------------------------------------------------------
# E2E acceptance: all five content types materialize through Core loaders
# ---------------------------------------------------------------------------


def test_e2e_tool_pack_materializes_through_post_rc_007():
    manifest = load_manifest_file(OFFICIAL / "official-tool-pack" / "manifest.extension.yaml")
    pack = materialize_tool_pack(OFFICIAL / "official-tool-pack", manifest)
    assert type(pack).__name__ == "ToolPack"
    assert pack.name
    content = materialize_content(OFFICIAL / "official-tool-pack", manifest)
    assert content.extension_type == "tool_pack"
    assert content.text


def test_e2e_skill_pack_materializes_through_post_rc_006():
    manifest = load_manifest_file(OFFICIAL / "official-skill-pack" / "manifest.extension.yaml")
    pack = materialize_skill_pack(OFFICIAL / "official-skill-pack", manifest)
    assert type(pack).__name__ == "SecuritySkillPack"


def test_e2e_threat_method_materializes_as_non_authoritative_data():
    manifest = load_manifest_file(OFFICIAL / "official-threat-method" / "manifest.extension.yaml")
    method, rules = materialize_threat_method(OFFICIAL / "official-threat-method", manifest)
    assert type(method).__name__ == "ThreatMethod"
    assert method.method_id
    assert rules and all(type(rule).__name__ == "ThreatRule" for rule in rules)
    assert not hasattr(method, "severity")  # methods never carry verdicts


def test_e2e_evaluation_dataset_keeps_its_classification():
    manifest = load_manifest_file(
        OFFICIAL / "official-evaluation-dataset" / "manifest.extension.yaml"
    )
    dataset = materialize_evaluation_dataset(OFFICIAL / "official-evaluation-dataset", manifest)
    assert type(dataset).__name__ == "EvaluationDataset"
    assert dataset.manifest.split.value == "development"
    assert dataset.cases


def test_e2e_verification_adapter_imports_only_through_the_loader(monkeypatch):
    directory = OFFICIAL / "official-verification-adapter"
    monkeypatch.syspath_prepend(str(directory))
    manifest = load_manifest_file(directory / "manifest.extension.yaml")
    try:
        adapter = materialize_verification_adapter(manifest)
        assert type(adapter).__name__ == "OfficialExternalAdapter"
        assert adapter.id == "official-external-adapter"
        assert adapter.provenance["provider_identity"] == "emo-cyber-agent"
        assert "official_adapter_impl" in sys.modules
    finally:
        sys.modules.pop("official_adapter_impl", None)


# ---------------------------------------------------------------------------
# Read actions are all code-load-disabled projections
# ---------------------------------------------------------------------------


def test_every_read_action_reports_code_load_disabled():
    for action in ("list", "describe", "resolve", "check"):
        body = _read(action, extension_id="valid-third-party", provide="report_template")
        assert body["code_load"] == "disabled"
        assert body["action"] == action
