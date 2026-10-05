"""Official tool pack catalog — POST-RC-007.

YAML files under templates/tools/packs/official/ are the canonical
authoring artifacts. Loader parses, normalizes to the flat
tool-pack.schema.json shape, cross-validates, and registers with
loader-assigned TRUSTED provenance (never self-declared).

Compatibility layer: existing T007 scanner adapters are reused
unchanged (argv + parse identical — proven by test). No adapter
logic is duplicated here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emo_cyber_agent.tools.packs.errors import ToolPackError, ToolPackErrorCode
from emo_cyber_agent.tools.packs.registry import ToolPackRegistry
from emo_cyber_agent.tools.packs.spec import PackTrust, ToolPack
from emo_cyber_agent.tools.packs.validator import ToolPackValidator


def compat_adapters() -> dict[str, Any]:
    """Existing T007 adapters, reused unchanged. Single import site so a
    future provider swap touches one place, never Core methodology."""
    from emo_cyber_agent.core.scanners import SCANNER_ADAPTERS

    return dict(SCANNER_ADAPTERS)


def _require_yaml() -> Any:
    try:
        import yaml as _yaml

        return _yaml
    except ImportError as e:
        raise ToolPackError(ToolPackErrorCode.INVALID, "YAML parsing needs pyyaml; use register(ToolPack) directly") from e


def load_yaml_text(text: str) -> dict[str, Any]:
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        raise ToolPackError(ToolPackErrorCode.INVALID, f"malformed YAML: {e}") from e
    if not isinstance(doc, dict) or "pack" not in doc:
        raise ToolPackError(ToolPackErrorCode.INVALID, "YAML must contain a top-level pack mapping")
    return doc


def normalize_pack_dict(doc: dict[str, Any]) -> dict[str, Any]:
    p = doc.get("pack", {})
    rt = doc.get("runtime", {})
    net = doc.get("network", {})
    fs = doc.get("filesystem", {})
    sec = doc.get("secrets", {})
    ev = doc.get("evidence", {})

    def _norm_definition(raw: dict[str, Any]) -> dict[str, Any]:
        inputs = raw.get("inputs", {})
        outputs = raw.get("outputs", {})
        runtime = raw.get("runtime", {})
        return {
            "definition_id": raw.get("id", ""),
            "tool_id": raw.get("tool_id", ""),
            "tool_capability": str(raw.get("tool_capability", "scanner.local.execute")),
            "mode": str(raw.get("mode", "scan")),
            "version_range": str(raw.get("version_range", ">=1.0.0")),
            "adapter": str(raw.get("adapter", "")),
            "capabilities": list(raw.get("capabilities", [])),
            "inputs": {"fields": [{"name": f.get("name", ""), "type": str(f.get("type", "string")), "required": bool(f.get("required", False)), "description": str(f.get("description", "")), "allowed_values": list(f.get("allowed_values", [])), "max_length": int(f.get("max_length", 512)), "min_value": f.get("min_value"), "max_value": f.get("max_value")} for f in inputs.get("fields", [])]},
            "outputs": {"record_kinds": list(outputs.get("record_kinds", [])), "retains_raw": bool(outputs.get("retains_raw", False)), "raw_limit": int(outputs.get("raw_limit", 4096)), "redaction": bool(outputs.get("redaction", True))},
            "runtime": {"entrypoint": str(runtime.get("entrypoint", p.get("entrypoint", ""))), "timeout_s": int(runtime.get("timeout_s", rt.get("timeout_s", 120))), "stdout_limit": int(runtime.get("stdout_limit", rt.get("stdout_limit", 65536))), "stderr_limit": int(runtime.get("stderr_limit", rt.get("stderr_limit", 16384))), "cwd_scoped": bool(runtime.get("cwd_scoped", True)), "env_allowlist": list(runtime.get("env_allowlist", []))},
            "network": str(raw.get("network", net.get("default", "network_none"))),
            "supported_targets": list(raw.get("supported_targets", p.get("supported_targets", ["repo"]))),
            "snapshot_binding": bool(raw.get("snapshot_binding", False)),
            "executable": bool(raw.get("executable", True)),
            "fixed_args": list(raw.get("fixed_args", [])),
            "value_flags": list(raw.get("value_flags", [])),
        }

    return {
        "pack_id": p.get("id", ""),
        "name": p.get("name", ""),
        "version": p.get("version", ""),
        "vendor": str(p.get("vendor", "")),
        "description": p.get("description", ""),
        "tool_version_range": str(p.get("tool_version_range", ">=1.0.0")),
        "maintenance_status": str(p.get("maintenance_status", "active")),
        "license": str(p.get("license", "")),
        "source_provenance": str(p.get("source_provenance", "")),
        "entrypoint": p.get("entrypoint", ""),
        "supported_platforms": list(p.get("supported_platforms", [])),
        "supported_targets": list(p.get("supported_targets", ["repo"])),
        "definitions": [_norm_definition(d) for d in doc.get("definitions", [])],
        "network_default": str(net.get("default", "network_none")),
        "filesystem_read_only": bool(fs.get("read_only", True)),
        "resource_limits": dict(doc.get("resource_limits", {})),
        "secret_handling": str(sec.get("handling", "redact-and-never-persist")),
        "redaction_rules": list(sec.get("redaction_rules", [])),
        "evidence_mapping": dict(ev.get("mapping", {})),
        "limitations": list(doc.get("limitations", [])),
        "provenance": dict(doc.get("provenance", {})),
    }


def validate_against_schema(flat: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    try:
        import jsonschema as _js
    except ImportError as e:
        raise ToolPackError(ToolPackErrorCode.INVALID, "schema cross-check needs jsonschema") from e
    if schema is None:
        import json as _json
        from pathlib import Path as _Path

        schema_path = _Path(__file__).resolve().parents[3] / "docs" / "schemas" / "tool-pack.schema.json"
        if schema_path.is_file():
            schema = _json.loads(schema_path.read_text())
        else:
            try:
                from emo_cyber_agent.core.resources import load_schema_text

                schema = _json.loads(load_schema_text("tool-pack"))
            except Exception as e:
                raise ToolPackError(ToolPackErrorCode.INVALID, f"tool pack schema unavailable: {e}") from e
    assert isinstance(schema, dict), "schema unavailable"
    try:
        _js.validate(flat, schema)
    except Exception as e:
        raise ToolPackError(ToolPackErrorCode.INVALID, f"schema validation failed: {e}") from e


def spec_from_yaml_text(text: str, *, check_schema: bool = True) -> ToolPack:
    flat = normalize_pack_dict(load_yaml_text(text))
    if check_schema:
        validate_against_schema(flat)
    try:
        return ToolPack(**flat)
    except ValueError as e:
        raise ToolPackError(ToolPackErrorCode.INVALID, f"ToolPack construction failed: {e}") from e


def load_official_tool_packs(directory: str | Path) -> ToolPackRegistry:
    directory = Path(directory)
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"no official tool packs in {directory}")
    registry = ToolPackRegistry()
    validator = ToolPackValidator()
    for path in files:
        pack = spec_from_yaml_text(path.read_text())
        result = validator.validate(pack)
        if not result.valid:
            raise ToolPackError(ToolPackErrorCode.INVALID, f"official tool pack invalid {pack.pack_id}: {result.errors}")
        registry.register(pack, trust=PackTrust.TRUSTED)
    return registry
