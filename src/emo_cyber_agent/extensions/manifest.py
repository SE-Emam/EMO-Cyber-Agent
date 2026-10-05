"""Extension manifest parsing — POST-RC-014.

Manifests are authoring-time documents. Parsing never imports an
extension module, never resolves an entry point and never touches the
network: distribution metadata, manifest text and schema validation are
the whole discovery surface. Self-declared trust keys are refused here,
before anything else can look at the document, so an extension can never
describe itself into a trusted state.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from emo_cyber_agent.extensions.errors import ExtensionError, ExtensionErrorCode
from emo_cyber_agent.extensions.spec import (
    SELF_DECLARED_TRUST_KEYS,
    ExtensionManifest,
    manifest_identity_digest,
)

__all__ = [
    "MANIFEST_KEYS",
    "compute_manifest_digest",
    "find_self_declared_trust",
    "load_manifest_file",
    "load_manifest_text",
    "manifest_from_dict",
    "manifest_to_dict",
    "normalize_manifest_dict",
    "validate_against_schema",
]

#: The minimum manifest surface required by the extension contract.
MANIFEST_KEYS: tuple[str, ...] = (
    "extension_id",
    "name",
    "version",
    "extension_type",
    "description",
    "api_version",
    "supported_emo_versions",
    "dependencies",
    "optional_dependencies",
    "provides",
    "requires",
    "entrypoint_metadata",
    "artifact_identity",
    "source_provenance",
    "license",
    "security_metadata",
    "digest",
)


def find_self_declared_trust(data: Any, path: str = "$") -> tuple[str, ...]:
    """Locate keys that claim trust/authority inside a raw manifest.

    Trust is assigned by the loader, catalog or a host verification
    process; a manifest that contains one of these keys is rejected as an
    authority declaration instead of being silently ignored."""
    hits: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            token = str(key).strip().lower()
            if token in SELF_DECLARED_TRUST_KEYS:
                hits.append(f"{path}.{key}")
            hits.extend(find_self_declared_trust(value, f"{path}.{key}"))
    elif isinstance(data, (list, tuple)):
        for index, item in enumerate(data):
            hits.extend(find_self_declared_trust(item, f"{path}[{index}]"))
    return tuple(hits)


def compute_manifest_digest(data: dict[str, Any]) -> str:
    """Deterministic identity digest of a raw manifest payload.

    Same rule as ``ExtensionManifest.identity_digest``: semantic metadata
    plus artifact identity, never install path or ordering."""
    payload = {key: value for key, value in data.items() if key != "digest"}
    return manifest_identity_digest(payload)


def normalize_manifest_dict(doc: dict[str, Any]) -> dict[str, Any]:
    """Flatten the authoring document into the flat manifest contract.

    Accepts either the flat shape or a single top-level ``extension:``
    mapping (the template style). Everything else passes through
    unchanged; pydantic still validates the result."""
    if not isinstance(doc, dict):
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, "manifest must be a mapping")
    nested = doc.get("extension")
    if isinstance(nested, dict):
        flat = {key: value for key, value in doc.items() if key != "extension"}
        flat.update(nested)
        return flat
    return dict(doc)


def manifest_from_dict(data: dict[str, Any]) -> ExtensionManifest:
    """Build a frozen manifest. Hostile keys fail closed with a typed error."""
    if not isinstance(data, dict):
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, "manifest must be a mapping")
    trust_hits = find_self_declared_trust(data)
    if trust_hits:
        raise ExtensionError(
            ExtensionErrorCode.AUTHORITY_DECLARED,
            f"manifest declares trust/authority fields: {', '.join(trust_hits[:4])}",
        )
    try:
        return ExtensionManifest(**normalize_manifest_dict(data))
    except ExtensionError:
        raise
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError and friends
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"{exc}") from None


def manifest_to_dict(manifest: ExtensionManifest) -> dict[str, Any]:
    """Canonical JSON-mode payload (stable key order at dump time only)."""
    return manifest.model_dump(mode="json")


def _require_yaml() -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - yaml is a hard dependency
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"yaml support missing: {exc}") from exc
    return yaml


def load_manifest_text(text: str, *, source: str = "") -> ExtensionManifest:
    """Parse manifest text (JSON or YAML) without touching the filesystem."""
    if not isinstance(text, str) or not text.strip():
        raise ExtensionError(ExtensionErrorCode.MANIFEST_MISSING, f"empty manifest text: {source}")
    stripped = text.lstrip()
    try:
        if stripped.startswith("{"):
            doc = json.loads(text)
        else:
            yaml = _require_yaml()
            doc = yaml.safe_load(text)
    except ExtensionError:
        raise
    except Exception as exc:  # noqa: BLE001 - parse failures are content failures
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"parse failed for {source}: {exc}") from None
    if not isinstance(doc, dict):
        raise ExtensionError(ExtensionErrorCode.MANIFEST_INVALID, f"manifest root must be a mapping: {source}")
    return manifest_from_dict(doc)


def load_manifest_file(path: str | Path) -> ExtensionManifest:
    """Read one manifest file. Reads only; never imports, never writes."""
    target = Path(path)
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExtensionError(ExtensionErrorCode.MANIFEST_MISSING, f"cannot read manifest {target.name}: {exc}") from None
    return load_manifest_text(text, source=target.name)


def validate_against_schema(data: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    """Cross-check a raw manifest against the published JSON schema."""
    try:
        import jsonschema as _js
    except ImportError as exc:  # pragma: no cover - jsonschema is a dependency
        raise ExtensionError(ExtensionErrorCode.SCHEMA_INVALID, "schema cross-check needs jsonschema") from exc
    if schema is None:
        from pathlib import Path as _Path

        schema_path = _Path(__file__).resolve().parents[3] / "docs" / "schemas" / "extension-manifest.schema.json"
        if schema_path.is_file():
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        else:
            try:
                from emo_cyber_agent.core.resources import load_schema_text

                schema = json.loads(load_schema_text("extension-manifest"))
            except Exception as exc:  # noqa: BLE001 - schema unavailability is typed
                raise ExtensionError(ExtensionErrorCode.SCHEMA_INVALID, f"extension manifest schema unavailable: {exc}") from None
    assert isinstance(schema, dict), "schema unavailable"
    try:
        _js.validate(data, schema)
    except Exception as exc:  # noqa: BLE001 - jsonschema raises many types
        raise ExtensionError(ExtensionErrorCode.SCHEMA_INVALID, f"schema validation failed: {exc}") from None
