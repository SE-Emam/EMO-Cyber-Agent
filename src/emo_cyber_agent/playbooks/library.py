"""Official playbook library loader — POST-RC-004.

YAML files under templates/playbooks/official/ are the canonical
authoring artifacts. The loader parses, normalizes to the flat
playbook.schema.json shape, cross-validates, and registers with
loader-assigned TRUSTED provenance (never self-declared).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emo_cyber_agent.playbooks.registry import PlaybookRegistry
from emo_cyber_agent.playbooks.spec import PlaybookError, PlaybookErrorCode, PlaybookSpec, PlaybookTrust
from emo_cyber_agent.playbooks.validator import PlaybookValidator


def _require_yaml() -> Any:
    try:
        import yaml as _yaml

        return _yaml
    except ImportError as e:
        raise PlaybookError(PlaybookErrorCode.INVALID, "YAML parsing needs pyyaml; use register(PlaybookSpec) directly") from e


def load_yaml_text(text: str) -> dict[str, Any]:
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        raise PlaybookError(PlaybookErrorCode.INVALID, f"malformed YAML: {e}") from e
    if not isinstance(doc, dict) or "playbook" not in doc:
        raise PlaybookError(PlaybookErrorCode.INVALID, "YAML must contain a top-level playbook mapping")
    return doc


def normalize_playbook_dict(doc: dict[str, Any]) -> dict[str, Any]:
    p = doc.get("playbook", {})
    tasks = doc.get("tasks", {})
    skills = doc.get("skills", {})
    tools = doc.get("tools", {})
    caps = doc.get("capabilities", {})
    ex = doc.get("execution", {})
    ev = doc.get("evidence", {})
    ver = doc.get("verification", {})
    sec = doc.get("security", {})
    rep = doc.get("report", {})
    return {
        "playbook_id": p.get("id", ""),
        "title": p.get("title", ""),
        "version": p.get("version", ""),
        "type": p.get("type", "security"),
        "objective": p.get("objective", ""),
        "description": p.get("description", ""),
        "required_tasks": list(tasks.get("required", [])),
        "optional_tasks": list(tasks.get("optional", [])),
        "required_skills": list(skills.get("required", [])),
        "optional_skills": list(skills.get("optional", [])),
        "required_tools": list(tools.get("required", [])),
        "optional_tools": list(tools.get("optional", [])),
        "requested_capabilities": list(caps.get("requested", [])),
        "denied_capabilities": list(caps.get("denied", [])),
        "execution_order": list(ex.get("order", [])),
        "conditions": [{"when_field": c.get("when_field", ""), "operator": c.get("operator", "=="), "value": c.get("value"), "select_tasks": list(c.get("select_tasks", []))} for c in ex.get("conditions", [])],
        "max_tasks": int(ex.get("max_tasks", 12)),
        "max_iterations": int(ex.get("max_iterations", 1)),
        "evidence_required": list(ev.get("required", [])),
        "evidence_provenance_required": bool(ev.get("provenance_required", True)),
        "verification_required": bool(ver.get("required", True)),
        "verification_methods": list(ver.get("methods", [])),
        "report_template": str(rep.get("template", "")),
        "stop_conditions": list(doc.get("stop_conditions", [])),
        "acceptance_criteria": list(doc.get("acceptance_criteria", [])),
        "security_read_only_default": bool(sec.get("read_only_default", True)),
        "security_forbidden_actions": list(sec.get("forbidden_actions", [])),
        "security_external_targets": str(sec.get("external_targets", "deny")),
        "security_secrets_policy": str(sec.get("secrets_policy", "strict")),
        "security_untrusted_content": bool(sec.get("untrusted_content", True)),
        "extends": p.get("extends"),
        "dependencies": list(p.get("dependencies", [])),
        "provenance": dict(doc.get("provenance", {})),
    }


def validate_against_schema(flat: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    try:
        import jsonschema as _js
    except ImportError as e:
        raise PlaybookError(PlaybookErrorCode.INVALID, "schema cross-check needs jsonschema") from e
    if schema is None:
        import json as _json
        from pathlib import Path as _Path

        schema_path = _Path(__file__).resolve().parents[3] / "docs" / "schemas" / "playbook.schema.json"
        if schema_path.is_file():
            schema = _json.loads(schema_path.read_text())
        else:
            try:
                from emo_cyber_agent.core.resources import load_schema_text

                schema = _json.loads(load_schema_text("playbook"))
            except Exception as e:
                raise PlaybookError(PlaybookErrorCode.INVALID, f"playbook schema unavailable: {e}") from e
    assert isinstance(schema, dict), "schema unavailable"
    try:
        _js.validate(flat, schema)
    except Exception as e:
        raise PlaybookError(PlaybookErrorCode.INVALID, f"schema validation failed: {e}") from e


def spec_from_yaml_text(text: str, *, check_schema: bool = True) -> PlaybookSpec:
    flat = normalize_playbook_dict(load_yaml_text(text))
    if check_schema:
        validate_against_schema(flat)
    try:
        return PlaybookSpec(**flat)
    except ValueError as e:
        raise PlaybookError(PlaybookErrorCode.INVALID, f"PlaybookSpec construction failed: {e}") from e


def load_official_registry(directory: str | Path) -> PlaybookRegistry:
    directory = Path(directory)
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise PlaybookError(PlaybookErrorCode.NOT_FOUND, f"no official playbooks in {directory}")
    registry = PlaybookRegistry()
    validator = PlaybookValidator()
    for path in files:
        spec = spec_from_yaml_text(path.read_text())
        result = validator.validate(spec)
        if not result.valid:
            raise PlaybookError(PlaybookErrorCode.INVALID, f"official playbook invalid {spec.playbook_id}: {result.errors}")
        registry.register(spec, trust=PlaybookTrust.TRUSTED)
    if registry.check_cycles():
        raise PlaybookError(PlaybookErrorCode.INVALID, f"official cycles: {registry.check_cycles()}")
    return registry
