"""Official task library loader — POST-RC-002.

YAML files under templates/tasks/official/ are the canonical authoring
artifacts. This loader parses (PyYAML when available, else explicit
UNSUPPORTED directing callers to the dict API), normalizes to the flat
task.schema.json shape, cross-validates, and registers with TRUSTED
provenance assigned BY THE LOADER (never self-declared).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emo_cyber_agent.tasks.registry import TaskRegistry
from emo_cyber_agent.tasks.spec import TaskError, TaskErrorCode, TaskSpec, TaskTrust


def _require_yaml() -> Any:
    try:
        import yaml as _yaml

        return _yaml
    except ImportError as e:
        raise TaskError(TaskErrorCode.INVALID, "YAML parsing needs pyyaml; use register(TaskSpec) directly") from e


def load_yaml_text(text: str) -> dict[str, Any]:
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        raise TaskError(TaskErrorCode.INVALID, f"malformed YAML: {e}") from e
    if not isinstance(doc, dict) or "task" not in doc:
        raise TaskError(TaskErrorCode.INVALID, "YAML must contain a top-level task mapping")
    return doc


def normalize_task_dict(doc: dict[str, Any]) -> dict[str, Any]:
    """Flat authoring shape (task: identity block + top-level sections, per
    templates/tasks/TASK-TEMPLATE.yaml) → flat task.schema.json shape."""
    t = doc.get("task", {})
    scope = doc.get("scope", {})
    inputs = doc.get("inputs", {})
    skills = doc.get("skills", {})
    caps = doc.get("capabilities", {})
    tools = doc.get("tools", {})
    meth = doc.get("methodology", {})
    ev = doc.get("evidence", {})
    ver = doc.get("verification", {})
    sec = doc.get("security_constraints", {})
    rep = doc.get("report", {})
    return {
        "task_id": t.get("id", ""),
        "name": t.get("title", ""),
        "version": t.get("version", ""),
        "type": t.get("type", "audit"),
        "objective": t.get("objective", ""),
        "scope": {"included": list(scope.get("included", [])), "excluded": list(scope.get("excluded", [])), "target_types": list(scope.get("target_types", []))},
        "inputs_required": list(inputs.get("required", [])),
        "inputs_optional": list(inputs.get("optional", [])),
        "required_skills": list(skills.get("required", [])),
        "optional_skills": list(skills.get("optional", [])),
        "required_capabilities": list(caps.get("required", [])),
        "denied_capabilities": list(caps.get("denied", [])),
        "required_tools": list(tools.get("required", [])),
        "optional_tools": list(tools.get("optional", [])),
        "methodology_phases": list(meth.get("phases", [])),
        "methodology_procedures": list(meth.get("procedures", [])),
        "evidence_required": list(ev.get("required", [])),
        "evidence_provenance_required": bool(ev.get("provenance_required", True)),
        "evidence_minimum_quality": str(ev.get("minimum_quality", "sourced-with-locator")),
        "verification_required": bool(ver.get("required", True)),
        "verification_methods": list(ver.get("methods", [])),
        "verification_confirmation": str(ver.get("confirmation", "")),
        "verification_refutation": str(ver.get("refutation", "")),
        "verification_stop_conditions": list(ver.get("stop_conditions", [])),
        "security_read_only_default": bool(sec.get("read_only_default", True)),
        "security_forbidden_actions": list(sec.get("forbidden_actions", [])),
        "security_external_targets": str(sec.get("external_targets", "deny")),
        "security_secrets_policy": str(sec.get("secrets_policy", "redact-and-never-persist")),
        "security_untrusted_content": str(sec.get("untrusted_content", "data-only")),
        "stop_conditions": list(doc.get("stop_conditions", ver.get("stop_conditions", []))),
        "acceptance_criteria": list(doc.get("acceptance_criteria", [])),
        "deliverables": list(doc.get("deliverables", [])),
        "report_template": str(rep.get("template", "")),
        "report_required_sections": list(rep.get("required_sections", [])),
        "extends": t.get("extends"),
        "provenance": dict(doc.get("provenance", t.get("provenance", {}))),
    }


def validate_against_schema(flat: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    """Cross-check the normalized dict against docs/schemas/task.schema.json."""
    try:
        import jsonschema as _js
    except ImportError as e:
        raise TaskError(TaskErrorCode.INVALID, "schema cross-check needs jsonschema") from e
    if schema is None:
        import json as _json
        from pathlib import Path as _Path

        schema_path = _Path(__file__).resolve().parents[3] / "docs" / "schemas" / "task.schema.json"
        # packaged fallback
        if not schema_path.is_file():
            try:
                from emo_cyber_agent.core.resources import load_schema_text

                schema = _json.loads(load_schema_text("task"))
            except Exception as e:
                raise TaskError(TaskErrorCode.INVALID, f"task schema unavailable: {e}") from e
        else:
            schema = _json.loads(schema_path.read_text())
    assert isinstance(schema, dict), "schema unavailable"
    try:
        _js.validate(flat, schema)
    except Exception as e:
        raise TaskError(TaskErrorCode.INVALID, f"schema validation failed: {e}") from e


def spec_from_yaml_text(text: str, *, check_schema: bool = True) -> TaskSpec:
    flat = normalize_task_dict(load_yaml_text(text))
    if check_schema:
        validate_against_schema(flat)
    try:
        return TaskSpec(**flat)
    except ValueError as e:
        raise TaskError(TaskErrorCode.INVALID, f"TaskSpec construction failed: {e}") from e


def load_official_registry(directory: str | Path, *, skill_registry: Any = None, tool_registry: Any = None) -> TaskRegistry:
    """Load every official YAML, validate (incl. skill/tool references), and
    register with loader-assigned TRUSTED provenance."""
    from emo_cyber_agent.tasks.validator import TaskValidator

    directory = Path(directory)
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise TaskError(TaskErrorCode.NOT_FOUND, f"no official tasks in {directory}")
    registry = TaskRegistry()
    validator = TaskValidator(skill_registry=skill_registry, tool_registry=tool_registry)
    for path in files:
        spec = spec_from_yaml_text(path.read_text())
        validation = validator.validate(spec)
        if not validation.valid:
            raise TaskError(TaskErrorCode.INVALID, f"official task invalid {spec.task_id}: {validation.errors}")
        registry.register(spec, trust=TaskTrust.TRUSTED)
    if registry.check_cycles():
        raise TaskError(TaskErrorCode.DEPENDENCY_CYCLE, f"official cycles: {registry.check_cycles()}")
    return registry
