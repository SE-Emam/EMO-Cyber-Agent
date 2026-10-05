"""Official report template library loader — POST-RC-003.

YAML files under templates/reports/official/ are the canonical authoring
artifacts. The loader parses, normalizes to the flat
report-template.schema.json shape, cross-validates, composes extends
chains (child adds sections/fields only; mandatory fields and security
defaults can never be weakened), and registers with loader-assigned
TRUSTED provenance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emo_cyber_agent.report_templates.registry import ReportTemplateRegistry
from emo_cyber_agent.report_templates.spec import (
    ReportTemplateSpec,
    TemplateError,
    TemplateErrorCode,
    TemplateTrust,
)
from emo_cyber_agent.report_templates.validator import ReportTemplateValidator


def _require_yaml() -> Any:
    try:
        import yaml as _yaml

        return _yaml
    except ImportError as e:
        raise TemplateError(TemplateErrorCode.INVALID, "YAML parsing needs pyyaml; use register(ReportTemplateSpec) directly") from e


def load_yaml_text(text: str) -> dict[str, Any]:
    yaml = _require_yaml()
    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        raise TemplateError(TemplateErrorCode.INVALID, f"malformed YAML: {e}") from e
    if not isinstance(doc, dict) or "report_template" not in doc:
        raise TemplateError(TemplateErrorCode.INVALID, "YAML must contain a top-level report_template mapping")
    return doc


def normalize_template_dict(doc: dict[str, Any]) -> dict[str, Any]:
    t = doc.get("report_template", {})
    sec = doc.get("security", {})
    return {
        "template_id": t.get("id", ""),
        "name": t.get("name", ""),
        "version": t.get("version", ""),
        "type": t.get("type", "security"),
        "description": t.get("description", ""),
        "sections": [{"name": s.get("name", ""), "fields": list(s.get("fields", [])), "visibility": [dict(v) for v in s.get("visibility", [])]} for s in doc.get("sections", [])],
        "finding_fields": list(doc.get("finding_fields", [])),
        "section_order": list(doc.get("section_order", [])),
        "show_non_reportable": bool(doc.get("show_non_reportable", False)),
        "evidence_presentation": str(doc.get("evidence_presentation", "references")),
        "verification_presentation": str(doc.get("verification_presentation", "status")),
        "limitations_sections": list(doc.get("limitations_sections", ["limitations"])),
        "appendices": list(doc.get("appendices", [])),
        "output_formats": list(doc.get("output_formats", ["json", "jsonl", "markdown"])),
        "extends": doc.get("extends"),
        "preserve_provenance": bool(sec.get("preserve_provenance", True)),
        "redact_secrets": bool(sec.get("redact_secrets", True)),
        "deterministic": bool(sec.get("deterministic", True)),
        "provenance": dict(doc.get("provenance", {})),
    }


def validate_against_schema(flat: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    try:
        import jsonschema as _js
    except ImportError as e:
        raise TemplateError(TemplateErrorCode.INVALID, "schema cross-check needs jsonschema") from e
    if schema is None:
        import json as _json
        from pathlib import Path as _Path

        schema_path = _Path(__file__).resolve().parents[3] / "docs" / "schemas" / "report-template.schema.json"
        if not schema_path.is_file():
            try:
                from emo_cyber_agent.core.resources import load_schema_text

                schema = _json.loads(load_schema_text("report-template"))
            except Exception as e:
                raise TemplateError(TemplateErrorCode.INVALID, f"template schema unavailable: {e}") from e
        else:
            schema = _json.loads(schema_path.read_text())
    assert isinstance(schema, dict), "schema unavailable"
    try:
        _js.validate(flat, schema)
    except Exception as e:
        raise TemplateError(TemplateErrorCode.INVALID, f"schema validation failed: {e}") from e


def spec_from_yaml_text(text: str, *, check_schema: bool = True) -> ReportTemplateSpec:
    flat = normalize_template_dict(load_yaml_text(text))
    if check_schema:
        validate_against_schema(flat)
    try:
        return ReportTemplateSpec(**flat)
    except ValueError as e:
        raise TemplateError(TemplateErrorCode.INVALID, f"ReportTemplateSpec construction failed: {e}") from e


def _compose(base: ReportTemplateSpec, child: ReportTemplateSpec) -> ReportTemplateSpec:
    """Child may add sections/fields/appendices and narrow visibility; it may
    never remove mandatory fields, provenance, verification state, severity,
    limitations, or security defaults. Violations raise COMPOSITION_INVALID."""
    from emo_cyber_agent.report_templates.spec import MANDATORY_FINDING_FIELDS

    merged_fields = tuple(dict.fromkeys((*base.finding_fields, *child.finding_fields)))
    missing = [f for f in MANDATORY_FINDING_FIELDS if f not in merged_fields]
    if missing:
        raise TemplateError(TemplateErrorCode.COMPOSITION_INVALID, f"composition drops mandatory fields: {missing}")
    if not child.preserve_provenance or not child.redact_secrets or not child.deterministic:
        raise TemplateError(TemplateErrorCode.COMPOSITION_INVALID, "composition weakens security defaults")
    base_sections = {s.name: s for s in base.sections}
    merged_sections = list(base.sections)
    for section in child.sections:
        if section.name in base_sections:
            parent = base_sections[section.name]
            merged_sections = [s if s.name != section.name else section.__class__(name=section.name, fields=tuple(dict.fromkeys((*parent.fields, *section.fields))), visibility=parent.visibility + section.visibility) for s in merged_sections]
        else:
            merged_sections.append(section)
    return ReportTemplateSpec(
        template_id=child.template_id, name=child.name, version=child.version, type=child.type, description=child.description,
        sections=tuple(merged_sections), finding_fields=merged_fields,
        section_order=tuple(child.section_order or [s.name for s in merged_sections]),
        show_non_reportable=child.show_non_reportable, evidence_presentation=child.evidence_presentation or base.evidence_presentation,
        verification_presentation=child.verification_presentation or base.verification_presentation,
        limitations_sections=tuple(child.limitations_sections or base.limitations_sections), appendices=tuple(dict.fromkeys((*base.appendices, *child.appendices))),
        output_formats=tuple(f for f in child.output_formats if f in base.output_formats) or base.output_formats,
        preserve_provenance=True, redact_secrets=True, deterministic=True, provenance={**base.provenance, **child.provenance, "composed_from": base.template_id},
    )


def load_official_registry(directory: str | Path) -> ReportTemplateRegistry:
    directory = Path(directory)
    files = sorted(directory.glob("*.yaml"))
    if not files:
        raise TemplateError(TemplateErrorCode.NOT_FOUND, f"no official templates in {directory}")
    raw: dict[str, ReportTemplateSpec] = {}
    validator = ReportTemplateValidator()
    for path in files:
        spec = spec_from_yaml_text(path.read_text())
        ok, _, errors, _ = validator.validate(spec)
        if not ok:
            raise TemplateError(TemplateErrorCode.INVALID, f"official template invalid {spec.template_id}: {errors}")
        raw[spec.template_id] = spec
    registry = ReportTemplateRegistry()
    for spec in raw.values():
        final = spec
        if spec.extends:
            if spec.extends not in raw:
                raise TemplateError(TemplateErrorCode.INVALID, f"unknown base template: {spec.extends}")
            final = _compose(raw[spec.extends], spec)
            ok, _, errors, _ = validator.validate(final)
            if not ok:
                raise TemplateError(TemplateErrorCode.COMPOSITION_INVALID, f"composed template invalid {spec.template_id}: {errors}")
        registry.register(final, trust=TemplateTrust.TRUSTED)
    if registry.check_cycles():
        raise TemplateError(TemplateErrorCode.INVALID, f"official cycles: {registry.check_cycles()}")
    return registry
