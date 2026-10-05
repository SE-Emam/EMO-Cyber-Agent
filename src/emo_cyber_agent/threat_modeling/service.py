"""Threat modeling service — POST-RC-009.

Core-owned orchestration: system model → attack surface →
method elicitation → scenarios → paths → controls → handoffs →
evidence → report view. Read-only, deterministic, planning-only.
No tool execution, no Finding creation, no confirmation.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.attack_surface import build_attack_surface
from emo_cyber_agent.threat_modeling.controls import CATEGORY_CONTROLS, expected_controls, observe_controls
from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.methods import get_method
from emo_cyber_agent.threat_modeling.paths import find_attack_paths
from emo_cyber_agent.threat_modeling.provenance import build_threat_provenance
from emo_cyber_agent.threat_modeling.spec import (
    Mitigation,
    ModelCoverage,
    ThreatAssessment,
    ThreatModel,
    ThreatScenario,
    ThreatTemplateConfig,
    ThreatVerificationHandoff,
    assert_no_threat_verdicts,
    canonical_digest as _canonical_digest,
    stable_id,
)
from emo_cyber_agent.threat_modeling.stride import elicit_stride
from emo_cyber_agent.threat_modeling.system_model import build_system_model
from emo_cyber_agent.threat_modeling.threats import build_threat_scenarios

# Deterministic skill → method selection (no model, no LLM).
SKILL_METHODS: dict[str, tuple[str, ...]] = {
    "authorization": ("stride", "attack-tree"),
    "authentication": ("stride",),
    "api-security": ("stride", "data-centric"),
    "injection": ("stride", "data-centric"),
    "business-logic": ("attack-tree", "data-centric"),
    "database-security": ("stride", "data-centric"),
    "threat-modeling": ("stride", "attack-tree", "data-centric"),
}

# Deterministic change-predicate → method refresh mapping.
PREDICATE_METHODS: dict[str, tuple[str, ...]] = {
    "AUTH_BOUNDARY_CHANGED": ("stride",),
    "ROUTE_PERMISSION_CHANGED": ("stride",),
    "STATE_CHANGE_ADDED": ("stride", "attack-tree"),
    "NEW_EXTERNAL_INPUT": ("stride", "data-centric"),
    "NEW_SINK": ("data-centric",),
    "NEW_TAINT_PATH": ("data-centric", "stride"),
    "TAINT_PATH_MODIFIED": ("data-centric",),
    "DEPENDENCY_VERSION_CHANGED": ("attack-tree",),
    "SECRET_HANDLING_CHANGED": ("stride",),
    "FILE_ACCESS_CHANGED": ("stride",),
    "DATABASE_ACCESS_CHANGED": ("data-centric", "stride"),
    "CONFIG_SECURITY_CHANGE": ("stride",),
}

# Deterministic threat-category → verification method handoff.
CATEGORY_METHODS: dict[str, str] = {
    "SPOOFING": "static_confirmation",
    "TAMPERING": "static_confirmation",
    "REPUDIATION": "static_confirmation",
    "INFORMATION_DISCLOSURE": "static_confirmation",
    "DENIAL_OF_SERVICE": "static_confirmation",
    "ELEVATION_OF_PRIVILEGE": "static_confirmation",
    "GOAL_DECOMPOSITION": "static_confirmation",
    "DATA_FLOW_RISK": "static_confirmation",
}


class ThreatModelingService:
    def __init__(self, *, max_paths: int = 25, max_length: int = 8):
        self._max_paths = max_paths
        self._max_length = max_length

    def build_model(
        self,
        *,
        model_id: str,
        audit_id: str,
        project_id: str = "",
        snapshot_id: str,
        methods: tuple[str, ...] = ("stride",),
        code_graph: Any = None,
        codeintel_capabilities: tuple[str, ...] = (),
        declared_assets: tuple[dict[str, Any], ...] = (),
        declared_boundaries: tuple[dict[str, Any], ...] = (),
        declared_actors: tuple[dict[str, Any], ...] = (),
        secret_symbols: tuple[str, ...] = (),
        evidence_index: dict[str, tuple[str, ...]] | None = None,
    ) -> ThreatModel:
        for method in methods:
            get_method(method)
        system = build_system_model(
            audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id, code_graph=code_graph,
            declared_assets=declared_assets, declared_boundaries=declared_boundaries, declared_actors=declared_actors,
        )
        surface = build_attack_surface(
            system, code_graph=code_graph, codeintel_capabilities=codeintel_capabilities,
            secret_symbols=secret_symbols, evidence_index=evidence_index or {},
        )
        candidates: list[dict[str, Any]] = []
        if "stride" in methods:
            candidates.extend(self._elicit_stride_filtered(system, code_graph))
        if "attack-tree" in methods:
            candidates.extend({
                "method": "attack-tree", "category": "GOAL_DECOMPOSITION", "subject": entry.entry_id,
                "subject_kind": "entry",
                "preconditions": (f"entry {entry.method} {entry.path} reachable",),
                "attack_goal": f"achieve objective through {entry.entry_id}",
                "required_evidence": ("entry-record",),
                "limitations": ("goal decomposition only: sub-goals need their own evidence",),
            } for entry in system.entries)
        if "data-centric" in methods:
            candidates.extend({
                "method": "data-centric", "category": "DATA_FLOW_RISK", "subject": flow.flow_id,
                "subject_kind": "flow",
                "preconditions": (f"flow {flow.source} -> {flow.target}",),
                "attack_goal": f"abuse data movement through {flow.flow_id}",
                "required_evidence": ("flow-record",),
                "limitations": ("flow presence only: exposure needs a demonstrated reader",),
            } for flow in system.flows)
        route_evidence: dict[str, tuple[str, ...]] = {}
        if evidence_index:
            for subject, ids in evidence_index.items():
                route_evidence[subject] = tuple(ids)
        categories = sorted({c["category"] for c in candidates})
        scenarios, _hypotheses = build_threat_scenarios(
            candidates, evidence_index=route_evidence,
            possible_controls={c: tuple(f"expected-{c.lower().replace('_', '-')}-{k.lower().replace('_', '-')}" for k in CATEGORY_CONTROLS.get(c, {}).get("controls", ())) for c in categories},
        )
        paths: list[Any] = []
        partial = False
        if code_graph is not None:
            paths, partial = find_attack_paths(code_graph, audit_id=audit_id, max_paths=self._max_paths, max_length=self._max_length)
        observed = observe_controls(code_graph)
        expected = expected_controls(tuple(categories))
        handoffs = self._handoffs(audit_id, snapshot_id, scenarios)
        mitigations = self._mitigations(scenarios)
        limitations = list(system.limitations) + list(surface.limitations)
        if partial:
            limitations.append("attack-path budget exhausted: partial path coverage")
        assessment = ThreatAssessment(
            scenario_count=len(scenarios), surface_count=len(surface.elements),
            boundary_count=len(system.boundaries), control_count=len(observed) + len(expected),
            coverage=surface.completeness, limitations=tuple(limitations),
        )
        coverage = ModelCoverage(
            endpoints=surface.completeness, boundaries=surface.completeness,
            flows=surface.completeness, assets=surface.completeness,
        )
        digest = _canonical_digest({
            "audit": audit_id, "project": project_id, "snapshot": snapshot_id, "methods": sorted(methods),
            "system": _stable(system.model_dump(mode="json", exclude={"limitations"})),
            "surface": [_stable(e.model_dump(mode="json")) for e in surface.elements],
            "scenarios": [s.model_dump(mode="json") for s in scenarios],
            "paths": [p.model_dump(mode="json") for p in paths],
            "controls": [c.model_dump(mode="json") for c in (*observed, *expected)],
        })
        return ThreatModel(
            model_id=model_id, audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id,
            methods=tuple(methods), system=system, surface=surface, scenarios=tuple(scenarios),
            attack_paths=tuple(paths), controls=tuple([*observed, *expected]), mitigations=tuple(mitigations),
            handoffs=tuple(handoffs), assessment=assessment, coverage=coverage,
            limitations=tuple(limitations), model_digest=digest,
        )

    def _elicit_stride_filtered(self, system: Any, code_graph: Any) -> list[dict[str, Any]]:

        return elicit_stride(system)

    def refresh_from_change(
        self,
        model: ThreatModel,
        predicates_fired: dict[str, list[str]],
        *,
        code_graph: Any = None,
        codeintel_capabilities: tuple[str, ...] = (),
    ) -> ThreatModel:
        """Change signals trigger targeted re-elicitation, never verdicts."""
        methods: list[str] = []
        for predicate in sorted(predicates_fired):
            methods.extend(m for m in PREDICATE_METHODS.get(predicate, ()) if m not in methods)
        if not methods:
            methods = list(model.methods)
        refreshed = self.build_model(
            model_id=f"{model.model_id}-refresh", audit_id=model.audit_id, project_id=model.project_id,
            snapshot_id=model.snapshot_id, methods=tuple(methods), code_graph=code_graph,
            codeintel_capabilities=codeintel_capabilities,
        )
        return refreshed.model_copy(update={"limitations": tuple([*refreshed.limitations, f"refresh triggered by change predicates: {','.join(sorted(predicates_fired)) or 'none'}"])})

    def select_methods_for_skills(self, skills: tuple[str, ...]) -> tuple[str, ...]:
        methods: list[str] = []
        for skill in skills:
            methods.extend(m for m in SKILL_METHODS.get(skill, ()) if m not in methods)
        return tuple(methods)

    def build_handoffs(self, scenarios: tuple[ThreatScenario, ...], *, snapshot_id: str) -> list[ThreatVerificationHandoff]:
        return self._handoffs("", snapshot_id, list(scenarios))

    def _handoffs(self, audit_id: str, snapshot_id: str, scenarios: list[ThreatScenario]) -> list[ThreatVerificationHandoff]:
        handoffs: list[ThreatVerificationHandoff] = []
        for index, scenario in enumerate(sorted(scenarios, key=lambda s: s.scenario_id)):
            handoffs.append(ThreatVerificationHandoff(
                handoff_id=f"threat-handoff-{index + 1:03d}", threat_scenario_id=scenario.scenario_id,
                target_snapshot_id=snapshot_id, target_component=scenario.affected_components[0] if scenario.affected_components else scenario.subject,
                target_entrypoint=scenario.subject, required_evidence=tuple(scenario.verification_requirements),
                verification_method=CATEGORY_METHODS.get(scenario.category, "static_confirmation"),
                safety_level="passive",
                success_criteria=f"supporting evidence recorded for {scenario.scenario_id}"[:500],
                refutation_criteria=f"contradicting evidence recorded for {scenario.scenario_id}"[:500],
                compatible_snapshots=(snapshot_id,),
            ))
        assert_no_threat_verdicts(*[h.success_criteria for h in handoffs])
        return handoffs

    def _mitigations(self, scenarios: list[ThreatScenario]) -> list[Any]:

        mitigations = []
        for scenario in sorted(scenarios, key=lambda s: s.scenario_id):
            for control in scenario.possible_controls:
                mitigations.append(Mitigation(
                    mitigation_id=stable_id("mitigation", scenario.scenario_id, control), control=control,
                    rationale=f"planning information for {scenario.scenario_id}; effectiveness unverified"[:500],
                    affected_component=scenario.subject, evidence_needed=("control-evidence",),
                    verification_needed=("control-verification",),
                ))
        return mitigations

    def check_handoff(self, handoff: ThreatVerificationHandoff, *, current_snapshot_id: str) -> None:
        if current_snapshot_id != handoff.target_snapshot_id and current_snapshot_id not in handoff.compatible_snapshots:
            raise ThreatModelError(ThreatModelErrorCode.VERIFICATION_STALE, f"handoff {handoff.handoff_id} not compatible with snapshot {current_snapshot_id}")

    def build_evidence(self, model: ThreatModel) -> list[Any]:
        from emo_cyber_agent.core.repository import redact_credentials
        from emo_cyber_agent.domain.models import EvidenceItem


        items: list[Any] = []
        for scenario in model.scenarios:
            summary = redact_credentials(f"threat hypothesis {scenario.method}/{scenario.category} subject={scenario.subject} status={scenario.hypothesis_status}")[:400]
            assert_no_threat_verdicts(summary)
            items.append(EvidenceItem(
                source_tool="threat-modeling", source_version="1.0",
                target_asset_id=model.project_id or None, location=f"scenario:{scenario.scenario_id}",
                content_summary=summary, content_hash=_canonical_digest({"summary": summary}),
                provenance=build_threat_provenance(
                    audit_id=model.audit_id, project_id=model.project_id, snapshot_id=model.snapshot_id,
                    subject_id=scenario.scenario_id, model_digest=model.model_digest,
                    coverage=scenario.coverage,
                ),
            ))
        return items

    def report_view(self, model: ThreatModel, evidence_ids: tuple[str, ...] = ()) -> dict[str, Any]:
        view = {
            "model_id": model.model_id, "methods": list(model.methods),
            "system_summary": {
                "actors": len(model.system.actors) if model.system else 0,
                "components": len(model.system.components) if model.system else 0,
                "entries": len(model.system.entries) if model.system else 0,
                "flows": len(model.system.flows) if model.system else 0,
                "boundaries": len(model.system.boundaries) if model.system else 0,
            },
            "attack_surface": {
                "completeness": model.surface.completeness if model.surface else "UNKNOWN",
                "elements": [e.model_dump(mode="json") for e in model.surface.elements] if model.surface else [],
            },
            "trust_boundaries": [b.model_dump(mode="json") for b in model.system.boundaries] if model.system else [],
            "threat_scenarios": [s.model_dump(mode="json") for s in model.scenarios],
            "affected_assets": sorted({a for s in model.scenarios for a in s.affected_assets}),
            "security_controls": [c.model_dump(mode="json") for c in model.controls],
            "evidence_references": list(evidence_ids),
            "coverage": model.coverage.model_dump(mode="json"),
            "limitations": list(model.limitations),
            "verification_handoffs": [h.model_dump(mode="json") for h in model.handoffs],
            "model_digest": model.model_digest,
        }
        assert_no_threat_verdicts(json_dump(view))
        return view

    def load_official_templates(self, directory: Any) -> list[ThreatTemplateConfig]:
        from pathlib import Path as _Path

        from emo_cyber_agent.threat_modeling.spec import ThreatTemplateConfig as _Config

        try:
            import yaml as _yaml
        except ImportError as e:
            raise ThreatModelError(ThreatModelErrorCode.INVALID, "YAML parsing needs pyyaml") from e
        templates: list[ThreatTemplateConfig] = []
        paths = sorted(_Path(directory).glob("*.yaml"))
        if not paths:
            raise ThreatModelError(ThreatModelErrorCode.INVALID, f"no threat templates in {directory}")
        for path in paths:
            try:
                doc = _yaml.safe_load(path.read_text())
            except Exception as e:
                raise ThreatModelError(ThreatModelErrorCode.INVALID, f"malformed template YAML: {e}") from e
            if not isinstance(doc, dict) or "threat_template" not in doc:
                raise ThreatModelError(ThreatModelErrorCode.INVALID, "template YAML must contain a top-level threat_template mapping")
            raw = doc["threat_template"]
            try:
                template = _Config(
                    template_id=str(raw.get("id", "")), name=str(raw.get("name", "")), version=str(raw.get("version", "")),
                    methods=tuple(raw.get("methods", ())), scope_assets=tuple(raw.get("scope_assets", ())),
                    declared_boundaries=tuple(raw.get("declared_boundaries", ())), provenance=dict(doc.get("provenance", {})),
                )
            except ValueError as e:
                raise ThreatModelError(ThreatModelErrorCode.INVALID, f"template invalid: {e}") from e
            for method in template.methods:
                get_method(method)
            templates.append(template)
        return templates


_VOLATILE_KEYS = {"observed_at", "timestamp", "captured_at", "created_at"}


def _stable(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: _stable(v) for k, v in payload.items() if k not in _VOLATILE_KEYS}
    if isinstance(payload, list):
        return [_stable(v) for v in payload]
    return payload


def json_dump(payload: Any) -> str:
    import json as _json

    return _json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
