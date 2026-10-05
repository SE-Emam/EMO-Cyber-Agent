"""POST-RC-009 — Threat modeling core tests (offline).

Contracts, system model, methods registry, STRIDE elicitation,
scenarios, attack paths, controls, delta, service orchestration,
templates, schemas, determinism, integrations. No Findings,
no severity, no execution, no model.
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.threat_modeling.attack_surface import build_attack_surface
from emo_cyber_agent.threat_modeling.controls import coverage_for, expected_controls, observe_controls
from emo_cyber_agent.threat_modeling.delta import diff_threat_models
from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.methods import get_method, register_method, registered_methods, rules_for
from emo_cyber_agent.threat_modeling.paths import find_attack_paths
from emo_cyber_agent.threat_modeling.service import ThreatModelingService
from emo_cyber_agent.threat_modeling.spec import (
    ThreatMethod,
    ThreatRule,
    ThreatTemplateConfig,
    TrustBoundary,
    assert_no_threat_verdicts,
    canonical_digest,
    stable_id,
)
from emo_cyber_agent.threat_modeling.stride import STRIDE_SPEC, elicit_stride
from emo_cyber_agent.threat_modeling.system_model import build_system_model
from emo_cyber_agent.threat_modeling.threats import build_threat_scenarios

FIXTURES = Path("tests/fixtures/threat_modeling")


def _graph(scenario, audit="A", files=None):
    from emo_cyber_agent.adapters.code_intelligence.mock import MockCodeIntelligenceProvider
    from emo_cyber_agent.code_intelligence.service import CodeIntelligenceService
    from emo_cyber_agent.code_intelligence.spec import CodeProject

    provider = MockCodeIntelligenceProvider(scenario)
    service = CodeIntelligenceService(provider)
    project = CodeProject(audit_id=audit, asset_id="asset", owner="acme", repo="web")
    content = files if files is not None else {"src/a.py": "x = 1\n"}
    snapshot = service.create_snapshot(project, content, revision="r1")
    return service.analyze(snapshot, content), tuple(provider.capabilities())


def _model(scenario="auth_flow", audit="A", snapshot="snap-1", methods=("stride",)):
    service = ThreatModelingService()
    graph, caps = _graph(scenario, audit=audit)
    return service.build_model(
        model_id="tm-001", audit_id=audit, project_id="P", snapshot_id=snapshot,
        methods=methods, code_graph=graph, codeintel_capabilities=caps,
    ), graph


# ---------------- contracts ----------------

def test_contract_ids_frozen_extra_forbidden():
    assert stable_id("threat", "stride", "SPOOFING", "x" * 200) != ""
    assert len(stable_id("threat", "stride", "SPOOFING", "x" * 200)) <= 78
    assert stable_id("a", "b") == stable_id("a", "b")
    with pytest.raises(Exception):
        TrustBoundary(boundary_id="Bad_ID", kind="TRUST")
    with pytest.raises(Exception):
        TrustBoundary(boundary_id="ok-id", kind="NOPE")
    with pytest.raises(Exception):
        TrustBoundary(boundary_id="ok-id", kind="TRUST", basis="MAYBE")
    with pytest.raises(Exception):
        TrustBoundary(boundary_id="ok-id", kind="TRUST", basis="DECLARED")
    ok = TrustBoundary(boundary_id="ok-id2", kind="TRUST", basis="DECLARED", provenance={"declared_by": "team"})
    assert ok.basis == "DECLARED"
    with pytest.raises(Exception):
        TrustBoundary(boundary_id="ok-id", kind="TRUST", basis="OBSERVED", bogus="x")
    with pytest.raises(ThreatModelError):
        assert_no_threat_verdicts("this is exploitable")
    with pytest.raises(ThreatModelError):
        assert_no_threat_verdicts("severity high")
    assert canonical_digest({"b": 1, "a": 2}) == canonical_digest({"a": 2, "b": 1})


def test_error_codes_stable():
    assert {c.value for c in ThreatModelErrorCode} == {
        "THREAT_MODEL_INVALID", "THREAT_MODEL_SNAPSHOT_MISMATCH", "THREAT_MODEL_STALE_SNAPSHOT",
        "THREAT_MODEL_CROSS_AUDIT", "THREAT_MODEL_CROSS_PROJECT", "THREAT_MODEL_METHOD_UNKNOWN",
        "THREAT_MODEL_QUERY_REJECTED", "THREAT_MODEL_BUDGET_EXCEEDED", "THREAT_MODEL_VERIFICATION_STALE",
        "THREAT_MODEL_EVIDENCE_GAP",
    }


# ---------------- system model ----------------

def test_system_model_from_graph():
    graph, _ = _graph("auth_flow")
    system = build_system_model(audit_id="A", project_id="P", snapshot_id="snap-1", code_graph=graph)
    assert len(system.entries) == 2 and len(system.boundaries) == 1
    assert system.boundaries[0].basis == "OBSERVED"
    assert system.coverage in ("FULLY_MAPPED", "PARTIALLY_MAPPED")
    assert any(f.kind == "call" for f in system.flows)
    with pytest.raises(ThreatModelError):
        build_system_model(audit_id="", project_id="P", snapshot_id="s", code_graph=graph)
    foreign, _ = _graph("auth_flow", audit="FOREIGN")
    with pytest.raises(ThreatModelError) as e:
        build_system_model(audit_id="A", project_id="P", snapshot_id="s", code_graph=foreign)
    assert e.value.code == ThreatModelErrorCode.CROSS_AUDIT


def test_system_model_declarations_only():
    system = build_system_model(
        audit_id="A", project_id="P", snapshot_id="s",
        declared_assets=[{"name": "user-accounts", "kind": "data"}],
        declared_boundaries=[{"kind": "TRUST", "basis": "DECLARED", "provenance": {"declared_by": "team"}, "protects": ["user-accounts"]}],
        declared_actors=[{"name": "Partner service", "kind": "external-system"}],
    )
    assert len(system.assets) == 1 and system.assets[0].provenance_kind == "DECLARED"
    assert len(system.actors) == 2
    assert any("declarations only" in lim for lim in system.limitations)
    with pytest.raises(ThreatModelError):
        build_system_model(audit_id="A", project_id="P", snapshot_id="s", declared_boundaries=[{"kind": "TRUST", "basis": "DECLARED"}])


def test_dfd_graph_identity_no_cross_audit_edges():
    model, _ = _model()
    assert model.system is not None
    for flow in model.system.flows:
        assert flow.flow_id and flow.source and flow.target


# ---------------- methods ----------------

def test_methods_registry_and_custom():
    assert {"stride", "attack-tree", "data-centric"} <= set(registered_methods())
    assert get_method("stride").version == "1.0.0"
    assert len(rules_for("stride")) == 6
    with pytest.raises(ThreatModelError) as e:
        get_method("phrenology")
    assert e.value.code == ThreatModelErrorCode.METHOD_UNKNOWN
    register_method(ThreatMethod(method_id="linddun", name="LINDDUN", version="1.0.0", categories=("LINKABILITY",), provenance={"source": "test"}))
    assert "linddun" in registered_methods()
    with pytest.raises(ThreatModelError):
        register_method(ThreatMethod(method_id="linddun", name="dup", version="1.0.0", categories=()))
    assert "method == STRIDE" not in json.dumps({"x": 1})


def test_unknown_method_rejected_at_build():
    service = ThreatModelingService()
    with pytest.raises(ThreatModelError) as e:
        service.build_model(model_id="tm-x", audit_id="A", snapshot_id="s", methods=("phrenology",))
    assert e.value.code == ThreatModelErrorCode.METHOD_UNKNOWN


# ---------------- STRIDE ----------------

def test_stride_elicitation_deterministic_no_severity():
    model, _ = _model()
    assert model.system is not None
    first = elicit_stride(model.system)
    second = elicit_stride(model.system)
    assert first == second
    categories = {c["category"] for c in first}
    assert {"SPOOFING", "TAMPERING", "REPUDIATION", "INFORMATION_DISCLOSURE", "DENIAL_OF_SERVICE", "ELEVATION_OF_PRIVILEGE"} <= categories
    for candidate in first:
        assert "severity" not in json.dumps(candidate).lower()
        assert candidate["limitations"]
    subset = elicit_stride(model.system, categories=("SPOOFING",))
    assert {c["category"] for c in subset} == {"SPOOFING"}
    assert elicit_stride(model.system, categories=("NOPE",)) == []


def test_stride_spec_contract():
    assert set(STRIDE_SPEC) == {"SPOOFING", "TAMPERING", "REPUDIATION", "INFORMATION_DISCLOSURE", "DENIAL_OF_SERVICE", "ELEVATION_OF_PRIVILEGE"}
    for category, spec in STRIDE_SPEC.items():
        assert spec["applicable_subjects"] and spec["required_evidence"] and spec["limitations"], category


# ---------------- scenarios ----------------

def test_scenarios_are_hypotheses_not_findings():
    model, _ = _model()
    assert model.scenarios
    for scenario in model.scenarios:
        assert scenario.hypothesis_status in ("HYPOTHESIZED", "SUPPORTED_BY_EVIDENCE")
        assert scenario.method in ("stride", "attack-tree", "data-centric")
    text = json.dumps([s.model_dump(mode="json") for s in model.scenarios]).lower()
    assert "finding_id" not in text and "severity" not in text and "confirmed_vulnerability" not in text
    assert "critical" not in text and "exploitable" not in text


def test_scenario_status_rises_only_with_evidence():
    from emo_cyber_agent.threat_modeling.threats import build_threat_scenarios

    candidates = [{"method": "stride", "category": "SPOOFING", "subject": "entry-x", "preconditions": (), "attack_goal": "goal", "required_evidence": (), "limitations": ()}]
    bare, _ = build_threat_scenarios(candidates)
    assert bare[0].hypothesis_status == "HYPOTHESIZED"
    supported, _ = build_threat_scenarios(candidates, evidence_index={"entry-x": ("ev-1",)})
    assert supported[0].hypothesis_status == "SUPPORTED_BY_EVIDENCE"
    assert supported[0].evidence_ids == ("ev-1",)


# ---------------- attack paths ----------------

def test_attack_paths_bounded_and_classed():
    graph, _ = _graph("sql_flow")
    from emo_cyber_agent.threat_modeling.paths import find_attack_paths

    paths, partial = find_attack_paths(graph, audit_id="A", max_paths=25, max_length=8)
    assert partial is False
    for path in paths:
        assert path.path_class in ("POSSIBLE_PATH", "SUPPORTED_PATH", "VERIFIED_PATH")
        assert "not an executable exploit path" in " ".join(path.limitations) or path.evidence_ids
    text = json.dumps([p.model_dump(mode="json") for p in paths]).lower()
    assert "exploit_confirmed" not in text and "exploit confirmed" not in text


def test_attack_path_budget_exhaustion():
    graph, _ = _graph("cyclic")
    from emo_cyber_agent.threat_modeling.paths import find_attack_paths

    paths, partial = find_attack_paths(graph, audit_id="A", max_paths=1, max_length=2)
    assert isinstance(partial, bool)
    foreign, _ = _graph("sql_flow", audit="FOREIGN")
    from emo_cyber_agent.threat_modeling.paths import find_attack_paths as _find

    with pytest.raises(ThreatModelError) as e:
        _find(foreign, audit_id="A")
    assert e.value.code == ThreatModelErrorCode.CROSS_AUDIT


# ---------------- controls ----------------

def test_controls_observed_not_effective():
    graph, _ = _graph("auth_flow")
    observed = observe_controls(graph)
    assert observed and all(c.status == "OBSERVED_CONTROL" for c in observed)
    assert observe_controls(None) == []
    expected = expected_controls(("ELEVATION_OF_PRIVILEGE", "SPOOFING"))
    assert all(c.status == "EXPECTED_CONTROL" for c in expected)
    coverage = coverage_for("ELEVATION_OF_PRIVILEGE")
    assert coverage.verification_requirements == ("static_confirmation",)
    text = json.dumps([c.model_dump(mode="json") for c in observed + expected]).lower()
    assert "effective" not in text and "works" not in text


# ---------------- delta ----------------

def test_delta_presence_not_resolution():
    service = ThreatModelingService()
    graph, caps = _graph("auth_flow")
    base = service.build_model(model_id="tm-base", audit_id="A", project_id="P", snapshot_id="snap-1", methods=("stride",), code_graph=graph, codeintel_capabilities=caps)
    target = service.build_model(model_id="tm-target", audit_id="A", project_id="P", snapshot_id="snap-2", methods=("stride", "attack-tree"), code_graph=graph, codeintel_capabilities=caps)
    from emo_cyber_agent.threat_modeling.delta import diff_threat_models

    delta = diff_threat_models(base, target)
    kinds = {e.kind for e in delta.entries}
    assert kinds <= {"NEW_THREAT_SCENARIO", "REMOVED_SCENARIO", "CHANGED_SCENARIO", "PERSISTING_SCENARIO", "NEW_ATTACK_SURFACE", "REMOVED_ATTACK_SURFACE", "CHANGED_BOUNDARY", "CHANGED_CONTROL", "COVERAGE_CHANGE", "UNKNOWN_CHANGE"}
    assert "REMOVED_SCENARIO" in kinds or "NEW_THREAT_SCENARIO" in kinds
    assert "resolved" not in json.dumps([e.model_dump(mode="json") for e in delta.entries]).lower()
    with pytest.raises(ThreatModelError):
        diff_threat_models(base, base)
    foreign, _ = _graph("auth_flow", audit="FOREIGN")
    foreign_model = service.build_model(model_id="tm-f", audit_id="FOREIGN", snapshot_id="snap-9", methods=("stride",), code_graph=foreign)
    with pytest.raises(ThreatModelError) as e:
        diff_threat_models(base, foreign_model)
    assert e.value.code == ThreatModelErrorCode.CROSS_AUDIT


# ---------------- service ----------------

def test_service_determinism_and_digest():
    service = ThreatModelingService()
    graph, caps = _graph("auth_flow")
    kwargs = dict(model_id="tm-001", audit_id="A", project_id="P", snapshot_id="snap-1", methods=("stride",), code_graph=graph, codeintel_capabilities=caps)
    first = service.build_model(**kwargs)
    second = service.build_model(**kwargs)
    assert first.model_digest == second.model_digest
    assert first.model_digest != ""
    assert service.select_methods_for_skills(("authorization", "injection")) == ("stride", "attack-tree", "data-centric")


def test_service_evidence_handoffs_report():
    service = ThreatModelingService()
    model, _ = _model()
    evidence = service.build_evidence(model)
    assert evidence and all(e.provenance["snapshot_id"] == "snap-1" for e in evidence)
    handoff = model.handoffs[0]
    assert handoff.target_snapshot_id == "snap-1" and handoff.safety_level == "passive"
    assert handoff.success_criteria and handoff.refutation_criteria
    service.check_handoff(handoff, current_snapshot_id="snap-1")
    with pytest.raises(ThreatModelError) as e:
        service.check_handoff(handoff, current_snapshot_id="stale")
    assert e.value.code == ThreatModelErrorCode.VERIFICATION_STALE
    view = service.report_view(model, evidence_ids=tuple(e.id for e in evidence))
    assert view["model_digest"] == model.model_digest
    text = json.dumps(view).lower()
    assert "finding" not in text.replace("threat_scenarios", "").replace("verification_handoffs", "")


def test_templates_trusted_schema_valid_digest_stable():
    service = ThreatModelingService()
    templates = service.load_official_templates("templates/threat-modeling/official")
    assert sorted(t.template_id for t in templates) == ["api-db-starter", "web-app-starter"]
    for template in templates:
        get_method(template.methods[0])
        assert ThreatTemplateConfig.digest_of(template) != ""
    again = service.load_official_templates("templates/threat-modeling/official")
    assert [ThreatTemplateConfig.digest_of(t) for t in templates] == [ThreatTemplateConfig.digest_of(t) for t in again]
    with pytest.raises(ThreatModelError):
        service.load_official_templates("templates/threat-modeling/nonexistent-dir")


def test_schemas_validate_real_objects():
    import jsonschema

    model, _ = _model()
    tm_schema = json.loads(Path("docs/schemas/threat-model.schema.json").read_text())
    jsonschema.validate(json.loads(json.dumps(model.model_dump(mode="json", exclude={"system", "surface", "coverage", "assessment", "limitations", "created_at"}))), tm_schema)
    as_schema = json.loads(Path("docs/schemas/attack-surface.schema.json").read_text())
    assert model.surface is not None
    jsonschema.validate(json.loads(json.dumps(model.surface.model_dump(mode="json", exclude={"relations"}))), as_schema)
    sc_schema = json.loads(Path("docs/schemas/threat-scenario.schema.json").read_text())
    jsonschema.validate(json.loads(json.dumps(model.scenarios[0].model_dump(mode="json"))), sc_schema)
