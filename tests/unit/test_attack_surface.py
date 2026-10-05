"""POST-RC-009 — Attack surface tests (offline).

Surface categories, element linkage, completeness honesty
(never NONE from nothing, never FULL from partial), queries,
audit binding, determinism, purity. No Findings, no severity.
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.threat_modeling.attack_surface import build_attack_surface
from emo_cyber_agent.threat_modeling.errors import ThreatModelError
from emo_cyber_agent.threat_modeling.queries import ALLOWED_SURFACE_QUERIES, ThreatQueryPort
from emo_cyber_agent.threat_modeling.service import ThreatModelingService
from emo_cyber_agent.threat_modeling.spec import SURFACE_CATEGORIES


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


def _model(scenario="auth_flow", audit="A", snapshot="snap-1", caps=None, secret_symbols=()):
    service = ThreatModelingService()
    graph, detected = _graph(scenario, audit=audit)
    return service.build_model(
        model_id="tm-001", audit_id=audit, project_id="P", snapshot_id=snapshot,
        methods=("stride",), code_graph=graph,
        codeintel_capabilities=caps if caps is not None else detected,
        secret_symbols=secret_symbols,
    )


def test_surface_categories_closed():
    assert set(SURFACE_CATEGORIES) == {
        "INBOUND", "OUTBOUND", "DATA_ACCESS", "STATE_CHANGE", "AUTHENTICATION",
        "AUTHORIZATION", "FILE_ACCESS", "DATABASE_ACCESS", "NETWORK_ACCESS",
        "SECRET_ACCESS", "ADMINISTRATIVE",
    }
    from emo_cyber_agent.threat_modeling.spec import AttackSurfaceElement

    with pytest.raises(Exception):
        AttackSurfaceElement(element_id="x", category="NOPE")


def test_surface_elements_linked():
    model = _model()
    assert model.surface is not None
    by_category: dict[str, list[str]] = {}
    for element in model.surface.elements:
        by_category.setdefault(element.category, []).append(element.element_id)
        assert element.snapshot_id == "snap-1" and element.project_id == "P"
        assert element.coverage and element.provenance.get("snapshot_id") == "snap-1"
    assert "INBOUND" in by_category and "AUTHORIZATION" in by_category
    text = json.dumps([e.model_dump(mode="json") for e in model.surface.elements]).lower()
    assert "finding_id" not in text and "severity" not in text


def test_state_change_and_admin_surfaces():
    from emo_cyber_agent.threat_modeling.system_model import build_system_model

    graph, caps = _graph("auth_flow")
    system = build_system_model(audit_id="A", project_id="P", snapshot_id="s", code_graph=graph)
    from emo_cyber_agent.threat_modeling.attack_surface import build_attack_surface

    surface = build_attack_surface(system, code_graph=graph, codeintel_capabilities=caps)
    categories = {e.category for e in surface.elements}
    assert "STATE_CHANGE" in categories  # POST /login is state-changing
    assert surface.completeness == "FULLY_MAPPED"


def test_empty_surface_is_unknown_never_none():
    service = ThreatModelingService()
    model = service.build_model(model_id="tm-e", audit_id="A", project_id="P", snapshot_id="s", methods=("stride",), code_graph=None, codeintel_capabilities=())
    assert model.surface is not None
    assert model.surface.elements == ()
    assert model.surface.completeness == "UNKNOWN"
    assert model.surface.completeness != "NONE_OBSERVED"


def test_none_observed_only_with_routes_capability():
    from emo_cyber_agent.code_intelligence.graph import CodeGraph
    from emo_cyber_agent.code_intelligence.spec import CodeProject, CodeSnapshot
    from emo_cyber_agent.threat_modeling.attack_surface import build_attack_surface
    from emo_cyber_agent.threat_modeling.system_model import build_system_model

    system = build_system_model(audit_id="A", project_id="P", snapshot_id="s")
    empty_graph = CodeGraph(CodeSnapshot(project=CodeProject(audit_id="A", asset_id="a"), provider="test", provider_version="1", revision="r", source_digest="d"))
    analyzed = build_attack_surface(system, code_graph=empty_graph, codeintel_capabilities=("routes", "symbols"))
    assert analyzed.completeness == "NONE_OBSERVED"
    blind = build_attack_surface(system, code_graph=empty_graph, codeintel_capabilities=())
    assert blind.completeness == "UNKNOWN"
    no_graph = build_attack_surface(system, code_graph=None, codeintel_capabilities=("routes", "symbols"))
    assert no_graph.completeness == "UNKNOWN"


def test_truncated_graph_is_partial_never_full():
    graph, caps = _graph("auth_flow")
    graph._truncated = True
    service = ThreatModelingService()
    model = service.build_model(model_id="tm-p", audit_id="A", project_id="P", snapshot_id="s", methods=("stride",), code_graph=graph, codeintel_capabilities=caps)
    assert model.surface is not None
    assert model.surface.completeness == "PARTIALLY_MAPPED"
    assert any("partial mapping is never complete mapping" in lim for lim in model.surface.limitations)


def test_secret_category_only_with_evidence():
    without = _model(secret_symbols=())
    assert not [e for e in (without.surface.elements if without.surface else ()) if e.category == "SECRET_ACCESS"]
    assert any("secret-access" in lim for lim in (without.surface.limitations if without.surface else ()))
    with_secrets = _model(secret_symbols=("src/cfg.py:api-key",))
    assert any(e.category == "SECRET_ACCESS" for e in (with_secrets.surface.elements if with_secrets.surface else ()))


def test_queries_allowlisted_audit_bound_recorded():
    model = _model()
    port = ThreatQueryPort(model)
    assert set(port.allowed_queries) == set(ALLOWED_SURFACE_QUERIES)
    entries, prov = port.list_external_entrypoints(audit_id="A")
    assert len(entries) == 2 and prov["snapshot_id"] == "snap-1" and prov["result_digest"] != ""
    stateful, _ = port.list_state_changing_entrypoints(audit_id="A")
    assert len(stateful) == 1
    boundaries, _ = port.list_auth_boundaries(audit_id="A")
    assert len(boundaries) == 1
    paths, _ = port.list_attack_paths(audit_id="A")
    assert isinstance(paths, list)
    with pytest.raises(ThreatModelError):
        port.list_external_entrypoints(audit_id="FOREIGN")
    with pytest.raises(ThreatModelError):
        port.run_named("drop table", audit_id="A")
    with pytest.raises(ThreatModelError):
        port.list_attack_paths(audit_id="A", target="x" * 400)
    assert len(port.history) >= 4


def test_queries_deterministic():
    model = _model()
    first, _ = ThreatQueryPort(model).list_external_entrypoints(audit_id="A")
    second, _ = ThreatQueryPort(model).list_external_entrypoints(audit_id="A")
    assert first == second


def test_surface_schema_validates():
    import jsonschema

    model = _model()
    assert model.surface is not None
    schema = json.loads(Path("docs/schemas/attack-surface.schema.json").read_text())
    jsonschema.validate(json.loads(json.dumps(model.surface.model_dump(mode="json", exclude={"relations"}))), schema)
