"""POST-RC-008 — Change analysis functional tests (offline).

Contracts, snapshot comparison, region precision, symbol/route/
dependency/database linking, predicates, propagation, impact,
planning, baselines, evidence, reports, schemas, determinism,
skill/pack/task integration. No git, no network, no model.
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.change_analysis.diff import compare_snapshots
from emo_cyber_agent.change_analysis.errors import ChangeError, ChangeErrorCode
from emo_cyber_agent.change_analysis.impact import analyze_impact, propagate
from emo_cyber_agent.change_analysis.planner import plan_review
from emo_cyber_agent.change_analysis.predicates import evaluate_predicates
from emo_cyber_agent.change_analysis.service import ChangeService, compare_baselines
from emo_cyber_agent.change_analysis.spec import (
    BASELINE_STATES,
    CHANGE_CLASSIFICATIONS,
    CHANGE_PREDICATES,
    FILE_CHANGE_STATES,
    REVIEW_MODES,
    ChangeSet,
    ComparisonSnapshot,
    assert_no_verdicts,
    canonical_digest,
)

FIXTURES = Path("tests/fixtures/change_analysis")


def _snap(snapshot_id, files, *, audit="A", project="P", revision=""):
    return ComparisonSnapshot(snapshot_id=snapshot_id, audit_id=audit, project_id=project, revision=revision, files=dict(files))


def _graph(symbols=(), endpoints=(), boundaries=(), taint=(), sources=(), sinks=(), deps=(), db=(), calls=(), audit="A"):
    from emo_cyber_agent.code_intelligence.graph import CodeGraph
    from emo_cyber_agent.code_intelligence.spec import (
        AuthorizationBoundary,
        CallEdge,
        CodeLocation,
        CodeProject,
        CodeSnapshot,
        CodeSymbol,
        DataSink,
        DataSource,
        DatabaseRelationship,
        DependencyEdge,
        RouteEndpoint,
        TaintPath,
    )

    snapshot = CodeSnapshot(project=CodeProject(audit_id=audit, asset_id="asset"), provider="test", provider_version="1", revision="r", source_digest="d")
    graph = CodeGraph(snapshot)
    for path, name, line in symbols:
        sid = f"{path}:{name}"
        graph.add_symbol(CodeSymbol(symbol_id=sid, kind="function", name=name, file=path, location=CodeLocation(path=path, line=line)))
    for eid, method, route_path, handler, boundary, state in endpoints:
        graph.add_endpoint(RouteEndpoint(endpoint_id=eid, method=method, path=route_path, handler_id=handler, framework="test", location=CodeLocation(path="src/app.py", line=1), auth_boundary_id=boundary, state_changing=state))
    for bid, kind in boundaries:
        graph.add_boundary(AuthorizationBoundary(boundary_id=bid, kind=kind, location=CodeLocation(path="src/auth.py", line=1)))
    for tid, src, snk in taint:
        graph.add_taint_path(TaintPath(path_id=tid, source_id=src, sink_id=snk, node_ids=(src, snk)))
    for sid, kind in sources:
        graph.add_source(DataSource(source_id=sid, kind=kind, location=CodeLocation(path="src/a.py", line=1)))
    for sid, kind in sinks:
        graph.add_sink(DataSink(sink_id=sid, kind=kind, location=CodeLocation(path="src/a.py", line=1)))
    for importer, package, version in deps:
        graph.add_dep_edge(DependencyEdge(importer=importer, package=package, version=version))
    for rid, code_id, obj in db:
        graph.add_db_relation(DatabaseRelationship(relation_id=rid, kind="queries_table", code_id=code_id, database_object=obj))
    for caller, callee in calls:
        graph.add_call_edge(CallEdge(caller_id=caller, callee_id=callee, location=CodeLocation(path="src/a.py", line=1)))
    return graph


# ---------------- contracts ----------------

def test_contract_vocabularies_and_frozen():
    assert set(FILE_CHANGE_STATES) == {"ADDED", "REMOVED", "MODIFIED", "RENAMED", "MOVED", "UNCHANGED", "UNKNOWN"}
    assert len(CHANGE_CLASSIFICATIONS) == 16 and "UNKNOWN" in CHANGE_CLASSIFICATIONS
    assert len(CHANGE_PREDICATES) == 12
    assert set(REVIEW_MODES) == {"FULL_REVIEW", "TARGETED_REVIEW", "REBASE_REVIEW"}
    assert "RESOLVED" not in BASELINE_STATES
    snap = _snap("s", {})
    with pytest.raises(Exception):
        ComparisonSnapshot(snapshot_id="s", audit_id="A", files={}, bogus_field="x")
    with pytest.raises(ChangeError):
        assert_no_verdicts("this is confirmed vulnerable")
    with pytest.raises(ChangeError):
        assert_no_verdicts("marked safe by review")
    assert canonical_digest({"b": 1, "a": 2}) == canonical_digest({"a": 2, "b": 1})


def test_identical_snapshots_rejected():
    base = _snap("same", {"a.py": "x\n"})
    with pytest.raises(ChangeError) as e:
        compare_snapshots(base, _snap("same", {"a.py": "x\n"}))
    assert e.value.code == ChangeErrorCode.INVALID


# ---------------- file states ----------------

def test_file_states_added_removed_modified_unchanged():
    base = _snap("b", {"keep.py": "a\n", "gone.py": "b\n", "chg.py": "c1\n"})
    target = _snap("t", {"keep.py": "a\n", "new.py": "d\n", "chg.py": "c2\n"})
    changeset = compare_snapshots(base, target)
    states = {f.path: f.state for f in changeset.files}
    assert states == {"chg.py": "MODIFIED", "new.py": "ADDED", "gone.py": "REMOVED"}
    assert "keep.py" not in states
    assert changeset.coverage == "partial"  # no graphs wired
    assert any("symbol-linking-unavailable" in lim for lim in changeset.limitations)


def test_rename_and_move_by_digest():
    content = (FIXTURES / "rename_old.py").read_text()
    base = _snap("b", {"src/old.py": content})
    target = _snap("t", {"src/new.py": content})
    changeset = compare_snapshots(base, target)
    assert [(f.path, f.previous_path, f.state) for f in changeset.files] == [("src/new.py", "src/old.py", "RENAMED")]
    base2 = _snap("b", {"src/old.py": content})
    target2 = _snap("t", {"lib/new.py": content})
    changeset2 = compare_snapshots(base2, target2)
    assert [f.state for f in changeset2.files] == ["MOVED"]


def test_binary_becomes_unknown_never_unchanged():
    base = _snap("b", {"bin.dat": "abc\x00def\n"})
    target = _snap("t", {"bin.dat": "abc\x00xyz\n"})
    changeset = compare_snapshots(base, target)
    assert [f.state for f in changeset.files] == ["UNKNOWN"]
    assert any("uncomparable-binary" in lim for lim in changeset.limitations)


def test_generated_flagged():
    base = _snap("b", {"vendor/bundle.min.js": "var a=1\n"})
    target = _snap("t", {"vendor/bundle.min.js": "var a=2\n"})
    changeset = compare_snapshots(base, target)
    assert changeset.files[0].generated is True


# ---------------- regions + symbols ----------------

def test_region_precision_and_symbol_linking():
    base_text = (FIXTURES / "auth_base.py").read_text()
    target_text = (FIXTURES / "auth_target.py").read_text()
    base = _snap("b", {"src/auth.py": base_text})
    target = _snap("t", {"src/auth.py": target_text})
    graph = _graph(symbols=[("src/auth.py", "require_auth", 1), ("src/auth.py", "login", 5)])
    changeset = compare_snapshots(base, target, base_graph=graph, target_graph=graph)
    regions = changeset.files[0].regions
    assert regions and all(r.start_line >= 5 for r in regions)
    assert {s.symbol_id for s in changeset.symbols} == {"src/auth.py:login"}
    assert changeset.symbols[0].change == "MODIFIED"


def test_removed_symbol_links_via_base_graph():
    base = _snap("b", {"src/old.py": "def gone():\n    pass\n"})
    target = _snap("t", {})
    graph = _graph(symbols=[("src/old.py", "gone", 1)])
    changeset = compare_snapshots(base, target, base_graph=graph)
    assert [(s.symbol_id, s.change) for s in changeset.symbols] == [("src/old.py:gone", "REMOVED")]


# ---------------- routes / deps / db ----------------

def test_route_linking_and_boundary_flag():
    base = _snap("b", {"src/app.py": "v1\n"})
    target = _snap("t", {"src/app.py": "v2\n"})
    base_graph = _graph(endpoints=[("GET /dash", "GET", "/dash", "src/app.py:view", "b1", False)], boundaries=[("b1", "decorator")])
    target_graph = _graph(endpoints=[("GET /dash", "GET", "/dash", "src/app.py:view", "b2", False)], boundaries=[("b2", "decorator")], symbols=[("src/app.py", "view", 1)])
    changeset = compare_snapshots(base, target, base_graph=base_graph, target_graph=target_graph)
    assert [(r.endpoint_id, r.change, r.auth_boundary_changed) for r in changeset.routes] == [("GET /dash", "MODIFIED", True)]


def test_dependency_version_change():
    base = _snap("b", {"requirements.txt": (FIXTURES / "deps_base.txt").read_text()})
    target = _snap("t", {"requirements.txt": (FIXTURES / "deps_target.txt").read_text()})
    base_graph = _graph(deps=[("requirements.txt", "flask", "3.0.0")])
    target_graph = _graph(deps=[("requirements.txt", "flask", "3.1.0")])
    changeset = compare_snapshots(base, target, base_graph=base_graph, target_graph=target_graph)
    assert [(d.package, d.previous_version, d.current_version) for d in changeset.dependencies] == [("flask", "3.0.0", "3.1.0")]
    assert any("DEPENDENCY" in c.classifications for c in changeset.classifications)


def test_database_relations_added_removed():
    base = _snap("b", {"src/a.py": "v1\n"})
    target = _snap("t", {"src/a.py": "v2\n"})
    base_graph = _graph(db=[("rel-old", "src/a.py:fn", "public.t1")])
    target_graph = _graph(db=[("rel-new", "src/a.py:fn", "public.t2")])
    changeset = compare_snapshots(base, target, base_graph=base_graph, target_graph=target_graph)
    assert sorted((r.relation_id, r.change) for r in changeset.database_relations) == [("rel-new", "ADDED"), ("rel-old", "REMOVED")]


# ---------------- predicates ----------------

def test_predicates_fire_deterministically():
    base = _snap("b", {"requirements.txt": "flask==3.0.0\n", "src/app.py": "v1\n"})
    target = _snap("t", {"requirements.txt": "flask==3.1.0\n", "src/app.py": "v2\n"})
    base_graph = _graph(deps=[("requirements.txt", "flask", "3.0.0")], endpoints=[("GET /x", "GET", "/x", "src/app.py:h", "b1", False)], boundaries=[("b1", "decorator")], taint=[("p1", "s1", "k1")],sources=[], sinks=[], db=[])
    target_graph = _graph(deps=[("requirements.txt", "flask", "3.1.0")], endpoints=[("GET /x", "GET", "/x", "src/app.py:h", "b2", False), ("POST /y", "POST", "/y", "src/app.py:n", "", True)], boundaries=[("b2", "decorator")], taint=[("p1", "s1", "k1"), ("p2", "s2", "k2")], sources=[("s3", "http_parameter")], sinks=[("k3", "sql_execution")], db=[("r1", "src/app.py:n", "public.t")], symbols=[("src/app.py", "h", 1), ("src/app.py", "n", 5)])
    changeset = compare_snapshots(base, target, base_graph=base_graph, target_graph=target_graph)
    fired = evaluate_predicates(changeset, base_graph=base_graph, target_graph=target_graph)
    assert fired["DEPENDENCY_VERSION_CHANGED"] == ["dependency:flask@3.1.0"]
    assert "NEW_TAINT_PATH" in fired and "NEW_EXTERNAL_INPUT" in fired and "NEW_SINK" in fired
    assert "DATABASE_ACCESS_CHANGED" in fired and "STATE_CHANGE_ADDED" in fired
    assert fired["AUTH_BOUNDARY_CHANGED"] == ["route:GET /x"]
    assert fired["ROUTE_PERMISSION_CHANGED"] == ["route:GET /x"]
    assert evaluate_predicates(changeset, base_graph=base_graph, target_graph=target_graph) == fired


def test_taint_modified_vs_new():
    from emo_cyber_agent.code_intelligence.spec import TaintPath

    base = _snap("b", {"src/a.py": "v1\n"})
    target = _snap("t", {"src/a.py": "v2\n"})
    base_graph = _graph(taint=[("p1", "s1", "k1")])
    target_graph = _graph()
    target_graph.add_taint_path(TaintPath(path_id="p1", source_id="s1", sink_id="k1", node_ids=("s1", "mid", "k1")))
    changeset = compare_snapshots(base, target, base_graph=base_graph, target_graph=target_graph)
    fired = evaluate_predicates(changeset, base_graph=base_graph, target_graph=target_graph)
    assert "TAINT_PATH_MODIFIED" in fired and "NEW_TAINT_PATH" not in fired


# ---------------- propagation + impact ----------------

def test_propagation_bounded_and_explained():
    base = _snap("b", {"src/a.py": "v1\n"})
    target = _snap("t", {"src/a.py": "v2\n"})
    graph = _graph(
        symbols=[("src/a.py", "changed_fn", 1), ("src/b.py", "caller_fn", 1), ("src/c.py", "far_fn", 1)],
        calls=[("src/b.py:caller_fn", "src/a.py:changed_fn"), ("src/c.py:far_fn", "src/b.py:caller_fn")],
        endpoints=[("GET /x", "GET", "/x", "src/b.py:caller_fn", "b1", False)],
        boundaries=[("b1", "decorator")],
        db=[("r1", "src/c.py:far_fn", "public.t")],
    )
    from emo_cyber_agent.change_analysis.diff import _link_symbols

    changeset = compare_snapshots(base, target, target_graph=graph)
    surface, partial, trail = propagate(changeset, target_graph=graph, max_hops=4, max_nodes=500)
    assert "src/b.py:caller_fn" in surface.symbols and "src/c.py:far_fn" in surface.symbols
    assert surface.routes == ("GET /x",) and surface.boundaries == ("b1",) and surface.database_objects == ("public.t",)
    assert partial is False and trail[0].startswith("seeds:")
    small, partial2, trail2 = propagate(changeset, target_graph=graph, max_hops=4, max_nodes=1)
    assert partial2 is True and any("budget-exhausted" in t for t in trail2)


def test_impact_domains_skills_reasons():
    from emo_cyber_agent.skills.builtin.catalog import load_builtin_registry

    base = _snap("b", {"requirements.txt": "flask==3.0.0\n"}, project="P")
    target = _snap("t", {"requirements.txt": "flask==3.1.0\n"}, project="P")
    changeset = compare_snapshots(base, target)
    fired = {"DEPENDENCY_VERSION_CHANGED": ["dependency:flask@3.1.0"]}
    from emo_cyber_agent.change_analysis.spec import AffectedSurface

    impact = analyze_impact(changeset, fired, AffectedSurface(), skill_registry=load_builtin_registry())
    assert impact.affected is True and impact.domains == ("DEPENDENCY",)
    assert set(impact.affected_skills) == {"dependency-security", "supply-chain"}
    assert impact.reason_codes == ("DEPENDENCY_VERSION_CHANGED",)
    assert impact.confidence_context == "structural-facts-only"
    assert impact.affected_assets == ("P",)
    text = __import__("json").dumps(impact.model_dump(mode="json")).lower()
    assert "vulnerable" not in text and "confirmed" not in text


# ---------------- planner ----------------

def test_plan_modes_handoffs_digest():
    base = _snap("b", {"src/a.py": "v1\n"})
    target = _snap("t", {"src/a.py": "v2\n", "requirements.txt": "flask==3.1.0\n"})
    svc = ChangeService()
    changeset, fired, impact, plan, _ = svc.review(base, target)
    assert plan.review_mode == "TARGETED_REVIEW"
    assert "affected surface is fully reviewed" in plan.coverage_statement
    assert "project-wide" in plan.coverage_statement
    assert all(h.target_snapshot_id == "t" for h in plan.verification_handoffs)
    assert plan.plan_digest != ""
    full = plan_review(changeset, impact, fired, review_mode="FULL_REVIEW")
    assert "full re-analysis" in full.coverage_statement
    rebase = plan_review(changeset, impact, fired, review_mode="REBASE_REVIEW")
    assert "re-validated" in rebase.coverage_statement
    with pytest.raises(ChangeError):
        plan_review(changeset, impact, fired, review_mode="WATCH")


def test_plan_selects_real_packs_and_tasks():
    from emo_cyber_agent.skills.packs.catalog import load_official_packs
    from emo_cyber_agent.skills.builtin.catalog import load_builtin_registry

    skills = load_builtin_registry()
    packs = load_official_packs("templates/skills/packs/official", skill_registry=skills)
    base = _snap("b", {"requirements.txt": "flask==3.0.0\n"})
    target = _snap("t", {"requirements.txt": "flask==3.1.0\n"})
    svc = ChangeService(skill_registry=skills, pack_registry=packs)
    _, _, impact, plan, _ = svc.review(base, target)
    assert "dependency-supply-chain" in plan.targeted_packs
    assert "dependency-audit" in plan.targeted_tasks
    assert "injection-security" not in plan.targeted_packs


# ---------------- baselines ----------------

def test_baseline_states_not_finding_states():
    from emo_cyber_agent.change_analysis.spec import BaselineSecurityObservation

    with pytest.raises(Exception):
        BaselineSecurityObservation(observation_key="k", state="RESOLVED")
    result = compare_baselines({"a": "d1", "b": "d1", "c": "d1", "d": ""}, {"a": "d1", "b": "d2", "e": "d3", "d": "d9"})
    assert {o.observation_key: o.state for o in result} == {"a": "PERSISTING", "b": "CHANGED", "c": "REMOVED", "d": "INDETERMINATE", "e": "NEW"}


# ---------------- evidence + reports + schemas ----------------

def test_evidence_provenance_and_redaction():
    svc = ChangeService()
    base = _snap("b", {"src/cfg.py": "x=1\n"}, project="P")
    target = _snap("t", {"src/cfg.py": 'KEY="ghp_LIVE999SECRET"\n'}, project="P")
    _, _, impact, _, evidence = svc.review(base, target)
    blob = json.dumps([e.model_dump(mode="json") for e in evidence])
    assert "ghp_LIVE999SECRET" not in blob
    for item in evidence:
        assert item.provenance["audit_id"] == "A" and item.provenance["base_snapshot_id"] == "b"
        assert item.provenance["target_snapshot_id"] == "t" and item.provenance["change_digest"] != ""
    assert impact.evidence_ids == tuple(e.id for e in evidence)


def test_report_view_projection_only():
    svc = ChangeService()
    base = _snap("b", {"src/a.py": "v1\n"}, revision="r1")
    target = _snap("t", {"src/a.py": "v2\n"}, revision="r2")
    changeset, _, impact, plan, evidence = svc.review(base, target)
    view = svc.report_view(changeset, impact, plan, tuple(e.id for e in evidence))
    assert view.base_revision == "r1" and view.target_revision == "r2"
    assert view.changed_files == ("src/a.py",)
    text = json.dumps(view.model_dump(mode="json")).lower()
    assert "vulnerable" not in text and "finding" not in text


def test_schemas_validate_real_payloads():
    import jsonschema

    svc = ChangeService()
    changeset, _, impact, plan, _ = svc.review(_snap("b", {"src/a.py": "v1\n"}), _snap("t", {"src/a.py": "v2\n"}))
    cs_schema = json.loads(Path("docs/schemas/change-set.schema.json").read_text())
    jsonschema.validate(json.loads(json.dumps(changeset.model_dump(mode="json", exclude={"symbols", "routes", "dependencies", "database_relations", "classifications"}))), cs_schema)
    plan_schema = json.loads(Path("docs/schemas/change-review-plan.schema.json").read_text())
    jsonschema.validate(json.loads(json.dumps(plan.model_dump(mode="json"))), plan_schema)


# ---------------- determinism ----------------

def test_deterministic_pipeline():
    svc = ChangeService()
    base = _snap("b", {"src/a.py": "v1\n"}, revision="r1")
    target = _snap("t", {"src/a.py": "v2\n"}, revision="r2")
    first = svc.review(base, target)
    second = svc.review(base, target)
    assert first[0].change_digest == second[0].change_digest
    assert first[3].plan_digest == second[3].plan_digest


# ---------------- integration workflows ----------------

def test_auth_change_workflow_end_to_end():
    base_text = (FIXTURES / "auth_base.py").read_text()
    target_text = (FIXTURES / "auth_target.py").read_text()
    base = _snap("b", {"src/auth.py": base_text}, revision="r1")
    target = _snap("t", {"src/auth.py": target_text}, revision="r2")
    base_graph = _graph(endpoints=[("GET /dash", "GET", "/dash", "src/auth.py:login", "b1", False)], boundaries=[("b1", "decorator")], symbols=[("src/auth.py", "require_auth", 1), ("src/auth.py", "login", 5)])
    target_graph = _graph(endpoints=[("GET /dash", "GET", "/dash", "src/auth.py:login", "b2", False)], boundaries=[("b2", "decorator")], symbols=[("src/auth.py", "require_auth", 1), ("src/auth.py", "login", 5)])
    svc = ChangeService()
    changeset, fired, impact, plan, evidence = svc.review(base, target, base_graph=base_graph, target_graph=target_graph)
    assert "AUTHENTICATION" in {c for cl in changeset.classifications for c in cl.classifications}
    assert "ROUTE_PERMISSION_CHANGED" in fired and "AUTH_BOUNDARY_CHANGED" in fired
    assert "authentication" in impact.affected_skills
    assert any(h.method == "static_confirmation" and h.target_snapshot_id == "t" for h in plan.verification_handoffs)
    assert evidence and plan.targeted_tasks


def test_dependency_change_workflow_end_to_end():
    base = _snap("b", {"requirements.txt": (FIXTURES / "deps_base.txt").read_text()}, revision="r1")
    target = _snap("t", {"requirements.txt": (FIXTURES / "deps_target.txt").read_text()}, revision="r2")
    base_graph = _graph(deps=[("requirements.txt", "flask", "3.0.0")])
    target_graph = _graph(deps=[("requirements.txt", "flask", "3.1.0")])
    svc = ChangeService()
    changeset, fired, impact, plan, _ = svc.review(base, target, base_graph=base_graph, target_graph=target_graph)
    assert "DEPENDENCY_VERSION_CHANGED" in fired
    assert "dependency-audit" in plan.targeted_tasks
    assert plan.coverage_statement != ""


# ---------------- authority boundaries ----------------

def test_no_model_git_finding_surface():
    import ast as _ast

    tree = _ast.parse("\n".join((Path("src/emo_cyber_agent/change_analysis") / f).read_text() for f in ["spec.py", "diff.py", "impact.py", "predicates.py", "planner.py", "service.py", "errors.py", "provenance.py"]))
    imports: set[str] = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, _ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert not (imports & {"subprocess", "os", "sys", "shutil", "openai", "anthropic", "git"})
    text = "\n".join((Path("src/emo_cyber_agent/change_analysis") / f).read_text() for f in ["spec.py", "diff.py", "impact.py", "predicates.py", "planner.py", "service.py"])
    assert "SecurityFinding" not in text and "watch_repository" not in text and "auto_fix" not in text
    assert "checkout" not in text.lower() and "auto_merge" not in text.lower()
