"""POST-RC-011 — Security knowledge & regression memory (offline).

Core contract: atomic record construction, provenance, fingerprints,
allowlisted queries, official templates, schema interop, and the two
first end-to-end workflows (A: evidence → knowledge round-trip,
B: idempotent re-ingest). Zero Findings required.
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.security_knowledge import (
    ALLOWED_KNOWLEDGE_QUERIES,
    PERSISTABLE_CATEGORIES,
    KnowledgeError,
    KnowledgeErrorCode,
    KnowledgeQueryPort,
    SecurityKnowledgeService,
    build_knowledge_record,
    load_knowledge_template,
    load_official_knowledge_templates,
    record_reference,
    route_property_key,
    snapshot_identity,
    structural_identity,
)

FIXTURES = Path("tests/fixtures/security_knowledge")
AUDIT = "audit-2026-001"
PROJECT = "payments-api"
SNAP = "snap-2026-09-01"


def _fixture() -> dict:
    return json.loads((FIXTURES / "knowledge_records.json").read_text())


def _remember(service: SecurityKnowledgeService | None = None, **kwargs):
    service = service or SecurityKnowledgeService()
    base = {
        "audit_id": AUDIT,
        "project_id": PROJECT,
        "snapshot_id": SNAP,
        "source_type": "evidence",
        "source_id": "ev-0001",
        "category": "OBSERVED_FACT",
        "content": {"statement": "transport layer enabled on the edge listener"},
    }
    base.update(kwargs)
    return service.remember(**base)


# ---------------- record construction ----------------

def test_record_is_complete_and_frozen():
    record, quarantined = _remember()
    assert record.record_id.startswith("kn-")
    assert record.digest and record.content_digest
    assert record.provenance is not None and record.provenance.origin
    assert quarantined is False
    with pytest.raises(ValueError):
        record.category = "TOOL_OBSERVATION"


def test_same_inputs_same_identity():
    a, _ = _remember()
    b, _ = _remember()
    assert a.record_id == b.record_id
    assert a.digest == b.digest


def test_different_content_different_identity():
    a, _ = _remember()
    b, _ = _remember(content={"statement": "rate limit configured at the gateway"})
    assert a.record_id != b.record_id


def test_provenance_is_mandatory():
    with pytest.raises(KnowledgeError) as e:
        build_knowledge_record(
            audit_id=AUDIT, project_id=PROJECT, source_type="evidence",
            source_id="ev-1", category="OBSERVED_FACT", provenance=None,
        )
    assert e.value.code == KnowledgeErrorCode.INVALID


def test_banned_category_rejected():
    with pytest.raises(KnowledgeError) as e:
        _remember(category="FINDING_STATE")
    assert e.value.code == KnowledgeErrorCode.BANNED_CONTENT


def test_trust_cannot_be_raised():
    with pytest.raises(KnowledgeError) as e:
        _remember(trust_level="trusted")
    assert e.value.code == KnowledgeErrorCode.INVALID


def test_every_persistable_category_round_trips():
    for category in PERSISTABLE_CATEGORIES:
        record, _ = _remember(category=category)
        assert record.category == category


def test_record_reference_carries_digest_and_validates():
    record, _ = _remember()
    ref = record_reference(record)
    assert ref.digest == record.digest
    import jsonschema

    schema = json.loads(Path("docs/schemas/knowledge-reference.schema.json").read_text())
    jsonschema.validate(json.loads(ref.model_dump_json()), schema)


def test_record_validates_against_schema():
    record, _ = _remember()
    import jsonschema

    schema = json.loads(Path("docs/schemas/security-knowledge.schema.json").read_text())
    jsonschema.validate(json.loads(record.model_dump_json()), schema)


def test_regression_record_validates_against_schema():
    import jsonschema

    from emo_cyber_agent.security_knowledge import SecurityKnowledgeService as Svc

    service = Svc()
    regression, _ = service.remember_regression(
        audit_id=AUDIT, project_id=PROJECT, regression_key=route_property_key("/login", "auth"),
        base_snapshot_id="snap-0", target_snapshot_id=SNAP,
        before_digest="aaa1", after_digest="bbb2",
    )
    schema = json.loads(Path("docs/schemas/security-regression.schema.json").read_text())
    jsonschema.validate(json.loads(regression.model_dump_json()), schema)


def test_fixture_records_validate_against_schema():
    import jsonschema

    schema = json.loads(Path("docs/schemas/security-knowledge.schema.json").read_text())
    for record in _fixture()["records"]:
        jsonschema.validate(record, schema)


# ---------------- fingerprints ----------------

def test_snapshot_identity_is_snapshot_bound():
    a = snapshot_identity(project_id=PROJECT, object_type="route", object_identity="/login", snapshot_id="s1", source="code", security_property="auth")
    b = snapshot_identity(project_id=PROJECT, object_type="route", object_identity="/login", snapshot_id="s2", source="code", security_property="auth")
    assert a != b


def test_structural_identity_is_snapshot_agnostic():
    a = structural_identity(project_id=PROJECT, object_type="route", object_identity="/login", source="code", security_property="auth", facts={"z": 1, "a": 2})
    b = structural_identity(project_id=PROJECT, object_type="route", object_identity="/login", source="code", security_property="auth", facts={"a": 2, "z": 1})
    assert a == b


def test_identity_never_leaks_formatting_inputs():
    a = structural_identity(project_id=PROJECT, object_type="route", object_identity="/login", source="code", security_property="auth", facts={"f": "line 1\n"})
    b = structural_identity(project_id=PROJECT, object_type="route", object_identity="/login", source="code", security_property="auth", facts={"f": "line 1\n"})
    assert a == b
    assert a != structural_identity(project_id=PROJECT, object_type="route", object_identity="/login", source="code", security_property="tls")


def test_regression_keys_are_stable_and_normalized():
    assert route_property_key("/Login/", "auth") == route_property_key("/login", "AUTH")
    assert route_property_key("/login", "auth").startswith("regression:")


# ---------------- queries ----------------

def test_query_allowlist_matches_fixture():
    assert set(ALLOWED_KNOWLEDGE_QUERIES) == set(_fixture()["allowed_queries"])


def test_unknown_query_is_rejected():
    port = KnowledgeQueryPort(SecurityKnowledgeService().store)
    with pytest.raises(KnowledgeError) as e:
        port.run_named("run_sql", audit_id=AUDIT, project_id=PROJECT)
    assert e.value.code == KnowledgeErrorCode.QUERY_REJECTED


def test_query_history_records_digests():
    service = SecurityKnowledgeService()
    _remember(service)
    assert service.query_history == []
    service.find_by_regression_key("regression:route:login:auth", audit_id=AUDIT, project_id=PROJECT)
    entry = service.query_history[-1]
    assert entry["query_type"] == "find_by_regression_key"
    assert entry["audit_id"] == AUDIT and entry["result_digest"]


def test_empty_regression_key_rejected():
    service = SecurityKnowledgeService()
    with pytest.raises(KnowledgeError) as e:
        service.find_by_regression_key("   ", audit_id=AUDIT, project_id=PROJECT)
    assert e.value.code == KnowledgeErrorCode.QUERY_REJECTED


# ---------------- templates ----------------

def test_starter_template_loads():
    template = load_knowledge_template("templates/security-knowledge/SECURITY-KNOWLEDGE-TEMPLATE.yaml")
    assert template.template_id == "knowledge-starter"
    assert set(template.allowed_categories) <= set(PERSISTABLE_CATEGORIES)
    assert template.provenance["source"] == "starter"


def test_official_templates_load_and_are_official():
    from emo_cyber_agent.security_knowledge import KnowledgeTemplateConfig

    templates = load_official_knowledge_templates("templates/security-knowledge/official")
    assert templates
    assert all(t.provenance["source"] == "official" for t in templates)
    assert len({t.template_id for t in templates}) == len(templates)
    for template in templates:
        assert isinstance(template, KnowledgeTemplateConfig)
        assert template.version.count(".") == 2
        assert set(template.allowed_categories) <= set(PERSISTABLE_CATEGORIES)


def test_template_with_banned_category_rejected(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "knowledge_template:\n"
        "  template_id: bad-profile\n"
        "  name: Bad Profile\n"
        "  version: 1.0.0\n"
        "  allowed_categories: [FINDING_STATE]\n"
        "provenance: {source: official}\n"
    )
    with pytest.raises(KnowledgeError) as e:
        load_knowledge_template(bad)
    assert e.value.code == KnowledgeErrorCode.BANNED_CONTENT


def test_official_dir_requires_official_provenance(tmp_path: Path):
    fake = tmp_path / "fake.yaml"
    fake.write_text(
        "knowledge_template:\n"
        "  template_id: fake-profile\n"
        "  name: Fake Profile\n"
        "  version: 1.0.0\n"
        "  allowed_categories: [OBSERVED_FACT]\n"
        "provenance: {source: community}\n"
    )
    with pytest.raises(KnowledgeError) as e:
        load_official_knowledge_templates(tmp_path)
    assert e.value.code == KnowledgeErrorCode.PROVENANCE_FORGED


# ---------------- end-to-end ----------------

def test_e2e_a_evidence_to_knowledge_round_trip():
    """Evidence → scoped knowledge record → reference → provenance chain."""
    service = SecurityKnowledgeService(origin="evidence:collector", collector="recon")
    record, _ = service.remember(
        audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAP,
        source_type="evidence", source_id="ev-0001", category="EVIDENCE_SUMMARY",
        created_from_evidence_ids=("ev-0001",),
        content={"statement": "transport layer enabled on the edge listener"},
    )
    fetched = service.get_record(record.record_id, audit_id=AUDIT, project_id=PROJECT)
    assert fetched is not None and fetched.digest == record.digest
    ref = service.reference(fetched)
    assert ref.record_id == record.record_id
    chain = service.provenance_chain(fetched)
    assert chain[0] == "origin:evidence:collector"
    assert "evidence:ev-0001" in chain


def test_e2e_b_reingest_is_idempotent():
    """The same observation re-ingested yields one record, one digest."""
    service = SecurityKnowledgeService()
    first, _ = _remember(service)
    second, _ = _remember(service)
    listed = service.store.list_records(audit_id=AUDIT, project_id=PROJECT)
    assert first.record_id == second.record_id
    assert len(listed) == 1


def test_service_exposes_no_delete_surface():
    service = SecurityKnowledgeService()
    for banned in ("delete", "forget", "purge", "remove", "drop"):
        assert not hasattr(service, banned)


def test_access_decision_is_scope_bound():
    service = SecurityKnowledgeService()
    access = service.access(audit_id=AUDIT, project_id=PROJECT)
    assert access.audit_id == AUDIT
    assert access.allowed_operations == ("read",)
