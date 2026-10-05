"""POST-RC-011 — Knowledge isolation & scope enforcement (offline).

No global namespace: every read and query binds to the caller's
(audit, project) and optional snapshot window. Same fingerprint,
same key, same text never implies same scope. Includes end-to-end
workflow D (two audits, one project identity, zero cross-visibility).
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.security_knowledge import (
    KnowledgeError,
    KnowledgeErrorCode,
    SecurityKnowledgeService,
    bind_query_scope,
    check_record_scope,
)
from emo_cyber_agent.security_knowledge.store import InMemoryKnowledgeStore

FIXTURES = Path("tests/fixtures/security_knowledge")
AUDIT = "audit-2026-001"
OTHER_AUDIT = "audit-2026-002"
PROJECT = "payments-api"
OTHER_PROJECT = "billing-worker"
KEY = "regression:route:login:auth"


def _fixture() -> dict:
    return json.loads((FIXTURES / "knowledge_records.json").read_text())


def _seed(service: SecurityKnowledgeService, *, audit_id: str = AUDIT, project_id: str = PROJECT, snapshot_id: str = "snap-1", source_id: str = "ev-0001", regression_key: str = KEY):
    return service.remember(
        audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id,
        source_type="evidence", source_id=source_id, category="OBSERVED_FACT",
        regression_key=regression_key,
        content={"statement": "transport layer enabled on the edge listener"},
    )[0]


# ---------------- record-level scope ----------------

def test_cross_audit_record_denied():
    record = _seed(service=SecurityKnowledgeService())
    with pytest.raises(KnowledgeError) as e:
        check_record_scope(record, audit_id=OTHER_AUDIT, project_id=PROJECT)
    assert e.value.code == KnowledgeErrorCode.CROSS_AUDIT


def test_cross_project_record_denied():
    record = _seed(service=SecurityKnowledgeService())
    with pytest.raises(KnowledgeError) as e:
        check_record_scope(record, audit_id=AUDIT, project_id=OTHER_PROJECT)
    assert e.value.code == KnowledgeErrorCode.CROSS_PROJECT


def test_cross_snapshot_record_denied():
    record = _seed(service=SecurityKnowledgeService(), snapshot_id="snap-a")
    with pytest.raises(KnowledgeError) as e:
        check_record_scope(record, audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-b")
    assert e.value.code == KnowledgeErrorCode.CROSS_SNAPSHOT


def test_service_get_record_cross_audit_returns_absence():
    service = SecurityKnowledgeService()
    record = _seed(service)
    assert service.get_record(record.record_id, audit_id=AUDIT, project_id=PROJECT) is not None
    assert service.get_record(record.record_id, audit_id=OTHER_AUDIT, project_id=PROJECT) is None
    assert service.get_record(record.record_id, audit_id=AUDIT, project_id=OTHER_PROJECT) is None


def test_service_get_record_cross_snapshot_raises():
    service = SecurityKnowledgeService()
    record = _seed(service, snapshot_id="snap-a")
    with pytest.raises(KnowledgeError) as e:
        service.get_record(record.record_id, audit_id=AUDIT, project_id=PROJECT, snapshot_id="snap-b")
    assert e.value.code == KnowledgeErrorCode.CROSS_SNAPSHOT


# ---------------- query scope binding ----------------

def test_query_scope_cannot_widen_audit():
    with pytest.raises(KnowledgeError) as e:
        bind_query_scope(caller_audit_id=AUDIT, caller_project_id=PROJECT, requested_audit_id=OTHER_AUDIT)
    assert e.value.code == KnowledgeErrorCode.CROSS_AUDIT


def test_query_scope_cannot_widen_project():
    with pytest.raises(KnowledgeError) as e:
        bind_query_scope(caller_audit_id=AUDIT, caller_project_id=PROJECT, requested_project_id=OTHER_PROJECT)
    assert e.value.code == KnowledgeErrorCode.CROSS_PROJECT


def test_query_scope_requires_caller_identity():
    with pytest.raises(KnowledgeError) as e:
        bind_query_scope(caller_audit_id="", caller_project_id=PROJECT)
    assert e.value.code == KnowledgeErrorCode.SCOPE_DENIED


def test_query_scope_rejects_forbidden_markers():
    for marker in ("other_audit_id", "raw_backend_query", "path_escape", "tenant_scope", "policy_override"):
        with pytest.raises(KnowledgeError) as e:
            bind_query_scope(caller_audit_id=AUDIT, caller_project_id=PROJECT, requested_snapshot_id=marker)
        assert e.value.code == KnowledgeErrorCode.QUERY_REJECTED


def test_remember_rejects_forbidden_scope_tokens():
    service = SecurityKnowledgeService()
    with pytest.raises(KnowledgeError) as e:
        _seed(service, audit_id="other_audit_id")
    assert e.value.code == KnowledgeErrorCode.QUERY_REJECTED


# ---------------- store scoping ----------------

def test_store_lists_only_own_scope():
    service = SecurityKnowledgeService()
    _seed(service, audit_id=AUDIT)
    _seed(service, audit_id=OTHER_AUDIT, source_id="ev-9001")
    own = service.store.list_records(audit_id=AUDIT, project_id=PROJECT)
    foreign = service.store.list_records(audit_id=OTHER_AUDIT, project_id=PROJECT)
    assert len(own) == 1 and len(foreign) == 1
    assert {r.audit_id for r in own} == {AUDIT}
    assert {r.audit_id for r in foreign} == {OTHER_AUDIT}


def test_regression_key_lookup_is_scope_bound():
    service = SecurityKnowledgeService()
    _seed(service, audit_id=AUDIT)
    _seed(service, audit_id=OTHER_AUDIT, source_id="ev-9001")
    assert len(service.find_by_regression_key(KEY, audit_id=AUDIT, project_id=PROJECT)) == 1
    assert len(service.find_by_regression_key(KEY, audit_id=OTHER_AUDIT, project_id=PROJECT)) == 1
    assert service.find_by_regression_key(KEY, audit_id=AUDIT, project_id=OTHER_PROJECT) == []


def test_namespace_mismatch_denied():
    store = InMemoryKnowledgeStore()
    service = SecurityKnowledgeService(store)
    record = _seed(service)
    assert store.get_record(record.record_id, audit_id=AUDIT, project_id=PROJECT, namespace="") is not None
    with pytest.raises(KnowledgeError) as e:
        store.get_record(record.record_id, audit_id=AUDIT, project_id=PROJECT, namespace="other")
    assert e.value.code == KnowledgeErrorCode.SCOPE_DENIED


def test_related_observations_stay_in_scope():
    service = SecurityKnowledgeService()
    _seed(service, source_id="ev-0001")
    _seed(service, audit_id=OTHER_AUDIT, source_id="ev-0001")
    matches = service.find_related_observations("ev-0001", audit_id=AUDIT, project_id=PROJECT)
    assert matches and {r.audit_id for r in matches} == {AUDIT}


def test_fixture_foreign_records_never_visible():
    fixture = _fixture()
    foreign = [r for r in fixture["records"] if r["audit_id"] != AUDIT]
    assert foreign, "fixture must contain other-audit records"
    service = SecurityKnowledgeService()
    _seed(service)
    listed = service.store.list_records(audit_id=AUDIT, project_id=PROJECT)
    assert all(r.audit_id == AUDIT for r in listed)


# ---------------- end-to-end ----------------

def test_e2e_d_two_audits_share_key_without_cross_visibility():
    """Two audits observe the same project identity and the same
    regression key: neither can read the other's memory."""
    service = SecurityKnowledgeService()
    a = _seed(service, audit_id=AUDIT, source_id="ev-a")
    b = _seed(service, audit_id=OTHER_AUDIT, source_id="ev-b")
    assert a.record_id != b.record_id or a.audit_id != b.audit_id
    assert [r.audit_id for r in service.find_by_regression_key(KEY, audit_id=AUDIT, project_id=PROJECT)] == [AUDIT]
    assert [r.audit_id for r in service.find_by_regression_key(KEY, audit_id=OTHER_AUDIT, project_id=PROJECT)] == [OTHER_AUDIT]
    assert service.get_record(a.record_id, audit_id=OTHER_AUDIT, project_id=PROJECT) is None


def test_layer_context_from_foreign_audit_is_invisible():
    service = SecurityKnowledgeService()
    record = service.remember_from_layer(
        "change-analysis", audit_id=OTHER_AUDIT, project_id=PROJECT,
        source_id="cs-1", content={"state": "CHANGED"},
    )
    assert service.get_record(record.record_id, audit_id=AUDIT, project_id=PROJECT) is None
    assert service.store.list_records(audit_id=AUDIT, project_id=PROJECT) == []
