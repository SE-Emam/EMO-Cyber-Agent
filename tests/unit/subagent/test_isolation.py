"""Host-context isolation tests — POST-T018 (Agent 3D)."""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.subagent.firewall import HostContextChunk
from emo_cyber_agent.subagent.isolation import (
    MAX_SCOPED_BYTES,
    MAX_SCOPED_CHUNKS,
    HostContextStore,
    HostScope,
    IsolationBoundExceeded,
    ScopeViolation,
)
from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.trust import HostErrorCode


def _scope(**over: Any) -> HostScope:
    base: dict[str, Any] = {
        "host_id": "host-01",
        "audit_id": "audit-01",
        "project_id": "proj-01",
        "snapshot_id": "snap-01",
    }
    base.update(over)
    return HostScope(**base)


def _chunk(text: str = "data", **over: Any) -> HostContextChunk:
    base: dict[str, Any] = {
        "audit_id": "audit-01",
        "project_id": "proj-01",
        "snapshot_id": "snap-01",
        "source": "host-01",
        "text": text,
    }
    base.update(over)
    return HostContextChunk(**base)


def _session() -> SubagentSession:
    return SubagentSession(
        session_id="sess-01",
        host_id="host-01",
        audit_id="audit-01",
        project_id="proj-01",
        snapshot_id="snap-01",
        created=0,
        expires=999999,
    )


# --- happy path ---


def test_happy_path_attach_read():
    store = HostContextStore()
    scope = _scope()
    n = store.attach(scope, _chunk("alpha"))
    assert n == 1
    store.attach(scope, _chunk("beta"))
    got = store.read(scope, "audit-01")
    assert [c.text for c in got] == ["alpha", "beta"]


def test_scope_from_session_roundtrip():
    scope = HostScope.from_session(_session())
    assert scope.key() == ("host-01", "audit-01", "proj-01", "snap-01")
    assert HostScope.from_dict(scope.to_dict()) == scope
    scope.to_canonical_json()
    with pytest.raises(TypeError):
        HostScope.from_session("nope")  # type: ignore[arg-type]


# --- cross-scope blocked: attach mismatches ---


def test_cross_audit_attach_blocked_and_quarantined():
    store = HostContextStore()
    scope = _scope()
    with pytest.raises(ScopeViolation) as exc:
        store.attach(scope, _chunk("x", audit_id="audit-02"))
    assert exc.value.quarantine is True
    assert exc.value.blocked is True
    assert exc.value.code == HostErrorCode.CROSS_AUDIT
    assert store.is_quarantined(scope) is True
    # Quarantined scope keeps failing closed with no data returned.
    with pytest.raises(ScopeViolation):
        store.read(scope, "audit-01")
    with pytest.raises(ScopeViolation):
        store.attach(scope, _chunk("ok"))


def test_cross_host_attach_blocked():
    store = HostContextStore()
    scope = _scope()
    with pytest.raises(ScopeViolation) as exc:
        store.attach(scope, _chunk("x", source="host-02"))
    assert exc.value.code == HostErrorCode.BINDING_MISMATCH
    assert exc.value.quarantine is True and exc.value.blocked is True


def test_cross_project_attach_blocked():
    store = HostContextStore()
    with pytest.raises(ScopeViolation) as exc:
        store.attach(_scope(), _chunk("x", project_id="proj-02"))
    assert exc.value.code == HostErrorCode.BINDING_MISMATCH
    assert exc.value.quarantine is True


def test_cross_snapshot_attach_blocked():
    store = HostContextStore()
    with pytest.raises(ScopeViolation) as exc:
        store.attach(_scope(), _chunk("x", snapshot_id="snap-02"))
    assert exc.value.code == HostErrorCode.BINDING_MISMATCH


# --- cross-scope blocked: read ---


def test_cross_audit_read_blocked_no_data():
    store = HostContextStore()
    scope = _scope()
    store.attach(scope, _chunk("secret-bytes"))
    with pytest.raises(ScopeViolation) as exc:
        store.read(scope, "audit-02")
    assert exc.value.code == HostErrorCode.CROSS_AUDIT
    assert exc.value.blocked is True
    # Exception carries no chunk payload.
    assert "secret-bytes" not in str(exc.value)


def test_per_host_partitioning():
    store = HostContextStore()
    a = _scope(host_id="host-01")
    b = _scope(host_id="host-02")
    store.attach(a, _chunk("for-a", source="host-01"))
    store.attach(b, _chunk("for-b", source="host-02", audit_id="audit-01"))
    assert [c.text for c in store.read(a, "audit-01")] == ["for-a"]
    assert [c.text for c in store.read(b, "audit-01")] == ["for-b"]


# --- bounds ---


def test_chunk_count_bound_evicts_oldest_within_scope():
    store = HostContextStore(max_chunks=2, max_bytes=10**6)
    scope = _scope()
    store.attach(scope, _chunk("one"))
    store.attach(scope, _chunk("two"))
    store.attach(scope, _chunk("three"))
    assert [c.text for c in store.read(scope, "audit-01")] == ["two", "three"]


def test_byte_bound_evicts_oldest_within_scope():
    store = HostContextStore(max_chunks=100, max_bytes=6)
    scope = _scope()
    store.attach(scope, _chunk("aaaa"))  # 4 bytes
    store.attach(scope, _chunk("bbbb"))  # 4+4 > 6 → evict "aaaa"
    assert [c.text for c in store.read(scope, "audit-01")] == ["bbbb"]
    assert store.scope_byte_count(scope) == 4


def test_single_oversized_chunk_rejected_not_buffered():
    store = HostContextStore(max_chunks=10, max_bytes=4)
    scope = _scope()
    with pytest.raises(IsolationBoundExceeded):
        store.attach(scope, _chunk("toolarge"))
    assert store.scope_chunk_count(scope) == 0
    assert store.read(scope, "audit-01") == ()


def test_default_bounds_and_invalid_bounds():
    assert MAX_SCOPED_CHUNKS > 0 and MAX_SCOPED_BYTES > 0
    store = HostContextStore()
    assert store.max_chunks == MAX_SCOPED_CHUNKS
    assert store.max_bytes == MAX_SCOPED_BYTES
    with pytest.raises(ValueError):
        HostContextStore(max_chunks=0)
    with pytest.raises(ValueError):
        HostContextStore(max_bytes=0)
    with pytest.raises(TypeError):
        HostContextStore(max_chunks="8")  # type: ignore[arg-type]


def test_bounds_never_spill_into_other_scope():
    store = HostContextStore(max_chunks=1, max_bytes=10**6)
    a = _scope(host_id="host-01")
    b = _scope(host_id="host-02")
    store.attach(a, _chunk("a1", source="host-01"))
    store.attach(b, _chunk("b1", source="host-02"))
    store.attach(a, _chunk("a2", source="host-01"))  # evicts a1 only
    assert [c.text for c in store.read(a, "audit-01")] == ["a2"]
    assert [c.text for c in store.read(b, "audit-01")] == ["b1"]


# --- purge on detach / session end ---


def test_purge_on_detach():
    store = HostContextStore()
    scope = _scope()
    store.attach(scope, _chunk("a"))
    store.attach(scope, _chunk("b"))
    assert store.detach(scope) == 2
    assert store.read(scope, "audit-01") == ()
    assert store.scope_chunk_count(scope) == 0
    assert store.scope_byte_count(scope) == 0


def test_detach_clears_quarantine_for_fresh_session():
    store = HostContextStore()
    scope = _scope()
    with pytest.raises(ScopeViolation):
        store.attach(scope, _chunk("x", audit_id="audit-02"))
    assert store.is_quarantined(scope) is True
    store.detach(scope)
    assert store.is_quarantined(scope) is False
    store.attach(scope, _chunk("fresh"))
    assert [c.text for c in store.read(scope, "audit-01")] == ["fresh"]


def test_end_session_purges_scope():
    store = HostContextStore()
    session = _session()
    store.attach(HostScope.from_session(session), _chunk("a"))
    assert store.end_session(session) == 1
    assert store.read(HostScope.from_session(session), "audit-01") == ()


# --- type safety + no-execution surface ---


def test_wrong_types_rejected():
    store = HostContextStore()
    scope = _scope()
    with pytest.raises(TypeError):
        store.attach("nope", _chunk("x"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        store.attach(scope, "nope")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        store.read("nope", "audit-01")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        store.detach("nope")  # type: ignore[arg-type]


def test_no_execution_or_network_surface():
    import emo_cyber_agent.subagent.isolation as iso

    for token in ("subprocess", "os.system", "socket", "urllib", "requests", "eval(", "exec("):
        assert token not in Path(iso.__file__).read_text()
    assert not hasattr(iso.HostContextStore, "execute")
    assert not hasattr(iso.HostContextStore, "fetch")
