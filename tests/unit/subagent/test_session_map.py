"""Unit tests for MCP transport ↔ subagent session mapping — POST-T018."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.session_map import (
    DEFAULT_TTL_SECONDS,
    MAX_TOKEN_LENGTH,
    McpSessionAttachment,
    McpSessionMap,
    SessionMapCode,
    SessionMapError,
    validate_mcp_token,
)
from emo_cyber_agent.subagent.trust import HostIntegrationError, SecurityDecision

AUDIT = "audit-001"
PROJECT = "project-001"
SNAPSHOT = "snap-001"
HOST = "host-alpha"
TOKEN = "progress-token-1"
NOW = 1000


def _session(**over) -> SubagentSession:
    base = dict(
        session_id="sess-01",
        host_id=HOST,
        audit_id=AUDIT,
        project_id=PROJECT,
        snapshot_id=SNAPSHOT,
        created=100,
        expires=9999,
    )
    base.update(over)
    return SubagentSession(**base)


def _attach(map_: McpSessionMap, session=None, token: str = TOKEN, now: int = NOW, **kw) -> McpSessionAttachment:
    session = session if session is not None else _session()
    return map_.attach(
        session,
        mcp_token_or_id=token,
        audit_id=kw.get("audit_id", AUDIT),
        project_id=kw.get("project_id", PROJECT),
        snapshot_id=kw.get("snapshot_id", SNAPSHOT),
        now=now,
        ttl=kw.get("ttl", DEFAULT_TTL_SECONDS),
    )


# --- attach happy path ---


def test_attach_happy_returns_attachment():
    att = _attach(McpSessionMap())
    assert att.mcp_token_or_id == TOKEN
    assert att.session_id == "sess-01"
    assert att.host_id == HOST
    assert (att.audit_id, att.project_id, att.snapshot_id) == (AUDIT, PROJECT, SNAPSHOT)
    assert att.attached_at == NOW
    assert att.last_seen == NOW


def test_attach_reattach_same_session_refreshes_last_seen():
    map_ = McpSessionMap()
    first = _attach(map_, now=NOW)
    second = _attach(map_, now=NOW + 10)
    assert second.mcp_token_or_id == first.mcp_token_or_id
    assert second.attached_at == NOW
    assert second.last_seen == NOW + 10
    assert len(map_) == 1


def test_attachment_roundtrip():
    att = _attach(McpSessionMap())
    assert McpSessionAttachment.from_dict(att.to_dict()) == att


def test_token_is_never_authority_resolve_unknown_is_keyerror():
    map_ = McpSessionMap()
    _attach(map_)
    with pytest.raises(KeyError):
        map_.resolve("some-unattached-token", now=NOW)


# --- triple mismatch ---


def test_triple_mismatch_quarantine():
    map_ = McpSessionMap()
    with pytest.raises(HostIntegrationError) as exc:
        _attach(map_, audit_id="audit-other")
    assert exc.value.quarantine is True


def test_triple_mismatch_each_link_quarantines():
    for kw in ({"audit_id": "audit-x"}, {"project_id": "project-x"}, {"snapshot_id": "snap-x"}):
        with pytest.raises(HostIntegrationError) as exc:
            _attach(McpSessionMap(), **kw)
        assert exc.value.quarantine is True


def test_triple_mismatch_stores_nothing():
    map_ = McpSessionMap()
    with pytest.raises(HostIntegrationError):
        _attach(map_, audit_id="audit-other")
    assert len(map_) == 0


# --- token shape rejects ---


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "\t\n ", "tok\x00en", "tok\x1fen", "tok\x7fen", "x" * (MAX_TOKEN_LENGTH + 1)],
    ids=["empty", "blank", "whitespace", "nul", "control", "del", "too-long"],
)
def test_token_shape_rejects(bad: str):
    with pytest.raises(SessionMapError) as exc:
        validate_mcp_token(bad)
    assert exc.value.map_code == SessionMapCode.INVALID_TOKEN
    assert exc.value.decision == SecurityDecision.DENY
    assert exc.value.quarantine is False


def test_token_shape_rejects_non_str():
    with pytest.raises(TypeError):
        validate_mcp_token(123)  # type: ignore[arg-type]


def test_attach_rejects_bad_token_shape_and_stores_nothing():
    map_ = McpSessionMap()
    with pytest.raises(SessionMapError) as exc:
        map_.attach(_session(), mcp_token_or_id="", audit_id=AUDIT, project_id=PROJECT, snapshot_id=SNAPSHOT, now=NOW)
    assert exc.value.map_code == SessionMapCode.INVALID_TOKEN
    assert len(map_) == 0


def test_token_shape_deny_is_not_quarantine():
    with pytest.raises(SessionMapError) as exc:
        validate_mcp_token("")
    assert exc.value.requires_quarantine() is False


# --- stale / TTL ---


def test_stale_ttl_detach_plus_quarantine_on_resolve():
    map_ = McpSessionMap()
    _attach(map_, now=NOW, ttl=60)
    with pytest.raises(SessionMapError) as exc:
        map_.resolve(TOKEN, now=NOW + 61, ttl=60)
    assert exc.value.map_code == SessionMapCode.STALE_ATTACHMENT
    assert exc.value.decision == SecurityDecision.QUARANTINE
    assert exc.value.quarantine is True
    assert exc.value.requires_quarantine() is True
    assert TOKEN not in map_  # detached
    assert len(map_) == 0


def test_stale_ttl_detach_plus_quarantine_on_reattach():
    map_ = McpSessionMap()
    _attach(map_, now=NOW, ttl=60)
    with pytest.raises(SessionMapError) as exc:
        _attach(map_, now=NOW + 61, ttl=60)
    assert exc.value.map_code == SessionMapCode.STALE_ATTACHMENT
    assert exc.value.quarantine is True
    assert len(map_) == 0


def test_live_within_ttl_resolves():
    map_ = McpSessionMap()
    att = _attach(map_, now=NOW, ttl=60)
    assert map_.resolve(TOKEN, now=NOW + 60, ttl=60) == att


def test_stale_snapshot_mismatch_detach_plus_quarantine():
    map_ = McpSessionMap()
    _attach(map_, now=NOW)
    rotated = _session(snapshot_id="snap-002")
    with pytest.raises(SessionMapError) as exc:
        map_.attach(
            rotated,
            mcp_token_or_id=TOKEN,
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id="snap-002",
            now=NOW + 5,
        )
    assert exc.value.map_code == SessionMapCode.STALE_ATTACHMENT
    assert exc.value.quarantine is True
    assert len(map_) == 0


# --- token-reuse deny ---


def test_token_reuse_on_different_session_denied():
    map_ = McpSessionMap()
    _attach(map_, now=NOW)
    other = _session(session_id="sess-02")
    with pytest.raises(SessionMapError) as exc:
        map_.attach(
            other,
            mcp_token_or_id=TOKEN,
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            now=NOW + 5,
        )
    assert exc.value.map_code == SessionMapCode.REPLAY_DENIED
    assert exc.value.decision == SecurityDecision.DENY
    assert exc.value.quarantine is False
    assert exc.value.requires_quarantine() is False


def test_token_reuse_deny_leaves_original_untouched():
    map_ = McpSessionMap()
    first = _attach(map_, now=NOW)
    other = _session(session_id="sess-02")
    with pytest.raises(SessionMapError):
        map_.attach(
            other,
            mcp_token_or_id=TOKEN,
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            now=NOW + 5,
        )
    assert map_.resolve(TOKEN, now=NOW + 5) == first


def test_replay_is_host_integration_error():
    map_ = McpSessionMap()
    _attach(map_, now=NOW)
    with pytest.raises(HostIntegrationError):
        map_.attach(
            _session(session_id="sess-02"),
            mcp_token_or_id=TOKEN,
            audit_id=AUDIT,
            project_id=PROJECT,
            snapshot_id=SNAPSHOT,
            now=NOW + 5,
        )


# --- detach / purge ---


def test_detach_purges_and_allows_clean_reattach():
    map_ = McpSessionMap()
    _attach(map_, now=NOW)
    assert map_.detach(TOKEN) is True
    assert map_.detach(TOKEN) is False
    second = _attach(map_, now=NOW + 10)
    assert second.attached_at == NOW + 10


# --- determinism ---


def test_attach_deterministic_same_inputs():
    def build() -> McpSessionAttachment:
        return _attach(McpSessionMap(), now=NOW)

    first = build()
    for _ in range(3):
        nxt = build()
        assert nxt == first
        assert nxt.to_canonical_json() == first.to_canonical_json()
    assert first.digest() == build().digest()


def test_failure_deterministic():
    for _ in range(3):
        with pytest.raises(SessionMapError) as exc:
            validate_mcp_token("")
        assert exc.value.map_code == SessionMapCode.INVALID_TOKEN
    for _ in range(3):
        map_ = McpSessionMap()
        _attach(map_, now=NOW)
        with pytest.raises(SessionMapError) as exc:
            map_.attach(
                _session(session_id="sess-02"),
                mcp_token_or_id=TOKEN,
                audit_id=AUDIT,
                project_id=PROJECT,
                snapshot_id=SNAPSHOT,
                now=NOW + 5,
            )
        assert exc.value.map_code == SessionMapCode.REPLAY_DENIED


# --- POST-T018 review regression (L5): entry cap + TTL sweep ---


def test_regression_entry_cap_rejects_new_with_explicit_error(monkeypatch):
    import emo_cyber_agent.subagent.session_map as session_map_mod

    monkeypatch.setattr(session_map_mod, "MAX_SESSION_MAP_ENTRIES", 2)
    map_ = McpSessionMap()
    _attach(map_, token="tok-1", now=NOW)
    _attach(map_, token="tok-2", now=NOW)
    with pytest.raises(SessionMapError) as exc:
        _attach(map_, token="tok-3", now=NOW)
    assert exc.value.map_code == SessionMapCode.CAPACITY_EXCEEDED
    assert exc.value.decision == SecurityDecision.DENY
    assert exc.value.quarantine is False
    assert len(map_) == 2
    # Refreshing a live entry under a full map still works (no growth).
    _attach(map_, token="tok-1", now=NOW + 5)
    assert len(map_) == 2


def test_regression_sweep_expired_purges_idle_entries():
    map_ = McpSessionMap()
    _attach(map_, token="tok-1", now=NOW, ttl=60)
    _attach(map_, token="tok-2", now=NOW, ttl=60)
    assert map_.sweep_expired(now=NOW + 30, ttl=60) == 0
    assert len(map_) == 2
    assert map_.sweep_expired(now=NOW + 61, ttl=60) == 2
    assert len(map_) == 0
