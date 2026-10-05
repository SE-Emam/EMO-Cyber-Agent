"""Unit tests for the Agent-A → Agent-B trust boundary gate — POST-T018."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

import pytest

from emo_cyber_agent.subagent.trust import HostIntegrationError, SecurityDecision
from emo_cyber_agent.subagent.trust_boundary import (
    MAX_DELEGATION_DEPTH,
    TrustBoundaryCode,
    TrustBoundaryError,
    TrustEdge,
    assert_chain,
    assert_edge,
    evaluate_chain,
    evaluate_edge,
)

NOW = 150
AUDIT = "audit-001"
PROJECT = "project-001"


def _edge(
    from_agent="agent-a",
    to_agent="agent-b",
    depth=1,
    audience="agent-b",
    valid_from=100,
    valid_until=200,
    scope=("read", "write"),
    scope_ref="scope-root",
    audit_id=AUDIT,
    project_id=PROJECT,
) -> TrustEdge:
    return TrustEdge(
        from_agent=from_agent,
        to_agent=to_agent,
        delegation_depth=depth,
        audience=audience,
        valid_from=valid_from,
        valid_until=valid_until,
        scope=tuple(scope),
        scope_ref=scope_ref,
        audit_id=audit_id,
        project_id=project_id,
    )


# --- direct edge allow ---


def test_direct_edge_allow():
    decision = evaluate_edge(_edge(), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.ALLOW
    assert decision.evaluated_at == NOW
    assert decision.reasons


def test_assert_edge_allow_no_raise():
    assert_edge(_edge(), receiver="agent-b", now=NOW) is None


def test_edge_roundtrip():
    assert TrustEdge.from_dict(_edge().to_dict()) == _edge()


def test_max_depth_boundary_allows():
    decision = evaluate_edge(_edge(depth=MAX_DELEGATION_DEPTH), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.ALLOW


# --- depth overflow ---


def test_depth_overflow_deny():
    decision = evaluate_edge(_edge(depth=MAX_DELEGATION_DEPTH + 1), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "depth-overflow" in decision.reasons[0]


def test_chain_depth_overflow_deny():
    chain = [
        _edge(depth=0, scope=("read", "write", "admin")),
        _edge(from_agent="agent-b", to_agent="agent-c", depth=MAX_DELEGATION_DEPTH + 1, audience="agent-c", scope=("read",)),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "depth-overflow" in decision.reasons[0]


def test_chain_depth_must_deepen():
    chain = [
        _edge(depth=1, scope=("read", "write")),
        _edge(from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c", scope=("read",)),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "depth-order" in decision.reasons[0]


# --- audience mismatch ---


def test_audience_mismatch_deny():
    decision = evaluate_edge(_edge(audience="agent-evil"), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "audience-mismatch" in decision.reasons[0]


def test_recipient_mismatch_deny():
    decision = evaluate_edge(_edge(to_agent="agent-c", audience="agent-c"), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY


def test_chain_audience_mismatch_deny():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-evil", scope=("read",)),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "audience-mismatch" in decision.reasons[0]


# --- expiry ---


def test_expired_deny():
    decision = evaluate_edge(_edge(valid_from=100, valid_until=149), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "expired" in decision.reasons[0]


def test_not_yet_valid_deny():
    decision = evaluate_edge(_edge(valid_from=151, valid_until=300), receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY


def test_inverted_window_deny():
    edge = _edge()
    inverted = edge.model_copy(update={"valid_from": 300, "valid_until": 100})
    decision = evaluate_edge(inverted, receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "invalid-window" in decision.reasons[0]


def test_chain_second_hop_expired_deny():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(
            from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c",
            scope=("read",), valid_from=100, valid_until=149,
        ),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "expired" in decision.reasons[0]


# --- narrowing ok / widening deny ---


def test_nested_narrowing_allow():
    chain = [
        _edge(depth=0, scope=("read", "write", "admin")),
        _edge(from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c", scope=("read", "write")),
        _edge(from_agent="agent-c", to_agent="agent-d", depth=2, audience="agent-d", scope=("read",)),
    ]
    decision = evaluate_chain(chain, receiver="agent-d", now=NOW)
    assert decision.decision == SecurityDecision.ALLOW


def test_equal_scope_is_narrowing_ok():
    chain = [
        _edge(depth=0, scope=("read",)),
        _edge(from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c", scope=("read",)),
    ]
    assert evaluate_chain(chain, receiver="agent-c", now=NOW).decision == SecurityDecision.ALLOW


def test_widening_deny():
    chain = [
        _edge(depth=0, scope=("read",)),
        _edge(
            from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c",
            scope=("read", "admin"),
        ),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "scope-widening" in decision.reasons[0]


def test_chain_discontinuity_deny():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(from_agent="agent-x", to_agent="agent-c", depth=1, audience="agent-c", scope=("read",)),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.DENY
    assert "chain-discontinuity" in decision.reasons[0]


# --- cross-audit / cross-project quarantine ---


def test_cross_audit_without_fresh_context_quarantine():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(
            from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c",
            scope=("read",), audit_id="audit-002",
        ),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW, has_fresh_context=False)
    assert decision.decision == SecurityDecision.QUARANTINE
    assert "cross-boundary" in decision.reasons[0]


def test_cross_audit_with_fresh_context_allow():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(
            from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c",
            scope=("read",), audit_id="audit-002",
        ),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW, has_fresh_context=True)
    assert decision.decision == SecurityDecision.ALLOW


def test_cross_project_without_fresh_context_quarantine():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(
            from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c",
            scope=("read",), project_id="project-002",
        ),
    ]
    decision = evaluate_chain(chain, receiver="agent-c", now=NOW)
    assert decision.decision == SecurityDecision.QUARANTINE


def test_expected_audit_mismatch_quarantine():
    decision = evaluate_chain(
        [_edge()], receiver="agent-b", now=NOW, expected_audit_id="audit-other",
    )
    assert decision.decision == SecurityDecision.QUARANTINE


def test_expected_audit_match_allow():
    decision = evaluate_chain(
        [_edge()], receiver="agent-b", now=NOW,
        expected_audit_id=AUDIT, expected_project_id=PROJECT,
    )
    assert decision.decision == SecurityDecision.ALLOW


# --- raising variants interop ---


def test_assert_chain_quarantine_error_interop():
    chain = [
        _edge(depth=0, scope=("read", "write")),
        _edge(
            from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c",
            scope=("read",), audit_id="audit-002",
        ),
    ]
    with pytest.raises(TrustBoundaryError) as exc:
        assert_chain(chain, receiver="agent-c", now=NOW)
    assert exc.value.boundary == TrustBoundaryCode.CROSS_BOUNDARY
    assert exc.value.decision == SecurityDecision.QUARANTINE
    assert exc.value.requires_quarantine() is True
    assert exc.value.quarantine is True


def test_assert_edge_deny_is_host_integration_error():
    with pytest.raises(HostIntegrationError):
        assert_edge(_edge(depth=MAX_DELEGATION_DEPTH + 1), receiver="agent-b", now=NOW)


def test_empty_chain_deny():
    decision = evaluate_chain([], receiver="agent-b", now=NOW)
    assert decision.decision == SecurityDecision.DENY


def test_evaluate_deterministic():
    first = evaluate_chain(
        [_edge(depth=0, scope=("read", "write")),
         _edge(from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c", scope=("read",))],
        receiver="agent-c", now=NOW,
    )
    for _ in range(3):
        again = evaluate_chain(
            [_edge(depth=0, scope=("read", "write")),
             _edge(from_agent="agent-b", to_agent="agent-c", depth=1, audience="agent-c", scope=("read",))],
            receiver="agent-c", now=NOW,
        )
        assert again == first


def test_no_escalation_surface():
    import emo_cyber_agent.subagent.trust_boundary as tb

    for forbidden in ("escalate", "execute", "grant", "approve", "run", "spawn", "exec"):
        assert not hasattr(tb, forbidden), forbidden
