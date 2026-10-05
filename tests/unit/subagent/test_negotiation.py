"""Capability-negotiation tests — POST-T018 (Agent 4A)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent.negotiation import (
    SECURITY_REVIEW_OFFER,
    NegotiationRecord,
    negotiate,
    propose_offer,
)
from emo_cyber_agent.subagent.trust import HostIntegrationError

OFFER = tuple(sorted(SECURITY_REVIEW_OFFER))


def test_propose_security_review_minimal_defaults():
    offered = propose_offer("security-review", server=True)
    assert tuple(sorted(offered)) == OFFER
    for cap in ("repo.read", "codeintel.read", "evidence.read", "evidence.create", "verification.safe", "report.generate"):
        assert cap in offered


def test_propose_requires_server_flag():
    with pytest.raises(HostIntegrationError):
        propose_offer("security-review")


def test_happy_path_narrowing():
    requested = ("repo.read", "report.generate")
    rec = negotiate("security-review", requested, server=True)
    assert rec.offered == OFFER
    assert rec.requested == tuple(sorted(requested))
    assert rec.granted == tuple(sorted(requested))
    assert rec.denied == ()
    assert "accepted" in rec.reason


def test_denied_with_reason_never_silent():
    rec = negotiate("security-review", ("repo.read", "scanner.network.read"), server=True)
    assert rec.granted == ("repo.read",)
    assert rec.denied != ()
    assert "scanner.network.read" in rec.denied
    assert "scanner.network.read" in rec.reason  # explicit, per-item reason


def test_empty_request_grants_nothing():
    rec = negotiate("security-review", (), server=True)
    assert rec.granted == ()
    assert rec.denied == ()
    assert rec.reason  # reason still recorded


def test_unknown_capability_denied():
    rec = negotiate("security-review", ("nope.unknown-cap",), server=True)
    assert rec.granted == ()
    assert rec.denied == ("nope.unknown-cap",)
    assert "unknown-capability:nope.unknown-cap" in rec.reason


def test_replay_determinism_same_input_same_record():
    first = negotiate("security-review", ("repo.read", "evidence.read"), server=True)
    second = negotiate("security-review", ("evidence.read", "repo.read"), server=True)
    assert first.negotiation_id == second.negotiation_id
    assert first.digest == second.digest
    assert first.to_canonical_json() == second.to_canonical_json()
    assert NegotiationRecord.from_dict(first.to_dict()) == first


def test_negotiate_requires_server_flag():
    with pytest.raises(HostIntegrationError):
        negotiate("security-review", ("repo.read",))


def test_replayed_offer_mismatch_rejected():
    with pytest.raises(HostIntegrationError):
        negotiate("security-review", ("repo.read",), server=True, offered=("repo.read", "admin.write"))


def test_module_has_no_execution():
    src = (Path(__file__).parent.parent.parent.parent / "src" / "emo_cyber_agent" / "subagent" / "negotiation.py").read_text()
    for marker in ("subprocess", "os.system", "popen", "socket", "urllib", "__import__"):
        assert marker not in src, marker
