"""Handoff-gate tests — POST-T018 (Agent 7A)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent.handoff import ResultStatus
from emo_cyber_agent.subagent.handoff_gate import (
    GateStatus,
    assemble,
    envelope_digest,
)
from emo_cyber_agent.subagent.session import SubagentSession


def _session(**overrides):
    base = {
        "session_id": "sess-01",
        "host_id": "host-a",
        "audit_id": "audit-01",
        "project_id": "proj-01",
        "snapshot_id": "snap-01",
        "created": 100,
        "expires": 9999,
    }
    base.update(overrides)
    return SubagentSession.model_validate(base)


def _data(**overrides):
    base = {
        "task_id": "task-01",
        "finding_refs": ["F-001"],
        "evidence_refs": ["E-001"],
        "report_ref": "R-001",
        "limitations": ["limited network view"],
    }
    base.update(overrides)
    return base


def test_happy_handoff_completed():
    res = assemble(
        _session(),
        _data(),
        ["V-001"],
        "none",
        authorization_ref="authz-handoff-01",
        now=123,
    )
    assert res.status == GateStatus.COMPLETED
    assert res.envelope is not None
    assert res.envelope.status == ResultStatus.COMPLETED
    assert res.envelope.handoff.verification_refs == ("V-001",)
    assert res.envelope.handoff.recovery_state == "none"
    assert res.digest == envelope_digest(res.envelope)
    assert not res.quarantined


def test_verification_gate_hold():
    res = assemble(_session(), _data(), [], "none", now=123)
    assert res.status == GateStatus.HOLD
    assert res.envelope is None
    assert res.digest  # hold still signs a stable record

    res_blank = assemble(_session(), _data(), ["   "], "none", now=123)
    assert res_blank.status == GateStatus.HOLD
    assert res_blank.envelope is None


def test_scrub_integration_strips_cot_and_raw():
    res = assemble(
        _session(),
        _data(chain_of_thought="step by step", raw_output="tool dump", reasoning="because"),
        ["V-001"],
        "none",
        now=123,
    )
    assert res.status == GateStatus.COMPLETED
    assert res.envelope is not None
    payload = res.envelope.to_dict()
    assert "chain_of_thought" not in str(payload)
    assert "raw_output" not in payload
    assert any(r.startswith("cot:") for r in res.removed)
    assert any(r.startswith("raw-output:") for r in res.removed)


def test_provenance_present_audit_snapshot_digest():
    now = 456
    res = assemble(
        _session(),
        _data(),
        ["V-001"],
        "none",
        authorization_ref="authz-handoff-01",
        now=now,
    )
    assert res.status == GateStatus.COMPLETED
    assert res.envelope is not None
    (link,) = res.envelope.handoff.provenance
    assert link.session_id == "sess-01"
    assert link.task_id == "task-01"
    assert link.authorization_ref == "authz-handoff-01"
    assert link.recorded_at == now
    # audit → snapshot binding carried on both envelope and handoff
    assert res.envelope.audit_id == "audit-01"
    assert res.envelope.handoff.audit_id == "audit-01"
    assert res.envelope.handoff.snapshot_id == "snap-01"
    # digest signs the sealed envelope
    assert res.digest == envelope_digest(res.envelope)
    # compat + health snapshots attached
    assert res.envelope.compatibility.host_id == "host-a"
    assert res.envelope.health.note == ""


def test_digest_stable():
    kwargs = dict(authorization_ref="authz-handoff-01", now=789)
    first = assemble(_session(), _data(), ["V-001"], "none", **kwargs)
    second = assemble(_session(), _data(), ["V-001"], "none", **kwargs)
    assert first.status == GateStatus.COMPLETED == second.status
    assert first.digest == second.digest
    assert first.envelope is not None and second.envelope is not None
    assert first.envelope.to_canonical_json() == second.envelope.to_canonical_json()


def test_bound_authorization_ref_survives_scrub():
    res = assemble(
        _session(),
        _data(),
        ["V-001"],
        "none",
        authorization_ref="authz-handoff-01",
        now=123,
    )
    assert res.status == GateStatus.COMPLETED
    assert res.envelope is not None
    (link,) = res.envelope.handoff.provenance
    assert link.authorization_ref == "authz-handoff-01"


def test_attacker_secret_value_still_redacted_through_gate():
    evil = "authz-evil-attacker-minted-token"
    res = assemble(
        _session(),
        _data(client_secret=evil),
        ["V-001"],
        "none",
        authorization_ref="authz-handoff-01",
        now=123,
    )
    assert res.status == GateStatus.COMPLETED
    assert res.envelope is not None
    payload = res.envelope.to_dict()
    assert evil not in str(payload)
    assert any(r.startswith("secret:") for r in res.removed)
    # ... while the bound ref itself is preserved.
    (link,) = res.envelope.handoff.provenance
    assert link.authorization_ref == "authz-handoff-01"
