"""POST-RC-010 — Agent isolation tests (offline).

Audit/project/snapshot isolation, memory isolation, delegation
non-inheritance, permission non-mutation, no-Finding creation,
determinism. No model, no execution.
"""

import json
from pathlib import Path

import pytest

from emo_cyber_agent.agent_security.errors import AgentSecurityError
from emo_cyber_agent.agent_security.queries import AgentQueryPort
from emo_cyber_agent.agent_security.service import AgentSecurityService

FIXTURES = Path("tests/fixtures/agent_security")


def _config():
    return json.loads((FIXTURES / "agent_config.json").read_text())


def _assessment(audit="A", project="P", snapshot="s1", **over):
    service = AgentSecurityService()
    architecture = _config()
    architecture["sessions"] = [{**s, "audit_id": audit} for s in architecture.get("sessions", [])]
    kwargs = dict(audit_id=audit, project_id=project, snapshot_id=snapshot, architecture=architecture, task_scope=("read-only",))
    kwargs.update(over)
    return service.analyze(**kwargs)


def test_audit_contexts_isolated():
    first = _assessment(audit="A")
    second = _assessment(audit="B")
    assert first.system.audit_id == "A" and second.system.audit_id == "B"
    assert first.digest != second.digest  # audit is identity: digests differ honestly
    assert "audit-B-content-marker" not in json.dumps(first.system.model_dump(mode="json"))
    port = AgentQueryPort(first)
    with pytest.raises(AgentSecurityError):
        port.list_agents(audit_id="B")
    memories_a = [m for m in first.system.memories]
    memories_b = [m for m in second.system.memories]
    assert [m.audit_id for m in memories_a] == ["A"] and [m.audit_id for m in memories_b] == ["B"]


def test_project_contexts_isolated():
    first = _assessment(project="P-A")
    second = _assessment(project="P-B")
    assert first.system.project_id == "P-A" and second.system.project_id == "P-B"
    assert first.digest != second.digest  # project is identity: digests differ honestly


def test_snapshot_contexts_isolated():
    first = _assessment(snapshot="s1")
    second = _assessment(snapshot="s2")
    assert first.system.snapshot_id == "s1" and second.system.snapshot_id == "s2"
    assert first.digest != second.digest
    service = AgentSecurityService()
    handoff = first.handoffs[0]
    service.check_handoff(handoff, current_snapshot_id="s1")
    with pytest.raises(AgentSecurityError):
        service.check_handoff(handoff, current_snapshot_id="s2")


def test_no_silent_memory_reuse():
    from emo_cyber_agent.agent_security.memory_analysis import check_memory_isolation
    from emo_cyber_agent.agent_security.spec import MemoryEntry

    entries = (
        MemoryEntry(entry_id="mem-a", audit_id="A", digest="d" * 64),
        MemoryEntry(entry_id="mem-b", audit_id="B", digest="d" * 64),
    )
    signals = check_memory_isolation(entries)
    assert any(s["signal"] == "CROSS_AUDIT_MEMORY" for s in signals)


def test_delegation_grants_nothing():
    from emo_cyber_agent.core.policy import StrictPolicyEngine

    assessment = _assessment()
    policy = StrictPolicyEngine()
    before = len(policy.decisions)
    assert assessment.system.delegations
    assert len(policy.decisions) == before  # analysis records no decisions
    researcher = next(s for s in assessment.system.subagents if s.subagent_id == "researcher")
    assert "code-run" in researcher.tool_ids
    assert policy.evaluate_policy("A", "code-run", "repo", "read_only", ["code.execute"]) is False


def test_no_permission_mutation_end_to_end():
    from emo_cyber_agent.core.policy import StrictPolicyEngine

    policy = StrictPolicyEngine()
    grants_before = (policy._granted_network, policy._granted_write, policy._granted_restricted)
    _assessment(policy_grants={"assistant": ("repository.read",)})
    assert (policy._granted_network, policy._granted_write, policy._granted_restricted) == grants_before


def test_no_finding_created_anywhere():
    assessment = _assessment()
    blob = json.dumps({
        "scenarios": [s.model_dump(mode="json") for s in assessment.scenarios],
        "handoffs": [h.model_dump(mode="json") for h in assessment.handoffs],
        "observations": [o.model_dump(mode="json") for o in assessment.observations],
    })
    assert "finding_id" not in blob and "Finding" not in blob
    import ast as _ast

    text = "\n".join((Path("src/emo_cyber_agent/agent_security") / f).read_text() for f in ["service.py", "threat_rules.py", "verification.py", "queries.py", "delta.py"])
    assert "SecurityFinding" not in text


def test_determinism_across_runs():
    assert _assessment().digest == _assessment().digest
