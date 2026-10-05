"""Verification handoffs — POST-RC-010.

Snapshot/target/evidence-bound handoffs for the VerificationService.
Passive by default, policy-gated downstream, never executed here.
Stale snapshots are rejected, never reused.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.agent_security.errors import AgentSecurityError, AgentSecurityErrorCode
from emo_cyber_agent.agent_security.spec import AgentVerificationHandoff, assert_no_authority_language

CATEGORY_HANDOFFS: dict[str, dict[str, str]] = {
    "PROMPT_INJECTION": {"method": "static_confirmation", "success": "record showing untrusted content cannot alter tool selection", "refutation": "record showing untrusted content alters tool selection"},
    "TOOL_POISONING": {"method": "static_confirmation", "success": "record showing description/output integrity boundary holds", "refutation": "record showing poisoned content steers behavior"},
    "SCOPE_CREEP": {"method": "static_confirmation", "success": "record showing effective capability remains bounded", "refutation": "record showing effective capability exceeds declared scope"},
    "CREDENTIAL_EXPOSURE": {"method": "static_confirmation", "success": "record showing secret cannot reach model/tool/log boundary", "refutation": "record showing secret crossing observed"},
    "INSECURE_DELEGATION": {"method": "static_confirmation", "success": "record showing child scope within parent delegated scope", "refutation": "record showing child scope exceeding delegation"},
}


def build_handoff(
    *,
    handoff_id: str,
    scenario_id: str,
    snapshot_id: str,
    target: str = "",
    category: str = "",
    required_evidence: tuple[str, ...] = (),
    verification_method: str = "static_confirmation",
    safety_level: str = "passive",
) -> AgentVerificationHandoff:
    preset = CATEGORY_HANDOFFS.get(category, {})
    method = preset.get("method", verification_method)
    success = preset.get("success", f"supporting record collected for {scenario_id}")[:500]
    refutation = preset.get("refutation", f"contradicting record collected for {scenario_id}")[:500]
    assert_no_authority_language(success, refutation)
    return AgentVerificationHandoff(
        handoff_id=handoff_id, threat_scenario_id=scenario_id, target_snapshot_id=snapshot_id,
        target_component=target, required_evidence=tuple(required_evidence),
        verification_method=method, safety_level=safety_level,
        success_criteria=success, refutation_criteria=refutation,
        compatible_snapshots=(snapshot_id,),
    )


def check_handoff(handoff: AgentVerificationHandoff, *, current_snapshot_id: str) -> None:
    if current_snapshot_id != handoff.target_snapshot_id and current_snapshot_id not in handoff.compatible_snapshots:
        raise AgentSecurityError(AgentSecurityErrorCode.VERIFICATION_STALE, f"handoff {handoff.handoff_id} not compatible with snapshot {current_snapshot_id}")


def handoffs_for_scenarios(scenarios: tuple[Any, ...], *, snapshot_id: str) -> list[AgentVerificationHandoff]:
    handoffs: list[AgentVerificationHandoff] = []
    for index, scenario in enumerate(sorted(scenarios, key=lambda s: s.scenario_id)):
        handoffs.append(build_handoff(
            handoff_id=f"agent-handoff-{index + 1:03d}", scenario_id=scenario.scenario_id,
            snapshot_id=snapshot_id, target=scenario.target or scenario.source,
            category=scenario.category, required_evidence=tuple(scenario.verification_requirements),
        ))
    return handoffs
