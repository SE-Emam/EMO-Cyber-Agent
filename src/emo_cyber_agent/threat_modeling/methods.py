"""Threat methodology abstraction — POST-RC-009.

Methods are elicitation lenses, never authorities. STRIDE,
ATTACK_TREE, and DATA_CENTRIC ship officially; LINDDUN, PASTA,
CAPEC/MITRE-oriented, and custom methods register through the
same contract. Core never assumes method == STRIDE.
"""

from __future__ import annotations


from emo_cyber_agent.threat_modeling.errors import ThreatModelError, ThreatModelErrorCode
from emo_cyber_agent.threat_modeling.spec import ThreatMethod, ThreatRule

_METHODS: dict[str, ThreatMethod] = {}
_RULES: dict[str, list[ThreatRule]] = {}


def register_method(method: ThreatMethod, rules: tuple[ThreatRule, ...] = ()) -> None:
    if method.method_id in _METHODS:
        raise ThreatModelError(ThreatModelErrorCode.INVALID, f"duplicate threat method: {method.method_id}")
    _METHODS[method.method_id] = method
    _RULES[method.method_id] = list(rules)


def get_method(method_id: str) -> ThreatMethod:
    try:
        return _METHODS[method_id]
    except KeyError:
        raise ThreatModelError(ThreatModelErrorCode.METHOD_UNKNOWN, f"unknown threat method: {method_id}") from None


def rules_for(method_id: str) -> list[ThreatRule]:
    get_method(method_id)
    return list(_RULES.get(method_id, []))


def registered_methods() -> list[str]:
    return sorted(_METHODS)


def _bootstrap() -> None:
    if _METHODS:
        return
    register_method(
        ThreatMethod(method_id="stride", name="STRIDE", version="1.0.0", categories=("SPOOFING", "TAMPERING", "REPUDIATION", "INFORMATION_DISCLOSURE", "DENIAL_OF_SERVICE", "ELEVATION_OF_PRIVILEGE"), description="Systematic per-element prompts over components, flows, and boundaries.", provenance={"source": "official"}),
        (
            ThreatRule(rule_id="stride-spoofing-entry", method="stride", category="SPOOFING", subject_kind="entry", description="Unauthenticated entry may admit spoofed identity."),
            ThreatRule(rule_id="stride-tampering-state", method="stride", category="TAMPERING", subject_kind="entry", description="State-changing entry may admit unauthorized modification."),
            ThreatRule(rule_id="stride-repudiation-action", method="stride", category="REPUDIATION", subject_kind="entry", description="Security-relevant action may lack audit trail."),
            ThreatRule(rule_id="stride-disclosure-flow", method="stride", category="INFORMATION_DISCLOSURE", subject_kind="flow", description="Data flow may expose sensitive data across a boundary."),
            ThreatRule(rule_id="stride-dos-entry", method="stride", category="DENIAL_OF_SERVICE", subject_kind="entry", description="Public entry may admit resource exhaustion."),
            ThreatRule(rule_id="stride-elevation-admin", method="stride", category="ELEVATION_OF_PRIVILEGE", subject_kind="entry", description="Privileged surface may admit boundary crossing."),
        ),
    )
    register_method(
        ThreatMethod(method_id="attack-tree", name="Attack Tree", version="1.0.0", categories=("GOAL_DECOMPOSITION",), description="Goal-rooted decomposition into sub-goals and preconditions.", provenance={"source": "official"}),
        (ThreatRule(rule_id="attack-tree-entry-goal", method="attack-tree", category="GOAL_DECOMPOSITION", subject_kind="entry", description="Entry reachable goal decomposed into entry, action, and objective."),),
    )
    register_method(
        ThreatMethod(method_id="data-centric", name="Data Centric", version="1.0.0", categories=("DATA_FLOW_RISK",), description="Data-first tracing from sources through stores to exits.", provenance={"source": "official"}),
        (ThreatRule(rule_id="data-centric-source-sink", method="data-centric", category="DATA_FLOW_RISK", subject_kind="flow", description="Source-to-sink path traced for exposure and modification hypotheses."),),
    )


_bootstrap()
