"""Threat scenario builder — POST-RC-009.

Structured hypothesis records from elicitation candidates. A
scenario is an analysis object, never a finding: status starts at
HYPOTHESIZED (or UNASSESSED), rises to SUPPORTED_BY_EVIDENCE only
with attached evidence, and can never become a vulnerability
verdict inside this layer.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.threat_modeling.spec import (
    ThreatHypothesis,
    ThreatScenario,
    assert_no_threat_verdicts,
    canonical_digest,
    stable_id,
)


def _slug(text: str) -> str:
    import re as _re

    slug = _re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:80] or "unnamed"


def build_threat_scenarios(
    candidates: list[dict[str, Any]],
    *,
    evidence_index: dict[str, tuple[str, ...]] | None = None,
    possible_controls: dict[str, tuple[str, ...]] | None = None,
) -> tuple[list[ThreatScenario], list[ThreatHypothesis]]:
    evidence_index = evidence_index or {}
    possible_controls = possible_controls or {}
    scenarios: list[ThreatScenario] = []
    hypotheses: list[ThreatHypothesis] = []
    seen: set[str] = set()
    for candidate in sorted(candidates, key=lambda c: (c.get("method", ""), c.get("category", ""), c.get("subject", ""))):
        method = str(candidate.get("method", "stride"))
        category = str(candidate.get("category", "UNKNOWN"))
        subject = str(candidate.get("subject", ""))
        scenario_id = stable_id("threat", method, category, subject)
        if scenario_id in seen:
            continue
        seen.add(scenario_id)
        evidence = tuple(evidence_index.get(subject, ()))
        status = "SUPPORTED_BY_EVIDENCE" if evidence else "HYPOTHESIZED"
        goal = str(candidate.get("attack_goal", ""))
        assert_no_threat_verdicts(goal, subject, category)
        scenarios.append(ThreatScenario(
            scenario_id=scenario_id, method=method, category=category, subject=subject,
            preconditions=tuple(candidate.get("preconditions", ())), attack_goal=goal,
            evidence_ids=evidence, hypothesis_status=status,
            verification_requirements=tuple(candidate.get("required_evidence", ())),
            possible_controls=tuple(possible_controls.get(category, ())),
            coverage="PARTIALLY_MAPPED" if evidence else "UNKNOWN",
            limitations=tuple(candidate.get("limitations", ())),
        ))
        hypotheses.append(ThreatHypothesis(
            hypothesis_id=f"hypothesis-{canonical_digest({'scenario': scenario_id})[:16]}",
            statement=f"Hypothesis ({method}/{category}): {goal} via {subject or 'unknown subject'}"[:1000],
            scenario_id=scenario_id, status=status,
        ))
    return scenarios, hypotheses
