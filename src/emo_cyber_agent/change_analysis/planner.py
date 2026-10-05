"""Re-analysis planning — POST-RC-008.

ChangeSet → impact → skill/pack/task selection → verification
handoffs. Planning ONLY: no execution, no policy calls, no authority
expansion. Task/Playbook constraints and PolicyEngine remain the
sole downstream authorities.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.change_analysis.spec import ChangeReviewPlan, ChangeSet, SecurityImpact, VerificationHandoff, canonical_digest

# Deterministic domain → task mapping (real task ids from POST-RC-002).
DOMAIN_TASKS: dict[str, tuple[str, ...]] = {
    "CODE_BEHAVIOR": ("deep-security-audit",),
    "AUTHORIZATION": ("authorization-review",),
    "AUTHENTICATION": ("authentication-review",),
    "INPUT_HANDLING": ("web-app-security", "api-security-review"),
    "OUTPUT_HANDLING": ("web-app-security",),
    "CRYPTO": ("deep-security-audit",),
    "SECRET_HANDLING": ("secret-audit",),
    "DEPENDENCY": ("dependency-audit", "supply-chain-review"),
    "CONFIGURATION": ("pre-release-security-review",),
    "NETWORK": ("api-security-review",),
    "FILE_ACCESS": ("deep-security-audit",),
    "DATABASE": ("database-security-review", "supabase-security-review"),
    "ROUTING": ("api-security-review",),
    "STATE_CHANGE": ("business-logic-review",),
    "INFRASTRUCTURE": ("cloud-security-review",),
}

# Deterministic domain → codeintel capabilities (unioned with pack needs).
DOMAIN_CODEINTEL: dict[str, tuple[str, ...]] = {
    "AUTHORIZATION": ("routes", "auth_boundaries", "call_graph"),
    "AUTHENTICATION": ("routes", "symbols"),
    "INPUT_HANDLING": ("dataflow", "taint", "symbols"),
    "OUTPUT_HANDLING": ("dataflow", "symbols"),
    "DATABASE": ("db_relationships", "dataflow"),
    "DEPENDENCY": ("dependencies",),
    "ROUTING": ("routes",),
    "STATE_CHANGE": ("routes", "call_graph"),
}

# Deterministic predicate → verification method handoff.
PREDICATE_METHODS: dict[str, str] = {
    "AUTH_BOUNDARY_CHANGED": "static_confirmation",
    "STATE_CHANGE_ADDED": "static_confirmation",
    "NEW_EXTERNAL_INPUT": "static_confirmation",
    "NEW_SINK": "static_confirmation",
    "NEW_TAINT_PATH": "static_confirmation",
    "TAINT_PATH_MODIFIED": "static_confirmation",
    "ROUTE_PERMISSION_CHANGED": "static_confirmation",
    "DEPENDENCY_VERSION_CHANGED": "static_confirmation",
    "SECRET_HANDLING_CHANGED": "static_confirmation",
    "FILE_ACCESS_CHANGED": "static_confirmation",
    "DATABASE_ACCESS_CHANGED": "read_only_query",
    "CONFIG_SECURITY_CHANGE": "configuration_confirmation",
}


def plan_review(
    changeset: ChangeSet,
    impact: SecurityImpact,
    predicates_fired: dict[str, list[str]],
    *,
    review_mode: str = "TARGETED_REVIEW",
    pack_registry: Any = None,
) -> ChangeReviewPlan:
    if review_mode not in ("FULL_REVIEW", "TARGETED_REVIEW", "REBASE_REVIEW"):
        from emo_cyber_agent.change_analysis.errors import ChangeError, ChangeErrorCode

        raise ChangeError(ChangeErrorCode.PLAN_INVALID, f"unknown review mode: {review_mode}")
    limitations = list(impact.limitations)
    targeted_packs: list[str] = []
    codeintel: list[str] = []
    if pack_registry is not None:
        try:
            for pack in sorted(pack_registry.list(), key=lambda p: p.pack_id):
                if set(pack.skills) & set(impact.affected_skills):
                    targeted_packs.append(pack.pack_id)
                    codeintel.extend(c for c in pack.required_code_intelligence if c not in codeintel)
        except Exception as e:
            limitations.append(f"pack-selection-unavailable: {e}")
    else:
        limitations.append("pack-selection-unavailable: no pack registry wired")
    for domain in impact.domains:
        codeintel.extend(c for c in DOMAIN_CODEINTEL.get(domain, ("symbols", "call_graph")) if c not in codeintel)
    tasks: list[str] = []
    for domain in impact.domains:
        tasks.extend(t for t in DOMAIN_TASKS.get(domain, ()) if t not in tasks)
    handoffs: list[VerificationHandoff] = []
    for index, predicate in enumerate(sorted(predicates_fired)):
        refs = predicates_fired[predicate]
        target = refs[0] if refs else "change-surface"
        handoffs.append(VerificationHandoff(
            handoff_id=f"handoff-{index + 1:03d}-{predicate.lower().replace('_', '-')}",
            target_snapshot_id=changeset.target_snapshot_id, method=PREDICATE_METHODS.get(predicate, "static_confirmation"),
            target=target, reason=f"predicate {predicate} fired on target snapshot",
            compatible_snapshots=(changeset.target_snapshot_id,),
        ))
    if review_mode == "FULL_REVIEW":
        coverage_statement = "full re-analysis requested: affected surface plus unchanged surroundings scheduled for review"
    elif review_mode == "REBASE_REVIEW":
        coverage_statement = "base moved: prior targeted results must be re-validated against the new target snapshot before reuse"
    else:
        coverage_statement = (
            "targeted coverage is complete iff the affected surface is fully reviewed; "
            "reviewing all changed files does not imply project-wide security properties are covered"
        )
    limitations.append("planning-only: Task/Playbook constraints and PolicyEngine remain the sole downstream authorities; this plan never expands audit authority")
    if impact.affected and not (targeted_packs or tasks):
        limitations.append("no actionable targets resolved: full review recommended")
    payload = {
        "audit": changeset.audit_id, "mode": review_mode,
        "skills": sorted(impact.affected_skills), "packs": sorted(targeted_packs), "tasks": sorted(tasks),
        "codeintel": sorted(codeintel), "tools": sorted(impact.affected_tools),
        "handoffs": [[h.handoff_id, h.method, h.target] for h in handoffs],
        "digest": changeset.change_digest,
    }
    return ChangeReviewPlan(
        plan_id=f"plan-{changeset.change_digest[:12]}", audit_id=changeset.audit_id, review_mode=review_mode,
        targeted_skills=tuple(impact.affected_skills), targeted_packs=tuple(sorted(targeted_packs)),
        targeted_tasks=tuple(sorted(tasks)), required_codeintel_capabilities=tuple(sorted(codeintel)),
        required_tools=tuple(impact.affected_tools),
        required_evidence=("change-diff-record", "provenance-record", "surface-record"),
        verification_handoffs=tuple(handoffs), coverage_statement=coverage_statement,
        limitations=tuple(limitations), plan_digest=canonical_digest(payload),
    )
