"""Security pack resolver — POST-RC-006 (deterministic, no LLM).

Pack + provider capabilities → coverage plan. Task → skills → packs →
codeintel → evidence/verification handoff. Resolution only: grants
nothing, executes nothing, confirms nothing.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.skills.packs.pack import (
    CheckCoverage,
    PackReportView,
    PackResolution,
    ResolvedCheck,
    ResolvedPack,
    SecuritySkillPack,
)


class PackResolver:
    """Deterministic pack → coverage resolution against provider capabilities."""

    def resolve(self, pack: SecuritySkillPack, *, provider_capabilities: tuple[str, ...] = ()) -> ResolvedPack:
        available = set(provider_capabilities)
        reasons: list[str] = []
        warnings: list[str] = []
        resolved_checks: list[ResolvedCheck] = []
        evidence: list[str] = list(pack.required_evidence)
        verification: list[str] = list(pack.required_verification)
        limitations: list[str] = list(pack.limitations)
        gaps: list[str] = []
        hypotheses: list[str] = []
        for check in pack.checks:
            needs = set(check.codeintel_needs)
            missing = sorted(needs - available)
            if not needs or not missing:
                coverage = CheckCoverage.COVERED
                reasons.append(f"check:{check.check_id} covered")
            elif set(needs) & available:
                coverage = CheckCoverage.PARTIAL
                gap = f"partial:{check.check_id} missing={','.join(missing)}"
                gaps.append(gap)
                limitations.append(f"{check.check_id}: proceed only on provable subset; missing {', '.join(missing)} recorded as coverage gap")
                warnings.append(gap)
            else:
                coverage = CheckCoverage.UNAVAILABLE
                gap = f"unavailable:{check.check_id} missing={','.join(missing)}"
                gaps.append(gap)
                limitations.append(f"{check.check_id}: no result invented; requires {', '.join(missing)}")
                warnings.append(gap)
            for item in (*check.evidence_required, *check.evidence_sufficient):
                if item not in evidence:
                    evidence.append(item)
            for method in check.verification_required:
                if method not in verification:
                    verification.append(method)
            hypothesis = f"[UNVERIFIED HYPOTHESIS] {check.hypothesis_template}" if check.hypothesis_template else ""
            if hypothesis and hypothesis not in hypotheses:
                hypotheses.append(hypothesis)
            resolved_checks.append(ResolvedCheck(check_id=check.check_id, title=check.title, coverage=coverage, missing_capabilities=tuple(missing), evidence_required=tuple(check.evidence_required), verification_required=tuple(check.verification_required), hypothesis=hypothesis))
        status = "resolved" if not gaps else ("partial" if any(c.coverage == CheckCoverage.COVERED for c in resolved_checks) else "limited")
        return ResolvedPack(
            pack_id=pack.pack_id, pack_version=pack.version, pack_digest=SecuritySkillPack.digest_of(pack), status=status,
            checks=tuple(resolved_checks), evidence_plan=tuple(sorted(set(evidence))), verification_plan=tuple(sorted(set(verification))),
            limitations=tuple(limitations), coverage_gaps=tuple(gaps), hypotheses=tuple(hypotheses), reasons=tuple(reasons), warnings=tuple(warnings),
        )

    def resolve_for_task(self, task_spec: Any, *, files: list[str], objective: str = "", skill_registry: Any = None, pack_registry: Any = None, provider_capabilities: tuple[str, ...] = ()) -> PackResolution:
        """Task → SkillResolver matches → packs by skill index → coverage."""
        from emo_cyber_agent.skills.resolver import SkillResolver

        reasons: list[str] = []
        warnings: list[str] = []
        matched: list[str] = []
        if skill_registry is not None:
            for hit in SkillResolver(skill_registry).resolve(files=files, objective=objective):
                matched.append(hit["skill_id"])
            reasons.append(f"skills:{','.join(sorted(matched)) or 'none'}")
        else:
            warnings.append("skills-unverified:no-registry")
        resolved_packs: list[ResolvedPack] = []
        if pack_registry is not None:
            for pack in sorted(pack_registry.list(), key=lambda p: p.pack_id):
                if set(pack.skills) & set(matched):
                    resolved_packs.append(self.resolve(pack, provider_capabilities=provider_capabilities))
                    reasons.append(f"pack:{pack.pack_id} via skills {sorted(set(pack.skills) & set(matched))}")
        else:
            warnings.append("packs-unverified:no-registry")
        evidence: list[str] = []
        verification: list[str] = []
        hypotheses: list[str] = []
        limitations: list[str] = []
        codeintel: list[str] = []
        for rp in resolved_packs:
            evidence.extend(e for e in rp.evidence_plan if e not in evidence)
            verification.extend(m for m in rp.verification_plan if m not in verification)
            hypotheses.extend(h for h in rp.hypotheses if h not in hypotheses)
            limitations.extend(lim for lim in rp.limitations if lim not in limitations)
        if pack_registry is not None:
            for rp in resolved_packs:
                try:
                    pack = pack_registry.get(rp.pack_id)
                    codeintel.extend(c for c in pack.required_code_intelligence if c not in codeintel)
                except Exception:
                    continue
        task_id = str(getattr(task_spec, "task_id", "") or "")
        payload = {"task": task_id, "skills": sorted(matched), "packs": [[p.pack_id, p.pack_version, p.status] for p in resolved_packs], "caps": sorted(provider_capabilities)}
        return PackResolution(
            task_id=task_id, skills=tuple(sorted(matched)), packs=tuple(resolved_packs), required_codeintel=tuple(sorted(codeintel)),
            evidence_requirements=tuple(sorted(set(evidence))), verification_requirements=tuple(sorted(set(verification))),
            hypotheses=tuple(hypotheses), limitations=tuple(limitations), digest=PackResolution.digest_of(payload),
            reasons=tuple(reasons), warnings=tuple(warnings),
        )


def report_view(resolved: ResolvedPack, *, security_domain: str = "", provenance: dict[str, Any] | None = None) -> PackReportView:
    """Projection-only metadata for report templates. No findings, no verdicts."""
    performed = tuple(c.check_id for c in resolved.checks if c.coverage != CheckCoverage.UNAVAILABLE)
    codeintel_coverage = tuple(sorted({f"{c.check_id}={c.coverage.value}" for c in resolved.checks}))
    return PackReportView(
        pack_id=resolved.pack_id, pack_version=resolved.pack_version, pack_digest=resolved.pack_digest,
        security_domain=security_domain, checks_performed=performed,
        evidence_coverage=tuple(resolved.evidence_plan), codeintel_coverage=codeintel_coverage,
        verification_status="REQUIRED" if resolved.verification_plan else "NONE-DECLARED",
        limitations=tuple(resolved.limitations), unverified_hypotheses=tuple(resolved.hypotheses),
        provenance=dict(provenance or {}),
    )
