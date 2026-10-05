"""Knowledge comparator — POST-RC-011.

Closed comparison outcomes with reason codes. The comparator
creates no Findings and mutates no lifecycle state.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.security_knowledge.spec import RegressionComparison


class KnowledgeComparator:
    def compare(
        self,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
        *,
        comparable: bool = True,
        coverage: str = "complete",
        evidence_ids: tuple[str, ...] = (),
    ) -> RegressionComparison:
        if not comparable:
            return RegressionComparison(result="INCOMPATIBLE", reason_codes=("not-comparable",), evidence_ids=tuple(evidence_ids), coverage=coverage, limitations=("comparison contract refused",))
        if before is None and after is None:
            return RegressionComparison(result="INDETERMINATE", reason_codes=("both-absent",), evidence_ids=tuple(evidence_ids), coverage=coverage, limitations=("nothing to compare",))
        if before is None:
            return RegressionComparison(result="NEW", reason_codes=("absent-before",), evidence_ids=tuple(evidence_ids), coverage=coverage)
        if after is None:
            result = "MISSING" if coverage == "complete" else "INDETERMINATE"
            return RegressionComparison(
                result=result, reason_codes=("absent-after",), evidence_ids=tuple(evidence_ids),
                coverage=coverage, limitations=() if result == "MISSING" else ("target coverage incomplete: absence is not disappearance",),
            )
        if before == after:
            return RegressionComparison(result="IDENTICAL", reason_codes=("digests-equal",), evidence_ids=tuple(evidence_ids), coverage=coverage)
        return RegressionComparison(result="CHANGED", reason_codes=("digests-differ",), evidence_ids=tuple(evidence_ids), coverage=coverage)
