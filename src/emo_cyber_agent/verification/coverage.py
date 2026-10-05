"""Verification coverage — POST-RC-012.

Honest coverage: controls are declared or explicitly absent, and
absent controls cap what coverage may claim. Coverage never
becomes a verdict — the strongest thing it can produce is a label
plus limitations.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

COVERAGE_STATES: tuple[str, ...] = ("COMPLETE", "PARTIAL", "LIMITED", "UNKNOWN")
CONTROL_STATES: tuple[str, ...] = ("PRESENT", "ABSENT", "NOT_APPLICABLE")

# Coverage can never assert more than this. Verdicts do not exist here.
CONCLUSION_CEILING = "context-only"


class VerificationControls(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    positive_control: str = Field(default="NOT_APPLICABLE", max_length=24)
    negative_control: str = Field(default="NOT_APPLICABLE", max_length=24)
    rationale: str = Field(default="", max_length=300)

    @field_validator("positive_control", "negative_control")
    @classmethod
    def _state(cls, v: str) -> str:
        if v not in CONTROL_STATES:
            raise ValueError(f"control state not allowed: {v}")
        return v


class CoverageAssessment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    coverage: str
    controls: VerificationControls
    limitations: tuple[str, ...] = ()
    conclusion_ceiling: str = CONCLUSION_CEILING
    digest: str = Field(default="", max_length=128)

    @field_validator("coverage")
    @classmethod
    def _coverage(cls, v: str) -> str:
        if v not in COVERAGE_STATES:
            raise ValueError(f"coverage not allowed: {v}")
        return v

    @field_validator("conclusion_ceiling")
    @classmethod
    def _ceiling(cls, v: str) -> str:
        if v != CONCLUSION_CEILING:
            raise ValueError("coverage may never raise the conclusion ceiling")
        return v

    def model_post_init(self, __context: Any, /) -> None:
        from emo_cyber_agent.threat_modeling.spec import canonical_digest

        if not self.digest:
            object.__setattr__(self, "digest", canonical_digest(self.model_dump(mode="json", exclude={"digest"})))


def assess_coverage(
    *,
    oracle_outcome: str,
    controls: VerificationControls | None = None,
    operational_result: str = "OK",
    response_coverage: str = "complete",
    limitations: tuple[str, ...] = (),
) -> CoverageAssessment:
    """Coverage is computed from what was actually observed: an
    operational failure or missing controls can only lower it."""
    controls = controls or VerificationControls()
    notes = list(limitations)
    if operational_result != "OK":
        notes.append(f"operational-result:{operational_result.lower()}")
        coverage = "LIMITED"
    elif oracle_outcome == "INCONCLUSIVE":
        coverage = "PARTIAL" if response_coverage == "complete" else "LIMITED"
        notes.append("oracle-inconclusive")
    elif response_coverage != "complete":
        coverage = "PARTIAL"
        notes.append(f"provider-coverage:{response_coverage}")
    else:
        coverage = "COMPLETE"
    if controls.positive_control == "ABSENT" or controls.negative_control == "ABSENT":
        if coverage == "COMPLETE":
            coverage = "LIMITED"
        notes.append("control-missing:conclusion-capped")
    if "control-missing:conclusion-capped" not in notes and controls.positive_control == "NOT_APPLICABLE" and controls.negative_control == "NOT_APPLICABLE":
        if coverage == "COMPLETE":
            coverage = "PARTIAL"
        notes.append("controls-not-applicable")
    return CoverageAssessment(
        coverage=coverage,
        controls=controls,
        limitations=tuple(dict.fromkeys(notes)),
        conclusion_ceiling=CONCLUSION_CEILING,
    )
