"""Evaluation cases — POST-RC-013.

A case is a self-contained evaluation unit: a scenario the system under test
executes, plus evaluation-only ground truth. The blind projection
(``blind_case``) carries everything the system may see and nothing it may
not: no expected values, no labels, no verdicts.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.ground_truth import GroundTruthRecord, judge_or_reject
from emo_cyber_agent.evaluation.spec import (
    CaseSplit,
    CaseVisibility,
    EvaluationStage,
    EvaluationTaxonomy,
    EvaluationTrack,
    evaluation_digest,
)

__all__ = [
    "CaseSource",
    "EvaluationScenario",
    "EvaluationCase",
    "BlindEvaluationCase",
    "SPLIT_VISIBILITIES",
    "blind_case",
    "normalize_case",
    "case_sections",
]

_CASE_ID = r"^[a-z0-9][a-z0-9._-]{1,95}$"
SPLIT_VISIBILITIES: dict[str, frozenset[str]] = {
    CaseSplit.DEVELOPMENT.value: frozenset(v.value for v in CaseVisibility),
    CaseSplit.VALIDATION.value: frozenset(v.value for v in CaseVisibility),
    CaseSplit.HOLDOUT.value: frozenset({CaseVisibility.HOLDOUT.value, CaseVisibility.BLIND.value}),
}


class CaseSource(BaseModel):
    """Where the fixture came from. Production sources are refused by
    mutations and by the dataset loader."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    system: str = Field(..., min_length=1, max_length=64)
    fixture: str = Field(default="", max_length=128)
    production: bool = False


class EvaluationScenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(..., min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _slug(cls, v: str) -> str:
        kind = v.strip().lower()
        if not kind or any(ch for ch in kind if not (ch.isalnum() or ch in "_-")):
            raise ValueError("scenario kind must be a slug")
        return kind


class BlindEvaluationCase(BaseModel):
    """What the system under test is allowed to see."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(..., pattern=_CASE_ID)
    title: str = Field(..., min_length=1, max_length=200)
    track: EvaluationTrack
    taxonomy: EvaluationTaxonomy
    stage: EvaluationStage
    visibility: CaseVisibility = CaseVisibility.PUBLIC
    split: CaseSplit = CaseSplit.DEVELOPMENT
    tags: tuple[str, ...] = Field(default_factory=tuple, max_length=24)
    scenario: EvaluationScenario
    section: str = Field(default="", max_length=64)

    @field_validator("tags")
    @classmethod
    def _tag_shape(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(t.strip().lower() for t in v if t and t.strip())
        for tag in cleaned:
            if len(tag) > 48:
                raise ValueError("tag too long")
        return tuple(dict.fromkeys(cleaned))


class EvaluationCase(BlindEvaluationCase):
    """Blind projection + evaluation-only ground truth."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ground_truth: tuple[GroundTruthRecord, ...] = Field(default_factory=tuple, max_length=64)
    source: CaseSource = Field(default_factory=lambda: CaseSource(system="internal", fixture="inline"))
    notes: str = Field(default="", max_length=1000)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        payload = dict(data)
        split = str(payload.get("split", CaseSplit.DEVELOPMENT.value))
        visibility = str(payload.get("visibility", CaseVisibility.PUBLIC.value))
        if split == CaseSplit.HOLDOUT.value and visibility not in (
            CaseVisibility.HOLDOUT.value,
            CaseVisibility.BLIND.value,
        ):
            raise ValueError("holdout split requires holdout or blind visibility")
        raw = payload.get("ground_truth") or ()
        records = [
            entry if isinstance(entry, GroundTruthRecord) else GroundTruthRecord(**entry)
            for entry in raw
        ]
        payload["ground_truth"] = [r.model_dump() for r in judge_or_reject(records)]
        return payload

    @property
    def identity_digest(self) -> str:
        return evaluation_digest(
            {
                "case_id": self.case_id,
                "track": self.track.value,
                "taxonomy": self.taxonomy.value,
                "stage": self.stage.value,
                "split": self.split.value,
                "visibility": self.visibility.value,
                "scenario": self.scenario.model_dump(mode="json"),
                "ground_truth": [r.model_dump(mode="json") for r in self.ground_truth],
            }
        )

    def blind(self) -> BlindEvaluationCase:
        return BlindEvaluationCase(
            **{
                field: getattr(self, field)
                for field in BlindEvaluationCase.model_fields
            }
        )

    def with_ground_truth(self, records: Iterable[GroundTruthRecord]) -> EvaluationCase:
        return EvaluationCase(
            **{
                **self.model_dump(exclude={"ground_truth"}),
                "ground_truth": tuple(records),
            }
        )


def blind_case(case: EvaluationCase | Mapping[str, Any]) -> BlindEvaluationCase:
    """Project a case (or a raw mapping) onto the blind shape.

    A mapping that still carries ground truth is rejected outright: the
    blind projection must never leak expected values."""
    if isinstance(case, EvaluationCase):
        return case.blind()
    if isinstance(case, BlindEvaluationCase):
        return case
    data = dict(case)
    leaked = [key for key in ("ground_truth", "expected", "label", "verdict") if key in data]
    if leaked:
        raise EvaluationError(
            EvaluationErrorCode.BLIND_ACCESS_DENIED,
            f"blind projection refuses ground-truth fields: {', '.join(leaked)}",
        )
    return BlindEvaluationCase(**{k: v for k, v in data.items() if k in BlindEvaluationCase.model_fields})


def normalize_case(payload: Mapping[str, Any]) -> EvaluationCase:
    data = dict(payload)
    data.setdefault("source", {"system": "internal", "fixture": ""})
    data["scenario"] = dict(data.get("scenario") or {})
    try:
        return EvaluationCase(**data)
    except EvaluationError:
        raise
    except Exception as exc:
        raise EvaluationError(
            EvaluationErrorCode.INVALID_CASE,
            f"invalid case {data.get('case_id', '?')}: {exc}",
        ) from exc


def case_sections(cases: Iterable[EvaluationCase]) -> tuple[str, ...]:
    return tuple(sorted({c.section for c in cases if c.section}))
