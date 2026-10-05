"""Datasets, blind delivery, and contamination control — POST-RC-013.

A dataset is a directory: one ``dataset.json`` manifest plus one section
directory per fixture family, each holding case documents. Loading is strict
(duplicate ids, production sources, empty corpora and out-of-visibility
cases are refused), fingerprinted, and deterministic.

Ground truth is delivered only through :class:`BlindDatasetProvider`, and
only after a case has actually been executed: a runner that reads expected
values before invoking the system under test is denied with
``EVALUATION_BLIND_ACCESS_DENIED``.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.evaluation.cases import (
    BlindEvaluationCase,
    EvaluationCase,
    SPLIT_VISIBILITIES,
    normalize_case,
)
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.ground_truth import GroundTruthRecord
from emo_cyber_agent.evaluation.spec import CaseSplit, evaluation_digest

__all__ = [
    "DatasetManifest",
    "EvaluationDataset",
    "ContaminationHit",
    "ContaminationReport",
    "BlindDatasetProvider",
    "load_dataset",
    "build_dataset",
    "contamination_scan",
    "collect_forbidden_identifiers",
]

MANIFEST_NAME = "dataset.json"
_DEFAULT_SPLITS = tuple(s.value for s in CaseSplit)


class DatasetManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    name: str = Field(..., min_length=1, max_length=120)
    version: str = Field(default="0.1.0", min_length=1, max_length=32)
    description: str = Field(default="", max_length=500)
    split: CaseSplit = CaseSplit.DEVELOPMENT
    sections: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    thresholds: dict[str, float] = Field(default_factory=dict)
    required_metrics: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    required_gates: tuple[str, ...] = Field(
        default=("security_gate", "correctness_gate", "regression_gate"),
        max_length=8,
    )
    case_count: int = Field(default=0, ge=0)
    baseline: dict[str, float] = Field(default_factory=dict)
    production: bool = False
    license: str = Field(default="", max_length=120)

    @field_validator("thresholds")
    @classmethod
    def _threshold_range(cls, v: dict[str, float]) -> dict[str, float]:
        for name, value in v.items():
            if not name or not name.isupper():
                raise ValueError(f"threshold key must be an uppercase metric name: {name!r}")
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"threshold {name} must be within [0, 1]")
        return dict(sorted(v.items()))

    @field_validator("baseline")
    @classmethod
    def _baseline_range(cls, v: dict[str, float]) -> dict[str, float]:
        for name, value in v.items():
            if not name or not name.isupper():
                raise ValueError(f"baseline key must be an uppercase metric name: {name!r}")
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"baseline {name} must be within [0, 1]")
        return dict(sorted(v.items()))


class EvaluationDataset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest: DatasetManifest
    cases: tuple[EvaluationCase, ...]
    root: str = Field(default="", max_length=512)
    fingerprint: str = Field(default="", min_length=8, max_length=128)

    @field_validator("cases")
    @classmethod
    def _unique_ids(cls, cases: tuple[EvaluationCase, ...]) -> tuple[EvaluationCase, ...]:
        seen: set[str] = set()
        for case in cases:
            if case.case_id in seen:
                raise EvaluationError(
                    EvaluationErrorCode.INVALID_DATASET,
                    f"duplicate case id: {case.case_id}",
                )
            if case.source.production:
                raise EvaluationError(
                    EvaluationErrorCode.INVALID_DATASET,
                    f"production-sourced case refused: {case.case_id}",
                )
            seen.add(case.case_id)
        if not cases:
            raise EvaluationError(EvaluationErrorCode.DATASET_EMPTY, "dataset has no cases")
        return cases

    @property
    def dataset_id(self) -> str:
        return self.manifest.dataset_id

    @property
    def split(self) -> CaseSplit:
        return self.manifest.split

    def case(self, case_id: str) -> EvaluationCase:
        for case in self.cases:
            if case.case_id == case_id:
                return case
        raise EvaluationError(EvaluationErrorCode.CASE_NOT_FOUND, f"unknown case: {case_id}")

    def select(
        self,
        *,
        split: str | CaseSplit | None = None,
        tracks: Sequence[str] | None = None,
        stages: Sequence[str] | None = None,
        sections: Sequence[str] | None = None,
        case_ids: Sequence[str] | None = None,
    ) -> tuple[EvaluationCase, ...]:
        wanted_split = CaseSplit(split).value if split is not None else None
        wanted_tracks = {str(t) for t in tracks} if tracks else None
        wanted_stages = {str(s) for s in stages} if stages else None
        wanted_sections = {str(s) for s in sections} if sections else None
        wanted_ids = {str(c) for c in case_ids} if case_ids else None
        chosen: list[EvaluationCase] = []
        for case in self.cases:
            if wanted_split is not None and case.split.value != wanted_split:
                continue
            if wanted_tracks is not None and case.track.value not in wanted_tracks:
                continue
            if wanted_stages is not None and case.stage.value not in wanted_stages:
                continue
            if wanted_sections is not None and case.section not in wanted_sections:
                continue
            if wanted_ids is not None and case.case_id not in wanted_ids:
                continue
            chosen.append(case)
        return tuple(chosen)

    @property
    def sections(self) -> tuple[str, ...]:
        return tuple(sorted({c.section for c in self.cases if c.section}))

    def counts(self) -> dict[str, int]:
        by_track: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        by_split: dict[str, int] = {}
        for case in self.cases:
            by_track[case.track.value] = by_track.get(case.track.value, 0) + 1
            by_stage[case.stage.value] = by_stage.get(case.stage.value, 0) + 1
            by_split[case.split.value] = by_split.get(case.split.value, 0) + 1
        return {
            "cases": len(self.cases),
            "sections": len(self.sections),
            "tracks": len(by_track),
            "stages": len(by_stage),
            **{f"track:{k}": v for k, v in sorted(by_track.items())},
            **{f"stage:{k}": v for k, v in sorted(by_stage.items())},
            **{f"split:{k}": v for k, v in sorted(by_split.items())},
        }


def _fingerprint(cases: Iterable[EvaluationCase], manifest: DatasetManifest) -> str:
    return evaluation_digest(
        {
            "dataset_id": manifest.dataset_id,
            "version": manifest.version,
            "split": manifest.split.value,
            "thresholds": manifest.thresholds,
            "required_metrics": list(manifest.required_metrics),
            "cases": [case.identity_digest for case in cases],
        }
    )


def build_dataset(
    manifest: DatasetManifest | Mapping[str, Any],
    cases: Iterable[EvaluationCase | Mapping[str, Any]],
) -> EvaluationDataset:
    meta = manifest if isinstance(manifest, DatasetManifest) else DatasetManifest(**dict(manifest))
    parsed = tuple(
        case if isinstance(case, EvaluationCase) else normalize_case(case)
        for case in cases
    )
    for case in parsed:
        allowed = SPLIT_VISIBILITIES.get(case.split.value)
        if allowed is not None and case.visibility.value not in allowed:
            raise EvaluationError(
                EvaluationErrorCode.INVALID_DATASET,
                f"case {case.case_id} visibility {case.visibility.value} not allowed in split {case.split.value}",
            )
    return EvaluationDataset(
        manifest=meta,
        cases=parsed,
        fingerprint=_fingerprint(parsed, meta),
    )


def load_dataset(root: str | Path, *, manifest_name: str = MANIFEST_NAME) -> EvaluationDataset:
    base = Path(root)
    manifest_path = base / manifest_name
    if not manifest_path.is_file():
        raise EvaluationError(
            EvaluationErrorCode.DATASET_NOT_FOUND,
            f"manifest not found: {manifest_path.name}",
        )
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise EvaluationError(
            EvaluationErrorCode.INVALID_DATASET,
            f"unreadable manifest {manifest_path.name}: {exc}",
        ) from exc
    try:
        manifest = DatasetManifest(**raw)
    except EvaluationError:
        raise
    except Exception as exc:
        raise EvaluationError(
            EvaluationErrorCode.INVALID_DATASET,
            f"invalid manifest {manifest_path.name}: {exc}",
        ) from exc

    section_dirs = sorted(path for path in base.iterdir() if path.is_dir() and not path.name.startswith("."))
    if not section_dirs:
        raise EvaluationError(EvaluationErrorCode.DATASET_EMPTY, "dataset has no section directories")
    if manifest.sections:
        declared = list(manifest.sections)
        found = [path.name for path in section_dirs]
        missing = [name for name in declared if name not in found]
        if missing:
            raise EvaluationError(
                EvaluationErrorCode.DATASET_NOT_FOUND,
                f"declared sections missing: {', '.join(missing)}",
            )

    cases: list[EvaluationCase] = []
    for section_dir in section_dirs:
        for case_path in sorted(section_dir.glob("*.json")):
            try:
                payload = json.loads(case_path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise EvaluationError(
                    EvaluationErrorCode.INVALID_CASE,
                    f"unreadable case {section_dir.name}/{case_path.name}: {exc}",
                ) from exc
            if not isinstance(payload, Mapping):
                raise EvaluationError(
                    EvaluationErrorCode.INVALID_CASE,
                    f"case document must be an object: {section_dir.name}/{case_path.name}",
                )
            payload = dict(payload)
            payload.setdefault("section", section_dir.name)
            case = normalize_case(payload)
            if case.section != section_dir.name:
                raise EvaluationError(
                    EvaluationErrorCode.INVALID_CASE,
                    f"case {case.case_id} section {case.section} does not match directory {section_dir.name}",
                )
            cases.append(case)

    if manifest.case_count and manifest.case_count != len(cases):
        raise EvaluationError(
            EvaluationErrorCode.INVALID_DATASET,
            f"manifest declares {manifest.case_count} cases, found {len(cases)}",
        )
    dataset = build_dataset(manifest, cases)
    return EvaluationDataset(
        manifest=dataset.manifest,
        cases=dataset.cases,
        root=str(base),
        fingerprint=dataset.fingerprint,
    )


# ---------------------------------------------------------------------------
# Blind delivery
# ---------------------------------------------------------------------------


class BlindDatasetProvider:
    """Delivers blind cases and gates ground-truth access on execution.

    The provider is the only object holding expected values; a runner must
    call :meth:`mark_executed` after invoking the system under test and
    before reading :meth:`ground_time_for`."""

    def __init__(self, dataset: EvaluationDataset) -> None:
        self._dataset = dataset
        self._executed: set[str] = set()
        self._lock = threading.Lock()

    @property
    def dataset(self) -> EvaluationDataset:
        return self._dataset

    def case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in self._dataset.cases)

    def blind_case(self, case_id: str) -> BlindEvaluationCase:
        return self._dataset.case(case_id).blind()

    def executed(self, case_id: str) -> bool:
        with self._lock:
            return case_id in self._executed

    def mark_executed(self, case_id: str) -> None:
        # raises CASE_NOT_FOUND for ids outside the dataset
        self._dataset.case(case_id)
        with self._lock:
            self._executed.add(case_id)

    def ground_time_for(self, case_id: str) -> tuple[GroundTruthRecord, ...]:
        with self._lock:
            executed = case_id in self._executed
        if not executed:
            raise EvaluationError(
                EvaluationErrorCode.BLIND_ACCESS_DENIED,
                f"ground truth for {case_id} released only after execution",
            )
        return self._dataset.case(case_id).ground_truth

    def executed_count(self) -> int:
        with self._lock:
            return len(self._executed)


# ---------------------------------------------------------------------------
# Contamination control
# ---------------------------------------------------------------------------


class ContaminationHit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    field: str
    token: str


class ContaminationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scanned_cases: int = 0
    forbidden_tokens: int = 0
    hits: tuple[ContaminationHit, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.hits


def collect_forbidden_identifiers(roots: Iterable[str | Path], *, min_length: int = 5) -> tuple[str, ...]:
    """Collect identifiers (file stems and declared ids) that evaluation
    fixtures must not re-use: skill, task, playbook, and template ids stay
    out of the corpus so a benchmark cannot memorize the product surface."""
    tokens: set[str] = set()
    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".json", ".md", ".yaml", ".yml"}:
                continue
            stem = path.stem.strip().lower()
            if len(stem) >= min_length:
                tokens.add(stem)
            if path.suffix.lower() == ".json":
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001, S112 - unreadable fixture files
                    continue
                tokens.update(_identifier_values(payload, min_length=min_length))
    return tuple(sorted(tokens))


def _identifier_values(payload: Any, *, min_length: int, depth: int = 0) -> set[str]:
    found: set[str] = set()
    if depth > 6:
        return found
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if (
                key in {"id", "skill_id", "task_id", "playbook_id", "template_id", "pack_id", "strategy_id"}
                and isinstance(value, str)
                and len(value) >= min_length
            ):
                found.add(value.strip().lower())
            if key == "ids" and isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, str) and len(item) >= min_length:
                        found.add(item.strip().lower())
            found |= _identifier_values(value, min_length=min_length, depth=depth + 1)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            found |= _identifier_values(item, min_length=min_length, depth=depth + 1)
    return found


def contamination_scan(dataset: EvaluationDataset, forbidden: Iterable[str]) -> ContaminationReport:
    """Compare structural fixture fields against forbidden identifiers.

    Scenario payloads are excluded on purpose: they hold the very code and
    messages under test, which may legitimately mention product names."""
    tokens = tuple(sorted({t.strip().lower() for t in forbidden if t and len(str(t).strip()) >= 5}))
    hits: list[ContaminationHit] = []
    for case in dataset.cases:
        haystacks: list[tuple[str, str]] = [
            ("case_id", case.case_id.lower()),
            ("title", case.title.lower()),
            ("section", case.section.lower()),
            ("scenario.kind", case.scenario.kind.lower()),
            ("notes", case.notes.lower()),
            ("tags", " ".join(case.tags)),
        ]
        for field, text in haystacks:
            for token in tokens:
                if token in text:
                    hits.append(ContaminationHit(case_id=case.case_id, field=field, token=token))
    return ContaminationReport(
        scanned_cases=len(dataset.cases),
        forbidden_tokens=len(tokens),
        hits=tuple(hits),
    )
