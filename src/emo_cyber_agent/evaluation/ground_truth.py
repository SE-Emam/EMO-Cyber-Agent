"""Ground truth records and the generic comparator — POST-RC-013.

Ground truth is evaluation-only data. It never enters Core, never reaches a
policy decision, and never appears in a system report. A record names a
subject (a dotted path into the observed payload, empty = the whole
payload), an expected value, and one closed comparison match.

Verdicts are explicit: a missing subject is REFUTED, an unresolvable
comparison is INCONCLUSIVE, and ``expected_absent`` supports the record when
the observed value does NOT match the forbidden shape. The ``unknown`` and
``inconclusive`` kinds score the uncertainty contract itself: they support the
record when the system reports uncertainty instead of inventing an answer.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.evaluation.spec import (
    ComparisonMatch,
    GroundTruthKind,
    OracleVerdict,
    SECURITY_GROUND_TRUTH_KINDS,
    evaluation_digest,
)

__all__ = [
    "GroundTruthRecord",
    "resolve_subject",
    "compare_value",
    "judge_record",
    "is_security_relevant",
    "record_identity",
]


class GroundTruthRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    record_id: str = Field(default="", max_length=96)
    kind: GroundTruthKind
    subject: str = Field(default="", max_length=256)
    value: Any = None
    match: ComparisonMatch = ComparisonMatch.EXACT
    stage: str = Field(default="", max_length=64)
    note: str = Field(default="", max_length=500)

    @field_validator("record_id")
    @classmethod
    def _shape(cls, v: str) -> str:
        return v.strip()

    @property
    def security_relevant(self) -> bool:
        return self.kind.value in SECURITY_GROUND_TRUTH_KINDS


def record_identity(record: GroundTruthRecord) -> str:
    """Deterministic record id when the fixture does not supply one."""
    if record.record_id:
        return record.record_id
    digest = evaluation_digest(
        {
            "kind": record.kind.value,
            "subject": record.subject,
            "value": record.value,
            "match": record.match.value,
            "stage": record.stage,
        }
    )
    return f"gt-{digest[:20]}"


def with_identity(record: GroundTruthRecord) -> GroundTruthRecord:
    rid = record_identity(record)
    if rid == record.record_id:
        return record
    return GroundTruthRecord(**{**record.model_dump(), "record_id": rid})


# ---------------------------------------------------------------------------
# Subject resolution: dotted paths with [index] segments
# ---------------------------------------------------------------------------


def _dig(node: Any, segments: Sequence[str]) -> tuple[bool, Any]:
    current = node
    for segment in segments:
        if current is None:
            return False, None
        if segment.startswith("[") and segment.endswith("]"):
            inner = segment[1:-1]
            if not isinstance(current, (list, tuple)):
                return False, None
            if inner.startswith(('"', "'")):
                return False, None
            try:
                index = int(inner)
            except ValueError:
                return False, None
            if index < 0 or index >= len(current):
                return False, None
            current = current[index]
            continue
        if isinstance(current, Mapping):
            if segment not in current:
                return False, None
            current = current[segment]
            continue
        if isinstance(current, (list, tuple)) and segment.isdigit():
            index = int(segment)
            if index >= len(current):
                return False, None
            current = current[index]
            continue
        return False, None
    return True, current


def _split(subject: str) -> list[str]:
    parts: list[str] = []
    buffer = ""
    index = 0
    while index < len(subject):
        char = subject[index]
        if char == "[":
            if buffer:
                parts.append(buffer)
                buffer = ""
            end = subject.find("]", index)
            if end == -1:
                parts.append(subject[index:])
                return parts
            parts.append(subject[index : end + 1])
            index = end + 1
            continue
        if char == ".":
            if buffer:
                parts.append(buffer)
                buffer = ""
            index += 1
            continue
        buffer += char
        index += 1
    if buffer:
        parts.append(buffer)
    return parts


def resolve_subject(payloads: Iterable[Mapping[str, Any]], subject: str) -> tuple[bool, Any]:
    """Find ``subject`` across ordered payloads. Empty subject merges all
    payloads (later stages win) and returns the whole merged view."""
    ordered = [dict(p) for p in payloads]
    if not ordered:
        return False, None
    if not subject.strip():
        merged: dict[str, Any] = {}
        for payload in ordered:
            merged.update(payload)
        return True, merged
    segments = _split(subject.strip())
    for payload in ordered:
        found, value = _dig(payload, segments)
        if found:
            return True, value
    return False, None


# ---------------------------------------------------------------------------
# Value comparison (closed match set)
# ---------------------------------------------------------------------------


def _as_set(value: Any) -> set[Any]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return set(value)
    if isinstance(value, Mapping):
        return set(value.keys())
    return {value}


def _dict_contains(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    for key, want in expected.items():
        if key not in actual:
            return False
        have = actual[key]
        if isinstance(want, Mapping):
            if not isinstance(have, Mapping) or not _dict_contains(have, want):
                return False
        elif isinstance(want, (list, tuple)) and isinstance(have, (list, tuple)):
            if not _list_contains(have, want):
                return False
        elif have != want:
            return False
    return True


def _list_contains(actual: Sequence[Any], expected: Sequence[Any]) -> bool:
    if isinstance(expected, (str, bytes)) or not isinstance(expected, Sequence):
        return expected in list(actual)
    for item in expected:
        if isinstance(item, Mapping):
            if not any(
                isinstance(candidate, Mapping) and _dict_contains(candidate, item)
                for candidate in actual
            ):
                return False
        elif item not in list(actual):
            return False
    return True


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str):
        return str(expected) in actual
    if isinstance(actual, Mapping):
        if isinstance(expected, Mapping):
            return _dict_contains(actual, expected)
        return expected in actual
    if isinstance(actual, (list, tuple, set, frozenset)):
        items = list(actual)
        if isinstance(expected, Mapping):
            return any(
                isinstance(item, Mapping) and _dict_contains(item, expected) for item in items
            )
        if isinstance(expected, (list, tuple, set, frozenset)):
            return _list_contains(items, list(expected))
        return expected in items
    return actual == expected


def compare_value(actual: Any, expected: Any, match: ComparisonMatch) -> bool | None:
    """Returns True/False, or None when the match cannot be decided."""
    if match is ComparisonMatch.TRUE:
        return actual is True
    if match is ComparisonMatch.ABSENT:
        if actual is None:
            return True
        if isinstance(actual, str):
            return actual.strip() == ""
        if isinstance(actual, (list, tuple, dict, set)):
            return len(actual) == 0
        return False
    if match is ComparisonMatch.NONEMPTY:
        if actual is None:
            return False
        if isinstance(actual, str):
            return actual.strip() != ""
        if isinstance(actual, (list, tuple, dict, set)):
            return len(actual) > 0
        return True
    if actual is None:
        return None
    if match is ComparisonMatch.EXACT:
        if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
            return float(actual) == float(expected)
        return bool(actual == expected)
    if match is ComparisonMatch.CONTAINS:
        return _contains(actual, expected)
    if match is ComparisonMatch.NOT_CONTAINS:
        return not _contains(actual, expected)
    if match is ComparisonMatch.SUPERSET:
        return _as_set(expected) <= _as_set(actual)
    if match is ComparisonMatch.SUBSET:
        return _as_set(actual) <= _as_set(expected)
    if match is ComparisonMatch.SET_EQUALS:
        return _as_set(actual) == _as_set(expected)
    return None


# ---------------------------------------------------------------------------
# Kind-aware judging
# ---------------------------------------------------------------------------

_INCONCLUSIVE_MARKERS = ("inconclusive", "unknown", "not_verifiable", "insufficient")


def _marks_inconclusive(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in _INCONCLUSIVE_MARKERS
    if isinstance(value, bool):
        return False
    if isinstance(value, Mapping):
        status = str(value.get("status", "")).strip().lower()
        return status in _INCONCLUSIVE_MARKERS
    return False


def _has_unknown(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("unknown", "", "unassessed")
    if isinstance(value, Mapping):
        return all(_has_unknown(v) for v in value.values()) if value else False
    if isinstance(value, (list, tuple)):
        return len(value) == 0
    return False


def judge_record(
    record: GroundTruthRecord,
    payloads: Iterable[Mapping[str, Any]],
) -> OracleVerdict:
    """Turn one ground-truth record into one verdict."""
    ordered = [dict(p) for p in payloads]
    kind = record.kind

    if kind is GroundTruthKind.UNKNOWN:
        # Expectation: the system reports "unknown" instead of inventing a
        # value. A concrete value is a refutation; an unknown-shaped value
        # (or an absent subject) supports the expectation.
        found, value = resolve_subject(ordered, record.subject)
        if not found or _has_unknown(value):
            return OracleVerdict.SUPPORTED
        return OracleVerdict.REFUTED

    if kind is GroundTruthKind.INCONCLUSIVE:
        # Expectation: the system marks the outcome inconclusive.
        found, value = resolve_subject(ordered, record.subject)
        if found and _marks_inconclusive(value):
            return OracleVerdict.SUPPORTED
        return OracleVerdict.REFUTED

    found, value = resolve_subject(ordered, record.subject)

    if kind is GroundTruthKind.EXPECTED_ABSENT:
        # The record states the forbidden shape, so the expectation is
        # supported when the observation does NOT match it. A subject that is
        # missing entirely is the strongest form of absence.
        if not found:
            return OracleVerdict.SUPPORTED
        decided = compare_value(value, record.value, record.match)
        if decided is None:
            return OracleVerdict.INCONCLUSIVE
        return OracleVerdict.SUPPORTED if not decided else OracleVerdict.REFUTED

    if kind is GroundTruthKind.EXPECTED_PRESENT:
        if not found:
            return OracleVerdict.REFUTED
        decided = compare_value(value, record.value, record.match)
        if decided is None:
            return OracleVerdict.INCONCLUSIVE
        return OracleVerdict.SUPPORTED if decided else OracleVerdict.REFUTED

    if not found:
        return OracleVerdict.REFUTED
    decided = compare_value(value, record.value, record.match)
    if decided is None:
        return OracleVerdict.INCONCLUSIVE
    return OracleVerdict.SUPPORTED if decided else OracleVerdict.REFUTED


def is_security_relevant(record: GroundTruthRecord, *, stage: str = "") -> bool:
    return record.security_relevant or stage in ("authority", "isolation", "parity")


def judge_or_reject(records: Iterable[GroundTruthRecord]) -> tuple[GroundTruthRecord, ...]:
    """Validate a record set: empty subject is allowed only for whole-payload
    checks, and a record with neither subject nor value is a fixture bug."""
    normalized: list[GroundTruthRecord] = []
    for record in records:
        if record.subject == "" and record.value is None and record.match not in (
            ComparisonMatch.ABSENT,
            ComparisonMatch.NONEMPTY,
            ComparisonMatch.TRUE,
        ):
            raise EvaluationError(
                EvaluationErrorCode.ORACLE_REJECTED,
                f"ground truth record {record.record_id or record.kind.value} needs a subject or value",
            )
        if record.kind is GroundTruthKind.EXPECTED_ABSENT and record.match in (
            ComparisonMatch.NOT_CONTAINS,
            ComparisonMatch.ABSENT,
        ):
            # expected_absent already inverts the comparison; combining it with
            # a negative match would double-negate and silently pass fixtures.
            raise EvaluationError(
                EvaluationErrorCode.ORACLE_REJECTED,
                (
                    f"record {record.record_id or record.kind.value} pairs expected_absent "
                    f"with match={record.match.value}"
                ),
            )
        normalized.append(with_identity(record))
    return tuple(normalized)
