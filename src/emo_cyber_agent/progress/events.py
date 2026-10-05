"""Progress events for EMO-Cyber-Agent operations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any


class ProgressEventType(str, Enum):
    """Type of progress event."""

    PROGRESS = "PROGRESS"
    ERROR = "ERROR"


def _parse_event_type(value: Any) -> ProgressEventType:
    if isinstance(value, ProgressEventType):
        return value
    if isinstance(value, str):
        try:
            return ProgressEventType[value.strip().upper()]
        except KeyError:
            try:
                return ProgressEventType(str(value).strip().upper())
            except ValueError as exc:
                raise ValueError(f"Invalid event_type: {value!r}") from exc
    raise ValueError(f"Invalid event_type: {value!r}")


def _parse_timestamp(value: Any) -> datetime:
    if value is None:
        return datetime.now()
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp: {value!r}") from exc
    raise ValueError(f"Invalid timestamp: {value!r}")


class ProgressEvent:
    """Deterministic progress event emitted during long-running operations."""

    def __init__(
        self,
        run_id: str,
        audit_id: str,
        phase: str,
        phase_index: int,
        phase_count: int,
        completed: int,
        total: int,
        percent: float,
        status: str,
        message_code: str,
        event_type: ProgressEventType | str = ProgressEventType.PROGRESS,
        timestamp: datetime | str | None = None,
    ) -> None:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        if not isinstance(audit_id, str) or not audit_id.strip():
            raise ValueError("audit_id must be a non-empty string")
        if not isinstance(phase, str) or not phase.strip():
            raise ValueError("phase must be a non-empty string")
        if not isinstance(phase_count, int) or isinstance(phase_count, bool) or phase_count <= 0:
            raise ValueError("phase_count must be a positive integer")
        if not isinstance(phase_index, int) or isinstance(phase_index, bool):
            raise ValueError("phase_index must be an integer")
        if phase_index < 0 or phase_index >= phase_count:
            raise ValueError("phase_index must satisfy 0 <= phase_index < phase_count")
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise ValueError("total must be a non-negative integer")
        if not isinstance(completed, int) or isinstance(completed, bool) or completed < 0:
            raise ValueError("completed must be a non-negative integer")
        if completed > total:
            raise ValueError("completed must not exceed total")
        try:
            percent_value = float(percent)
        except (TypeError, ValueError) as exc:
            raise ValueError("percent must be a number") from exc
        if not 0.0 <= percent_value <= 100.0:
            raise ValueError("percent must be in range [0.0, 100.0]")
        if not isinstance(status, str) or not status.strip():
            raise ValueError("status must be a non-empty string")
        if not isinstance(message_code, str) or not message_code.strip():
            raise ValueError("message_code must be a non-empty string")

        self.run_id = run_id
        self.audit_id = audit_id
        self.phase = phase
        self.phase_index = phase_index
        self.phase_count = phase_count
        self.completed = completed
        self.total = total
        self.percent = percent_value
        self.status = status
        self.message_code = message_code
        self.event_type = _parse_event_type(event_type)
        self.timestamp = _parse_timestamp(timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "audit_id": self.audit_id,
            "phase": self.phase,
            "phase_index": self.phase_index,
            "phase_count": self.phase_count,
            "completed": self.completed,
            "total": self.total,
            "percent": self.percent,
            "status": self.status,
            "message_code": self.message_code,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProgressEvent":
        try:
            return cls(
                run_id=data["run_id"],
                audit_id=data["audit_id"],
                phase=data["phase"],
                phase_index=data["phase_index"],
                phase_count=data["phase_count"],
                completed=data["completed"],
                total=data["total"],
                percent=data["percent"],
                status=data["status"],
                message_code=data["message_code"],
                event_type=_parse_event_type(data.get("event_type", ProgressEventType.PROGRESS)),
                timestamp=_parse_timestamp(data.get("timestamp")),
            )
        except KeyError as exc:
            raise ValueError(f"Missing required progress event field: {exc}") from exc

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ProgressEvent):
            return NotImplemented
        return (
            self.run_id == other.run_id
            and self.audit_id == other.audit_id
            and self.phase == other.phase
            and self.phase_index == other.phase_index
            and self.phase_count == other.phase_count
            and self.completed == other.completed
            and self.total == other.total
            and self.percent == other.percent
            and self.status == other.status
            and self.message_code == other.message_code
            and self.event_type == other.event_type
        )

    def __repr__(self) -> str:
        return (
            f"ProgressEvent(run_id={self.run_id!r}, audit_id={self.audit_id!r}, "
            f"phase={self.phase!r}, phase_index={self.phase_index!r}, "
            f"phase_count={self.phase_count!r}, completed={self.completed!r}, "
            f"total={self.total!r}, percent={self.percent!r}, status={self.status!r}, "
            f"message_code={self.message_code!r}, event_type={self.event_type.value!r})"
        )
