"""Deterministic progress state tracking."""

from __future__ import annotations

from dataclasses import dataclass, field

from .events import ProgressEvent, ProgressEventType


@dataclass
class ProgressState:
    """Mutable tracker that derives ProgressEvent objects for a run."""

    run_id: str
    audit_id: str
    phases: list[str]
    completed: int = 0
    total: int = 0
    current_phase_index: int = 0
    events: list[ProgressEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.phases:
            raise ValueError("phases must be a non-empty list")
        if self.total <= 0:
            self.total = len(self.phases)
        if self.completed < 0 or self.completed > self.total:
            raise ValueError("completed must satisfy 0 <= completed <= total")

    @property
    def phase_count(self) -> int:
        return len(self.phases)

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.completed / self.total) * 100.0, 2)

    @property
    def current_phase(self) -> str:
        index = max(0, min(self.current_phase_index, len(self.phases) - 1))
        return self.phases[index]

    def advance(
        self,
        phase: str | None = None,
        status: str | None = None,
        message_code: str = "PHASE_STARTED",
        event_type: ProgressEventType = ProgressEventType.PROGRESS,
    ) -> ProgressEvent:
        if phase is not None:
            if phase not in self.phases:
                raise ValueError(f"Unknown phase: {phase!r}")
            self.current_phase_index = self.phases.index(phase)
        self.completed = min(self.completed + 1, self.total)
        event = ProgressEvent(
            run_id=self.run_id,
            audit_id=self.audit_id,
            phase=self.current_phase,
            phase_index=self.current_phase_index,
            phase_count=self.phase_count,
            completed=self.completed,
            total=self.total,
            percent=self.percent,
            status=status or self.current_phase,
            message_code=message_code,
            event_type=event_type,
        )
        self.events.append(event)
        return event
