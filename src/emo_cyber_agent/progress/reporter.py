"""Progress reporting to CLI and MCP consumers."""

from __future__ import annotations

from typing import Callable, Iterable

from .events import ProgressEvent

ProgressSink = Callable[[ProgressEvent], None]


class ProgressReporter:
    """Fan-out reporter delivering progress events to registered sinks."""

    def __init__(self, sinks: Iterable[ProgressSink] | None = None) -> None:
        self._sinks: list[ProgressSink] = list(sinks) if sinks else []
        self._events: list[ProgressEvent] = []

    def add_sink(self, sink: ProgressSink) -> None:
        self._sinks.append(sink)

    def report(self, event: ProgressEvent) -> ProgressEvent:
        self._events.append(event)
        for sink in self._sinks:
            sink(event)
        return event

    @property
    def events(self) -> list[ProgressEvent]:
        return list(self._events)

    def cli_sink(self) -> ProgressSink:
        def _sink(event: ProgressEvent) -> None:
            bar_width = 20
            filled = int(round((event.percent / 100.0) * bar_width))
            bar = "#" * filled + "-" * (bar_width - filled)
            print(f"[{bar}] {event.percent:6.2f}% {event.phase} ({event.message_code})")

        return _sink

    def mcp_notification(self, event: ProgressEvent) -> dict[str, object]:
        return {
            "method": "notifications/progress",
            "params": event.to_dict(),
        }
