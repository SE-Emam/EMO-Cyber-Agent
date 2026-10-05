"""Provider port: no concrete model is bundled."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(slots=True)
class ToolCallRequest:
    name: str
    arguments: dict[str, Any]


class ModelProvider(Protocol):
    async def complete(self, messages: list[dict[str, Any]], *, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Return a normalized structured response from an external model provider."""
        ...
