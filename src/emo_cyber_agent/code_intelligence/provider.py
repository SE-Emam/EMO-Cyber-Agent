"""Code intelligence provider port — POST-RC-005.

Core knows ONLY this contract. Joern, CodeQL, tree-sitter, semgrep-AST
and language-specific libraries live behind it, never in Core.
Providers return normalized FACTS. They cannot emit findings,
severity, policy, permissions, verification, or remediation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

PROVIDER_CAPABILITIES: tuple[str, ...] = (
    "ast", "symbols", "references", "call_graph", "control_flow",
    "dataflow", "taint", "dependencies", "routes", "auth_boundaries",
    "db_relationships",
)


class CodeIntelligenceProvider(ABC):
    """Application port. Adapters implement; Core owns decisions.

    READ-ONLY ONLY. No code execution, no repository/database mutation,
    no secret access, no network, no shell. External processes run
    inside the Tool/Execution boundary; the adapter only normalizes.
    """

    @property
    @abstractmethod
    def provider_id(self) -> str: ...

    @property
    @abstractmethod
    def provider_version(self) -> str: ...

    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        """Subset of PROVIDER_CAPABILITIES this provider truly supports."""

    @abstractmethod
    def analyze(self, *, snapshot: Any, files: dict[str, str]) -> Any:
        """Build a snapshot-scoped normalized result.

        files: normalized path → source text (DATA). Returns a
        provider-local analysis bundle the graph builder consumes.
        Must be deterministic for identical inputs or declare
        nondeterminism in the returned metadata.
        """

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities()
