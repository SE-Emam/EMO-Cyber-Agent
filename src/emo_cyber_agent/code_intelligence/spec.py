"""Normalized code intelligence domain — POST-RC-005.

PROGRAM STRUCTURE → SECURITY-RELEVANT FACTS. Every model here is a
FACT container: no severity, no verdicts, no policy, no remediation.
Frozen, extra-forbidden, audit- and snapshot-scoped. Source text is
always DATA (never authority).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CODE_INTELLIGENCE_CONTRACT_VERSION = "1.0"
TAINT_TAXONOMY_VERSION = "1.0"

# Graph safety defaults (§34). Providers may tighten, never loosen.
DEFAULT_MAX_NODES = 50_000
DEFAULT_MAX_EDGES = 200_000
DEFAULT_MAX_TRAVERSAL_DEPTH = 25
DEFAULT_MAX_RESULTS = 1_000
DEFAULT_MAX_PATH_LENGTH = 64


class ResultQuality(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class ResolutionConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ObservationKind(StrEnum):
    DATAFLOW_PATH_FOUND = "DATAFLOW_PATH_FOUND"
    UNRESOLVED_AUTH_BOUNDARY = "UNRESOLVED_AUTH_BOUNDARY"
    DATABASE_ACCESS_PATH = "DATABASE_ACCESS_PATH"
    EXTERNAL_CALL_PATH = "EXTERNAL_CALL_PATH"
    DEPENDENCY_USAGE = "DEPENDENCY_USAGE"
    ROUTE_HANDLER_DISCOVERED = "ROUTE_HANDLER_DISCOVERED"
    STATE_CHANGE_OPERATION = "STATE_CHANGE_OPERATION"


# Extensible, versioned source/sink taxonomy (§13).
SOURCE_KINDS: tuple[str, ...] = (
    "http_parameter", "request_body", "header", "cookie", "environment",
    "database", "message_queue", "external_input", "file_input",
)
SINK_KINDS: tuple[str, ...] = (
    "sql_execution", "shell_process", "html_rendering", "filesystem",
    "network_request", "template_engine", "deserialization",
    "dynamic_code_execution",
)

# Task/skill-facing capability requests (§45). Requests only — the
# PolicyEngine decides. Provider capability → requested capability.
PROVIDER_CAPABILITY_TO_REQUESTED: dict[str, str] = {
    "ast": "code.ast.read",
    "symbols": "code.symbols.read",
    "references": "code.symbols.read",
    "call_graph": "code.callgraph.read",
    "control_flow": "code.callgraph.read",
    "dataflow": "code.dataflow.read",
    "taint": "code.dataflow.read",
    "dependencies": "code.dependencies.read",
    "routes": "code.routes.read",
    "auth_boundaries": "code.routes.read",
    "db_relationships": "code.dataflow.read",
}

_EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rs": "rust", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp", ".php": "php",
    ".rb": "ruby", ".kt": "kotlin", ".sql": "sql", ".yaml": "yaml",
    ".yml": "yaml", ".json": "json",
}
_FILENAME_LANGUAGE: dict[str, str] = {
    "dockerfile": "dockerfile", "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
}


def detect_language(path: str) -> str:
    """Pure, deterministic language guess. Unknown → 'unknown' (never invented)."""
    lowered = path.lower().replace("\\", "/")
    base = lowered.rsplit("/", 1)[-1]
    if base in _FILENAME_LANGUAGE:
        return _FILENAME_LANGUAGE[base]
    if base.endswith(".tf") or base.endswith(".tofu"):
        return "terraform"
    if "k8s" in base or "kubernetes" in base or base.endswith(("-deployment.yaml", "-service.yaml", "-manifest.yaml", "-manifest.yml")):
        return "kubernetes"
    ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    return _EXTENSION_LANGUAGE.get(ext, "unknown")


def content_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def normalize_code_path(path: str) -> str:
    """Canonical repo-relative path. Reuses the T015 repository rule —
    no competing implementation."""
    from emo_cyber_agent.core.repository import normalize_path

    try:
        return normalize_path(path)
    except Exception as e:
        from emo_cyber_agent.code_intelligence.errors import CodeIntelligenceError, CodeIntelligenceErrorCode

        raise CodeIntelligenceError(CodeIntelligenceErrorCode.QUERY_REJECTED, f"path rejected: {e}") from e


class CodeLocation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str = Field(...)
    line: int = Field(default=1, ge=1)
    column: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return normalize_code_path(v)


class CodeProject(BaseModel):
    """Identity binding: audit + asset + repository. Cross-audit reuse = DENY."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    audit_id: str = Field(..., min_length=1, max_length=120)
    asset_id: str = Field(default="", max_length=200)
    provider: str = Field(default="local", min_length=1, max_length=40)
    owner: str = Field(default="", max_length=120)
    repo: str = Field(default="", max_length=120)
    ref: str = Field(default="main", min_length=1, max_length=200)


class CodeSnapshot(BaseModel):
    """Immutable analysis instant. No revision → explicit limitation, never assumed."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    project: CodeProject
    provider: str = Field(..., min_length=1, max_length=80)
    provider_version: str = Field(..., min_length=1, max_length=40)
    revision: str | None = Field(default=None, max_length=120)
    source_digest: str = Field(default="", max_length=128)
    captured_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    limitation: str = Field(default="")

    @model_validator(mode="after")
    def _limitation(self) -> CodeSnapshot:
        if not self.limitation and not self.revision:
            object.__setattr__(self, "limitation", "no revision pinned: snapshot is best-effort, not reproducible")
        return self


class CodeFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str = Field(...)
    language: str = Field(default="unknown", max_length=40)
    digest: str = Field(default="", max_length=128)
    size_bytes: int = Field(default=0, ge=0)

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return normalize_code_path(v)


class CodeSymbol(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    symbol_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=40)
    name: str = Field(..., min_length=1, max_length=320)
    file: str = Field(...)
    location: CodeLocation
    scope: str = Field(default="", max_length=320)
    exported: bool = False
    language: str = Field(default="unknown", max_length=40)

    @field_validator("file")
    @classmethod
    def _file(cls, v: str) -> str:
        return normalize_code_path(v)


class AstNodeReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    node_id: str = Field(..., min_length=1, max_length=320)
    node_type: str = Field(..., min_length=1, max_length=80)
    location: CodeLocation
    parent_id: str = Field(default="", max_length=320)
    symbol_id: str = Field(default="", max_length=320)
    digest: str = Field(default="", max_length=128)


class CallEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    caller_id: str = Field(..., min_length=1, max_length=320)
    callee_id: str = Field(..., min_length=1, max_length=320)
    location: CodeLocation
    confidence: ResolutionConfidence = ResolutionConfidence.MEDIUM
    incomplete: bool = False
    provider: str = Field(default="", max_length=80)


class ControlFlowEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    from_id: str = Field(..., min_length=1, max_length=320)
    to_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=40)
    location: CodeLocation | None = None


class DataFlowEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    from_id: str = Field(..., min_length=1, max_length=320)
    to_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(default="flows_to", max_length=40)
    location: CodeLocation | None = None
    confidence: ResolutionConfidence = ResolutionConfidence.MEDIUM


class DependencyEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    importer: str = Field(..., min_length=1, max_length=320)
    package: str = Field(..., min_length=1, max_length=200)
    version: str = Field(default="", max_length=40)
    module: str = Field(default="", max_length=320)
    reachable: bool = True
    manifest_path: str = Field(default="", max_length=512)


class RouteEndpoint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    endpoint_id: str = Field(..., min_length=1, max_length=320)
    method: str = Field(..., min_length=1, max_length=12)
    path: str = Field(..., min_length=1, max_length=512)
    handler_id: str = Field(default="", max_length=320)
    framework: str = Field(default="unknown", max_length=40)
    location: CodeLocation
    auth_boundary_id: str = Field(default="", max_length=320)
    downstream: tuple[str, ...] = ()
    state_changing: bool = False


class AuthorizationBoundary(BaseModel):
    """A discovered check — presence metadata, never a vulnerability claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    boundary_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=40)
    location: CodeLocation
    protects_id: str = Field(default="", max_length=320)
    mechanism: str = Field(default="", max_length=200)
    confidence: ResolutionConfidence = ResolutionConfidence.MEDIUM


class DataSource(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    source_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=40)
    location: CodeLocation
    symbol_id: str = Field(default="", max_length=320)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in SOURCE_KINDS:
            raise ValueError(f"source kind not in taxonomy v{TAINT_TAXONOMY_VERSION}: {v}")
        return v


class DataSink(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    sink_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=40)
    location: CodeLocation
    symbol_id: str = Field(default="", max_length=320)

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in SINK_KINDS:
            raise ValueError(f"sink kind not in taxonomy v{TAINT_TAXONOMY_VERSION}: {v}")
        return v


class TaintPath(BaseModel):
    """A structure path source → sink. TAINT_PATH_FOUND, never *_CONFIRMED."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    path_id: str = Field(..., min_length=1, max_length=320)
    source_id: str = Field(..., min_length=1, max_length=320)
    sink_id: str = Field(..., min_length=1, max_length=320)
    node_ids: tuple[str, ...] = ()
    locations: tuple[CodeLocation, ...] = ()
    confidence: ResolutionConfidence = ResolutionConfidence.MEDIUM
    completeness: ResultQuality = ResultQuality.PARTIAL
    provider: str = Field(default="", max_length=80)


class CodeComponent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    component_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=40)
    name: str = Field(..., min_length=1, max_length=320)
    children: tuple[str, ...] = ()


class DatabaseRelationship(BaseModel):
    """Code ↔ database fact edge (cross-layer substrate, not a verdict)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    relation_id: str = Field(..., min_length=1, max_length=320)
    kind: str = Field(..., min_length=1, max_length=60)
    code_id: str = Field(..., min_length=1, max_length=320)
    database_object: str = Field(..., min_length=1, max_length=320)
    location: CodeLocation | None = None
    confidence: ResolutionConfidence = ResolutionConfidence.MEDIUM


class CodeObservation(BaseModel):
    """Security-relevant fact with mandatory evidence linkage. Never a finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    observation_id: str = Field(..., min_length=1, max_length=320)
    kind: ObservationKind
    statement: str = Field(..., min_length=1, max_length=1000)
    evidence_ids: tuple[str, ...] = ()
    location: CodeLocation | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def _evidence_required(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("observation requires at least one evidence id")
        return v


class QueryProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    query_type: str = Field(..., min_length=1, max_length=60)
    target: str = Field(default="", max_length=320)
    provider: str = Field(..., min_length=1, max_length=80)
    provider_version: str = Field(default="", max_length=40)
    snapshot_digest: str = Field(default="", max_length=128)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    result_digest: str = Field(default="", max_length=128)
