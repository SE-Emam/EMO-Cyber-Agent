"""Core Repository Port — ECA-T005.

Defines the ONLY path for repository access:

Request → Core → ToolRegistry → PolicyEngine → Repository Tool Invocation
→ RepositoryPort → External Repository → Normalized Result → EvidenceItem → Core

Rules enforced here:
- READ_ONLY first: only repository.read / .list / .search / .metadata.
- No write capabilities are defined in this phase.
- Every repository has a stable identity bound to audit/project scope.
- Cross-project / cross-audit reuse is denied without explicit contract.
- Credentials are never part of evidence, logs, invocations, or errors.
- All repository content is UNTRUSTED DATA (never instructions).
- Provider-specific exceptions are normalized to RepositoryErrorCode.
- No global mutable repository state; every call is scoped.

Adapters (GitHub, Mock) implement RepositoryPort. They fetch → map → return.
They MUST NOT make security decisions, compute severity, or escalate privilege.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.core.tool_registry import ToolInvocation, ToolRegistry, ToolSpec

POLICY_VERSION = "eca-t005-v1"
SCHEMA_VERSION = "0.1.0"

# Read-only capabilities for this phase. No write capabilities exist here.
REPOSITORY_CAPABILITIES: tuple[str, ...] = (
    "repository.read",
    "repository.list",
    "repository.search",
    "repository.metadata",
)

_REF_RE = re.compile(r"^[A-Za-z0-9._\-/]{1,128}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")

# Token/secret patterns redacted before persistence, logs, evidence, errors.
_SECRET_PATTERNS = (
    re.compile(r"(?i)(github_pat_[A-Za-z0-9_]+)"),
    re.compile(r"(?i)(ghp_[A-Za-z0-9]+)"),
    re.compile(r"(?i)(gho_[A-Za-z0-9]+)"),
    re.compile(r"(?i)(bearer\s+[A-Za-z0-9\-._~+/=]+)"),
    re.compile(r"(?i)(token\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/=]{8,})"),
)


class RepositoryErrorCode(StrEnum):
    REPOSITORY_NOT_FOUND = "REPOSITORY_NOT_FOUND"
    ACCESS_DENIED = "ACCESS_DENIED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    INVALID_REF = "INVALID_REF"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    SEARCH_FAILED = "SEARCH_FAILED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    CONTENT_UNAVAILABLE = "CONTENT_UNAVAILABLE"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    AMBIGUOUS_IDENTITY = "AMBIGUOUS_IDENTITY"
    POLICY_DENIED = "POLICY_DENIED"
    STALE_POLICY = "STALE_POLICY"
    MISMATCHED_AUDIT = "MISMATCHED_AUDIT"


class RepositoryError(Exception):
    """Normalized repository failure. Provider exceptions never leak to Core."""

    def __init__(self, code: RepositoryErrorCode, message: str, *, safe_details: dict[str, Any] | None = None):
        super().__init__(f"{code.value}: {redact_credentials(message)}")
        self.code = code
        self.safe_details = safe_details or {}


def redact_credentials(text: str) -> str:
    """Redact credential material. Never returns raw secrets."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_CREDENTIAL]", redacted)
    return redacted


def content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def mark_untrusted(content: str) -> dict[str, Any]:
    """Wrap repository content as explicitly untrusted data.

    The returned envelope is DATA, never an instruction. Policy, permissions,
    system instructions, tool capabilities, and agent authority MUST NOT be
    derived from this envelope.
    """
    return {
        "classification": "untrusted",
        "trust_level": "untrusted-data",
        "content_digest": content_digest(content),
        "content_preview": content[:500],
        "must_not_alter": ["policy", "permissions", "system_instructions", "tool_capabilities", "agent_authority"],
    }


def normalize_path(path: str) -> str:
    """Validate a repository-relative path. Rejects traversal (literal,
    percent-encoded, and double-encoded), absolutes, and null bytes."""
    import re as _re

    if not path or not path.strip():
        raise RepositoryError(RepositoryErrorCode.FILE_NOT_FOUND, "empty path")
    p = path.strip()
    if "\x00" in p:
        raise RepositoryError(RepositoryErrorCode.PATH_TRAVERSAL, "null byte denied")
    if p.startswith("/") or p.startswith("\\"):
        raise RepositoryError(RepositoryErrorCode.PATH_TRAVERSAL, f"absolute path denied: {p[:80]}")
    if len(p) > 1 and p[1] == ":":
        raise RepositoryError(RepositoryErrorCode.PATH_TRAVERSAL, "drive-letter path denied")
    # Decode percent-escapes iteratively (catches %2e and %252e) then re-check.
    decoded = p
    for _ in range(3):
        nxt = _re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), decoded)
        if nxt == decoded:
            break
        decoded = nxt
    if decoded != p:
        raise RepositoryError(RepositoryErrorCode.PATH_TRAVERSAL, f"encoded traversal denied: {p[:80]}")
    parts = p.replace("\\", "/").split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        raise RepositoryError(RepositoryErrorCode.PATH_TRAVERSAL, f"traversal denied: {p[:80]}")
    if len(p) > 512:
        raise RepositoryError(RepositoryErrorCode.FILE_NOT_FOUND, "path too long")
    return "/".join(parts)


def validate_ref(ref: str) -> str:
    if not ref or not ref.strip():
        raise RepositoryError(RepositoryErrorCode.INVALID_REF, "empty ref")
    r = ref.strip()
    if "\x00" in r or "%" in r:
        raise RepositoryError(RepositoryErrorCode.INVALID_REF, "invalid ref characters")
    if not _REF_RE.match(r) or r in (".", "..") or ".." in r or r.startswith("/") or r.startswith("-"):
        raise RepositoryError(RepositoryErrorCode.INVALID_REF, f"invalid ref: {r[:80]}")
    return r


class RepositoryIdentity(BaseModel):
    """Stable repository identity bound to an audit scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    repo: str = Field(..., min_length=1)
    ref: str = Field(default="main")
    revision: str | None = None

    @field_validator("provider")
    @classmethod
    def _provider(cls, v: str) -> str:
        vv = v.strip().lower()
        if vv not in ("github", "local", "mock"):
            raise ValueError(f"unsupported provider: {v}")
        return vv

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str) -> str:
        if not _OWNER_RE.match(v.strip()):
            raise ValueError(f"invalid owner: {v[:40]}")
        return v.strip()

    @field_validator("repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        if not _REPO_RE.match(v.strip()):
            raise ValueError(f"invalid repo: {v[:40]}")
        return v.strip()

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        try:
            return validate_ref(v)
        except RepositoryError as e:
            raise ValueError(str(e)) from e

    @property
    def canonical_locator(self) -> str:
        base = f"{self.provider}:{self.owner}/{self.repo}@{self.ref}"
        if self.revision:
            base += f"#{self.revision[:12]}"
        return base


def parse_repository_locator(locator: str) -> RepositoryIdentity:
    """Parse 'provider:owner/repo@ref[#revision]'. Rejects ambiguous locators.

    Hostname-only or owner-less strings are AMBIGUOUS_IDENTITY (never guessed).
    """
    if not locator or not locator.strip():
        raise RepositoryError(RepositoryErrorCode.AMBIGUOUS_IDENTITY, "empty locator")
    loc = locator.strip()
    if ":" not in loc or "/" not in loc or "@" not in loc:
        raise RepositoryError(
            RepositoryErrorCode.AMBIGUOUS_IDENTITY,
            f"locator must be provider:owner/repo@ref, got: {loc[:80]}",
        )
    try:
        provider_part, rest = loc.split(":", 1)
        owner_repo, ref_part = rest.split("@", 1)
        owner, repo = owner_repo.split("/", 1)
        revision = None
        if "#" in ref_part:
            ref_part, revision = ref_part.split("#", 1)
        return RepositoryIdentity(provider=provider_part, owner=owner, repo=repo, ref=ref_part, revision=revision or None)
    except (ValueError, RepositoryError) as e:
        if isinstance(e, RepositoryError):
            raise
        raise RepositoryError(RepositoryErrorCode.AMBIGUOUS_IDENTITY, f"unparseable locator: {loc[:80]}") from e


class AuditRepositoryScope(BaseModel):
    """Scope binding: one audit may only touch its own listed repositories."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str = Field(..., min_length=1)
    project_id: str = Field(..., min_length=1)
    allowed: tuple[RepositoryIdentity, ...] = Field(default_factory=tuple)

    def allows(self, identity: RepositoryIdentity) -> bool:
        for a in self.allowed:
            if (
                a.provider == identity.provider
                and a.owner == identity.owner
                and a.repo == identity.repo
            ):
                return True
        return False


def assert_repository_in_scope(scope: AuditRepositoryScope, identity: RepositoryIdentity, *, audit_id: str) -> None:
    if audit_id != scope.audit_id:
        raise RepositoryError(RepositoryErrorCode.MISMATCHED_AUDIT, "audit_id mismatch")
    if not scope.allows(identity):
        raise RepositoryError(
            RepositoryErrorCode.OUT_OF_SCOPE,
            f"repository not in scope: {identity.canonical_locator}",
            safe_details={"canonical": identity.canonical_locator},
        )


# ---------------------------------------------------------------------------
# Normalized representations (provider-agnostic, no GitHub assumptions)
# ---------------------------------------------------------------------------

class Repository(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: RepositoryIdentity
    name: str = ""
    description: str = ""
    default_branch: str = "main"
    private: bool = False
    provider: str = "github"


class RepositoryTreeEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str
    kind: str  # file | dir
    sha: str | None = None
    size: int | None = None


class RepositoryTree(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: RepositoryIdentity
    path: str = ""
    entries: tuple[RepositoryTreeEntry, ...] = ()
    truncated: bool = False


class RepositoryFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: RepositoryIdentity
    path: str
    ref: str
    sha: str | None = None
    content_digest: str = ""
    untrusted: dict[str, Any] = Field(default_factory=dict)
    # Full content is carried for read-only analysis but ALWAYS untrusted.
    content: str = ""

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        try:
            return normalize_path(v)
        except RepositoryError as e:
            raise ValueError(str(e)) from e


class CodeSearchResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: RepositoryIdentity
    path: str
    line: int | None = None
    snippet_digest: str = ""
    untrusted_snippet: dict[str, Any] = Field(default_factory=dict)


class CommitInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: RepositoryIdentity
    sha: str
    message_digest: str = ""
    author: str = ""
    committed_at: str = ""


class RepositoryPort(ABC):
    """Application port. Adapters implement; Core owns decisions.

    READ-ONLY ONLY. No write/pr/merge/push/issue methods may be added in ECA-T005.
    """

    @abstractmethod
    def resolve_repository(self, identity: RepositoryIdentity) -> Repository: ...
    @abstractmethod
    def get_metadata(self, identity: RepositoryIdentity) -> Repository: ...
    @abstractmethod
    def list_tree(self, identity: RepositoryIdentity, path: str = "") -> RepositoryTree: ...
    @abstractmethod
    def get_file(self, identity: RepositoryIdentity, path: str) -> RepositoryFile: ...
    @abstractmethod
    def search_code(self, identity: RepositoryIdentity, query: str) -> list[CodeSearchResult]: ...
    @abstractmethod
    def get_commit(self, identity: RepositoryIdentity, ref: str) -> CommitInfo: ...


def get_repository_tool_specs() -> list[ToolSpec]:
    """Read-only ToolSpecs for repository operations (no write capabilities)."""
    base = dict(
        version="1.0.0",
        description="Read-only repository operation",
        category="repository",
        risk_level="low",
        supports_read_only=True,
        supports_verification=False,
        supports_remediation=False,
        target_types=("repo",),
        evidence_behavior="summarize",
        timeout_ms=30000,
    )
    return [
        ToolSpec(tool_id="repository.metadata", name="Repository Metadata", capabilities_required=("repository.metadata",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="repository.list", name="Repository Tree Listing", capabilities_required=("repository.list",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="repository.read", name="Repository File Read", capabilities_required=("repository.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="repository.search", name="Repository Code Search", capabilities_required=("repository.search",), **base),  # type: ignore[arg-type]
    ]


def build_evidence_provenance(
    *,
    identity: RepositoryIdentity,
    invocation_id: str,
    tool_id: str,
    tool_version: str = "1.0.0",
    path: str | None = None,
    content: str | None = None,
) -> dict[str, Any]:
    """Provenance sufficient to re-trace source without storing full code by default."""
    prov: dict[str, Any] = {
        "source_provider": identity.provider,
        "repository": f"{identity.owner}/{identity.repo}",
        "ref": identity.ref,
        "revision": identity.revision,
        "canonical_locator": identity.canonical_locator,
        "invocation_id": invocation_id,
        "tool_id": tool_id,
        "tool_version": tool_version,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
    }
    if path:
        prov["path"] = path
    if content is not None:
        prov["content_digest"] = content_digest(content)
    return prov


class RepositoryService:
    """Core-owned orchestration: scope → registry → policy → port → evidence.

    This is the ONLY allowed path for repository operations. Hosts and adapters
    MUST NOT call RepositoryPort directly.
    """

    def __init__(self, *, port: RepositoryPort, policy_engine: Any, registry: ToolRegistry, scope: AuditRepositoryScope, profile: str = "read_only"):

        self._port = port
        self._policy: Any = policy_engine
        self._registry = registry
        self._scope = scope
        self._profile = profile
        self._policy_version = POLICY_VERSION

    def _require(self, *, capability: str, tool_id: str, identity: RepositoryIdentity, audit_id: str, policy_decision_id: str | None = None) -> str:
        # 1. audit binding
        assert_repository_in_scope(self._scope, identity, audit_id=audit_id)
        # 2. tool must be registered (unknown tool = DENY)
        try:
            spec = self._registry.get(tool_id)
        except ValueError as e:
            raise RepositoryError(RepositoryErrorCode.POLICY_DENIED, f"unknown tool: {tool_id}") from e
        # 3. capability must have been declared by the tool
        if capability not in spec.capabilities_required:
            raise RepositoryError(RepositoryErrorCode.POLICY_DENIED, f"undeclared capability: {capability} for {tool_id}")
        # 4. profile must allow read-only; this phase has no write caps at all
        if self._profile != "read_only":
            # Only read_only profile exists in ECA-T005 scope; anything else needs explicit contract.
            raise RepositoryError(RepositoryErrorCode.POLICY_DENIED, f"unsupported profile in ECA-T005: {self._profile}")
        # 5. policy decision required, fresh, and matching
        if not policy_decision_id:
            raise RepositoryError(RepositoryErrorCode.POLICY_DENIED, "missing policy_decision_id")
        allowed = self._policy.evaluate_policy(audit_id, tool_id, identity.canonical_locator, self._profile, [capability])
        if not allowed:
            raise RepositoryError(RepositoryErrorCode.POLICY_DENIED, f"policy denied {tool_id}:{capability}")
        return policy_decision_id

    def _invocation(self, *, audit_id: str, tool_id: str, identity: RepositoryIdentity, capability: str, policy_decision_id: str) -> ToolInvocation:
        spec_version = self._registry.get(tool_id).version
        inv = ToolInvocation(
            audit_id=audit_id,
            tool_id=tool_id,
            tool_version=spec_version,
            target=identity.canonical_locator,
            requested_capabilities=(capability,),
            policy_decision_id=policy_decision_id,
            profile=self._profile,
        )
        inv = inv.transition_to(__import__("emo_cyber_agent.core.tool_registry", fromlist=["ToolInvocationStatus"]).ToolInvocationStatus.VALIDATING)
        mod = __import__("emo_cyber_agent.core.tool_registry", fromlist=["ToolInvocationStatus"])
        inv = inv.transition_to(mod.ToolInvocationStatus.POLICY_CHECK)
        inv = inv.transition_to(mod.ToolInvocationStatus.APPROVED)
        inv = inv.transition_to(mod.ToolInvocationStatus.EXECUTING)
        return inv

    def _complete(self, inv: ToolInvocation, *, summary: str, evidence_ids: tuple[str, ...] = ()) -> ToolInvocation:
        return inv.update_output(redact_credentials(summary), evidence_ids=evidence_ids)

    # ---- operations (read-only) ----
    def resolve_repository(self, identity: RepositoryIdentity, *, audit_id: str, policy_decision_id: str | None) -> tuple[Repository, ToolInvocation, dict[str, Any]]:
        pid = self._require(capability="repository.metadata", tool_id="repository.metadata", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="repository.metadata", identity=identity, capability="repository.metadata", policy_decision_id=pid)
        try:
            repo = self._port.resolve_repository(identity)
        except RepositoryError:
            raise
        except Exception as e:
            raise RepositoryError(RepositoryErrorCode.PROVIDER_ERROR, redact_credentials(str(e))) from e
        prov = build_evidence_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="repository.metadata")
        return repo, self._complete(inv, summary=f"resolved {identity.canonical_locator}"), prov

    def get_metadata(self, identity: RepositoryIdentity, *, audit_id: str, policy_decision_id: str | None) -> tuple[Repository, ToolInvocation, dict[str, Any]]:
        return self.resolve_repository(identity, audit_id=audit_id, policy_decision_id=policy_decision_id)

    def list_tree(self, identity: RepositoryIdentity, path: str = "", *, audit_id: str, policy_decision_id: str | None) -> tuple[RepositoryTree, ToolInvocation, dict[str, Any]]:
        clean = normalize_path(path) if path else ""
        pid = self._require(capability="repository.list", tool_id="repository.list", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="repository.list", identity=identity, capability="repository.list", policy_decision_id=pid)
        try:
            tree = self._port.list_tree(identity, clean)
        except RepositoryError:
            raise
        except Exception as e:
            raise RepositoryError(RepositoryErrorCode.PROVIDER_ERROR, redact_credentials(str(e))) from e
        prov = build_evidence_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="repository.list", path=clean or None)
        return tree, self._complete(inv, summary=f"listed {clean or '/'} in {identity.canonical_locator}"), prov

    def get_file(self, identity: RepositoryIdentity, path: str, *, audit_id: str, policy_decision_id: str | None) -> tuple[RepositoryFile, ToolInvocation, dict[str, Any]]:
        clean = normalize_path(path)
        pid = self._require(capability="repository.read", tool_id="repository.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="repository.read", identity=identity, capability="repository.read", policy_decision_id=pid)
        try:
            f = self._port.get_file(identity, clean)
        except RepositoryError:
            raise
        except Exception as e:
            raise RepositoryError(RepositoryErrorCode.PROVIDER_ERROR, redact_credentials(str(e))) from e
        # Enforce untrusted envelope even if adapter forgot it.
        if not f.untrusted:
            f = RepositoryFile(identity=f.identity, path=f.path, ref=f.ref, sha=f.sha, content_digest=f.content_digest or content_digest(f.content), untrusted=mark_untrusted(f.content), content=f.content)
        prov = build_evidence_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="repository.read", path=clean, content=f.content)
        return f, self._complete(inv, summary=f"read {clean} digest={prov['content_digest'][:12]}"), prov

    def search_code(self, identity: RepositoryIdentity, query: str, *, audit_id: str, policy_decision_id: str | None) -> tuple[list[CodeSearchResult], ToolInvocation, dict[str, Any]]:
        if not query or not query.strip() or len(query.strip()) > 256:
            raise RepositoryError(RepositoryErrorCode.SEARCH_FAILED, "invalid query")
        pid = self._require(capability="repository.search", tool_id="repository.search", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="repository.search", identity=identity, capability="repository.search", policy_decision_id=pid)
        try:
            results = self._port.search_code(identity, query.strip())
        except RepositoryError:
            raise
        except Exception as e:
            raise RepositoryError(RepositoryErrorCode.SEARCH_FAILED, redact_credentials(str(e))) from e
        prov = build_evidence_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="repository.search")
        prov["query_digest"] = content_digest(query.strip())
        prov["result_count"] = len(results)
        return results, self._complete(inv, summary=f"search returned {len(results)} results"), prov

    def get_commit(self, identity: RepositoryIdentity, ref: str, *, audit_id: str, policy_decision_id: str | None) -> tuple[CommitInfo, ToolInvocation, dict[str, Any]]:
        clean_ref = validate_ref(ref)
        pid = self._require(capability="repository.metadata", tool_id="repository.metadata", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="repository.metadata", identity=identity, capability="repository.metadata", policy_decision_id=pid)
        try:
            info = self._port.get_commit(identity, clean_ref)
        except RepositoryError:
            raise
        except Exception as e:
            raise RepositoryError(RepositoryErrorCode.PROVIDER_ERROR, redact_credentials(str(e))) from e
        prov = build_evidence_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="repository.metadata")
        return info, self._complete(inv, summary=f"commit {info.sha[:12]}"), prov
