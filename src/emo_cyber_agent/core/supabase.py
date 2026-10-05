"""Core Supabase Port — ECA-T006 (read-only FACT collection).

Mandatory path:
Request → Core → ToolRegistry → PolicyEngine → Supabase ToolInvocation
→ SupabasePort → Supabase Adapter → External Supabase → Normalized Result
→ Evidence → Core

Rules:
- Supabase is an external resource provider, NOT Core/Policy/Agent.
- READ-ONLY ONLY. No write/mutation methods exist in this module.
- project_ref is mandatory in every operation; cross-project = DENY.
- Capabilities are fine-grained (no supabase.admin).
- SQL path (if used) is single-statement SELECT/WITH only; anything
  uncertain → DENY. Never rely on model classification.
- Secrets are never stored in invocations, evidence, logs, or errors.
- All database text (names, comments, bodies, expressions, SQL) is
  UNTRUSTED DATA and can never become instructions.
- Normalized models are transport-agnostic (API/CLI/MCP-bridge all map here).
- Snapshot sections carry their own timestamps; mixed times are recorded
  explicitly, never silently merged.
- ECA-T006 collects FACTS. It issues no severity/CWE/OWASP findings.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from emo_cyber_agent.core.repository import (  # single source for shared guards
    content_digest,
    redact_credentials as _redact_repo,
)
from emo_cyber_agent.core.tool_registry import ToolInvocation, ToolRegistry, ToolSpec

POLICY_VERSION = "eca-t006-v1"
SCHEMA_VERSION = "0.1.0"
SOURCE_PROVIDER = "supabase"

SUPABASE_CAPABILITIES: tuple[str, ...] = (
    "supabase.project.read",
    "supabase.schema.read",
    "supabase.table.read",
    "supabase.policy.read",
    "supabase.grant.read",
    "supabase.function.read",
    "supabase.view.read",
)

_REF_RE = re.compile(r"^[a-z0-9]{20}$")
_ENV_RE = re.compile(r"^(prod|staging|dev|test)$")

_EXTRA_SECRET_PATTERNS = (
    re.compile(r"(?i)(sb_secret_[A-Za-z0-9_\-]+)"),
    re.compile(r"(?i)(sb_publishable_[A-Za-z0-9_\-]+)"),
    re.compile(r"(?i)(service_role\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/=]{8,})"),
    re.compile(r"(?i)(postgres(ql)?://[^\s'\"]+)"),
)


class SupabaseErrorCode(StrEnum):
    PROJECT_NOT_FOUND = "SUPABASE_PROJECT_NOT_FOUND"
    ACCESS_DENIED = "SUPABASE_ACCESS_DENIED"
    OUT_OF_SCOPE = "SUPABASE_OUT_OF_SCOPE"
    AUTH_FAILED = "SUPABASE_AUTH_FAILED"
    RATE_LIMITED = "SUPABASE_RATE_LIMITED"
    OBJECT_NOT_FOUND = "SUPABASE_OBJECT_NOT_FOUND"
    QUERY_REJECTED = "SUPABASE_QUERY_REJECTED"
    READ_ONLY_VIOLATION = "SUPABASE_READ_ONLY_VIOLATION"
    PROVIDER_ERROR = "SUPABASE_PROVIDER_ERROR"
    SCHEMA_UNAVAILABLE = "SUPABASE_SCHEMA_UNAVAILABLE"
    POLICY_UNAVAILABLE = "SUPABASE_POLICY_UNAVAILABLE"
    AMBIGUOUS_IDENTITY = "SUPABASE_AMBIGUOUS_IDENTITY"
    MISMATCHED_AUDIT = "SUPABASE_MISMATCHED_AUDIT"
    POLICY_DENIED = "SUPABASE_POLICY_DENIED"


class SupabaseError(Exception):
    def __init__(self, code: SupabaseErrorCode, message: str, *, safe_details: dict[str, Any] | None = None):
        super().__init__(f"{code.value}: {redact_supabase_secrets(message)}")
        self.code = code
        self.safe_details = safe_details or {}


def redact_supabase_secrets(text: str) -> str:
    redacted = _redact_repo(text)
    for pattern in _EXTRA_SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SUPABASE_SECRET]", redacted)
    return redacted


# ---------------------------------------------------------------------------
# Identity & scope
# ---------------------------------------------------------------------------

class SupabaseProjectIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    project_ref: str = Field(..., min_length=1)
    provider: str = Field(default="supabase")
    environment: str = Field(default="prod")

    @field_validator("provider")
    @classmethod
    def _provider(cls, v: str) -> str:
        if v.strip().lower() != "supabase":
            raise ValueError("provider must be supabase")
        return "supabase"

    @field_validator("project_ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        vv = v.strip()
        if not _REF_RE.match(vv):
            raise ValueError("project_ref must be 20 lowercase alphanumerics")
        return vv

    @field_validator("environment")
    @classmethod
    def _env(cls, v: str) -> str:
        vv = v.strip().lower()
        if not _ENV_RE.match(vv):
            raise ValueError("unknown environment")
        return vv

    @property
    def canonical_locator(self) -> str:
        return f"supabase:{self.project_ref}:{self.environment}"


def parse_supabase_locator(locator: str) -> SupabaseProjectIdentity:
    """Parse 'supabase:<20-char-ref>[:env]'. Name-only or ref-less → ambiguous."""
    if not locator or not locator.strip():
        raise SupabaseError(SupabaseErrorCode.AMBIGUOUS_IDENTITY, "empty locator")
    loc = locator.strip()
    parts = loc.split(":")
    if len(parts) not in (2, 3) or parts[0].lower() != "supabase":
        raise SupabaseError(SupabaseErrorCode.AMBIGUOUS_IDENTITY, f"locator must be supabase:<ref>[:env], got: {loc[:60]}")
    ref = parts[1]
    env = parts[2] if len(parts) == 3 else "prod"
    try:
        return SupabaseProjectIdentity(project_ref=ref, environment=env)
    except ValueError as e:
        raise SupabaseError(SupabaseErrorCode.AMBIGUOUS_IDENTITY, f"invalid locator: {loc[:60]}") from e


class AuditSupabaseScope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str = Field(..., min_length=1)
    project_id: str = Field(..., min_length=1)
    allowed_refs: tuple[str, ...] = Field(default_factory=tuple)

    def allows(self, identity: SupabaseProjectIdentity) -> bool:
        return identity.project_ref in self.allowed_refs


def assert_supabase_in_scope(scope: AuditSupabaseScope, identity: SupabaseProjectIdentity, *, audit_id: str) -> None:
    if audit_id != scope.audit_id:
        raise SupabaseError(SupabaseErrorCode.MISMATCHED_AUDIT, "audit_id mismatch")
    if not scope.allows(identity):
        raise SupabaseError(
            SupabaseErrorCode.OUT_OF_SCOPE,
            f"project not in scope: {identity.canonical_locator}",
            safe_details={"canonical": identity.canonical_locator},
        )


# ---------------------------------------------------------------------------
# Normalized models (transport-agnostic facts, no verdicts)
# ---------------------------------------------------------------------------

class SupabaseProject(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    name: str = ""
    region: str = ""
    status: str = ""


class DatabaseSchema(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    name: str


class DatabaseTable(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    name: str
    comment_untrusted: dict[str, Any] = Field(default_factory=dict)


class DatabaseColumn(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    table: str
    name: str
    data_type: str = ""
    nullable: bool = True
    default_digest: str = ""


class DatabaseConstraint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    table: str
    name: str
    kind: str = ""
    definition_digest: str = ""


class DatabaseIndex(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    table: str
    name: str
    definition_digest: str = ""


class DatabaseView(BaseModel):
    """Views are independent of table RLS; always inspected separately."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    name: str
    definition_digest: str = ""
    definition_untrusted: dict[str, Any] = Field(default_factory=dict)
    security_metadata: dict[str, Any] = Field(default_factory=dict)


class DatabaseFunction(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    name: str
    language: str = ""
    security_definer: bool | None = None
    body_digest: str = ""
    body_untrusted: dict[str, Any] = Field(default_factory=dict)


class DatabaseRole(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    name: str


class DatabaseGrant(BaseModel):
    """A GRANT fact. Presence of grants is independent of RLS policies."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    role: str
    object_schema: str = ""
    object_name: str = ""
    object_type: str = ""
    privilege: str = ""
    grantor: str = ""


class RLSPolicy(BaseModel):
    """One RLS policy fact. Existence ≠ safety (see grants + enablement)."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    table: str
    name: str
    command: str = ""  # SELECT | INSERT | UPDATE | DELETE | ALL
    roles: tuple[str, ...] = ()
    using_digest: str = ""
    with_check_digest: str = ""
    using_untrusted: dict[str, Any] = Field(default_factory=dict)
    with_check_untrusted: dict[str, Any] = Field(default_factory=dict)
    provider_metadata: dict[str, Any] = Field(default_factory=dict)


class RLSStatus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    db_schema: str
    table: str
    enabled: bool = False
    force_row_level_security: bool = False


class SnapshotContext(BaseModel):
    """Unified snapshot note: sections carry own timestamps; drift is explicit."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    identity: SupabaseProjectIdentity
    collected_at: dict[str, str] = Field(default_factory=dict)
    consistent: bool = True
    note: str = ""


# ---------------------------------------------------------------------------
# Read-only SQL safety (deny-on-uncertainty, never model-classified)
# ---------------------------------------------------------------------------

_FORBIDDEN_SQL = (
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "GRANT", "REVOKE", "COPY", "VACUUM", "CALL", "DO", "EXECUTE",
)
_ALLOWED_FIRST = ("SELECT", "WITH", "EXPLAIN", "SHOW", "TABLE", "VALUES")


def classify_read_only_sql(sql: str) -> str:
    """Return 'allow' only for a single SELECT/WITH-family statement.

    Denies: empty input, multi-statements, non-read first keyword, or any
    forbidden keyword as a whole word anywhere (deny-on-uncertainty,
    including inside comments — a disguised DROP is still DROP).
    """
    if not sql or not sql.strip():
        raise SupabaseError(SupabaseErrorCode.QUERY_REJECTED, "empty sql")
    text = sql.strip()
    # multi-statement: more than one semicolon, or a non-trailing one
    semis = text.count(";")
    if semis > 1 or (semis == 1 and not text.endswith(";")):
        raise SupabaseError(SupabaseErrorCode.QUERY_REJECTED, "multi-statement denied")
    upper = text.upper()
    for word in _FORBIDDEN_SQL:
        if re.search(rf"\b{word}\b", upper):
            raise SupabaseError(SupabaseErrorCode.READ_ONLY_VIOLATION, f"forbidden statement: {word}")
    first = re.split(r"\s+|\(", upper.lstrip(" (;"), maxsplit=1)[0] if upper.strip() else ""
    first = first.strip(" (")
    if first not in _ALLOWED_FIRST:
        raise SupabaseError(SupabaseErrorCode.QUERY_REJECTED, f"not a read statement: {first[:20]}")
    return "allow"


# ---------------------------------------------------------------------------
# Port
# ---------------------------------------------------------------------------

class SupabasePort(ABC):
    """Read-only application port. No write/mutation methods may be added."""

    @abstractmethod
    def get_project_identity(self, identity: SupabaseProjectIdentity) -> SupabaseProject: ...
    @abstractmethod
    def get_database_metadata(self, identity: SupabaseProjectIdentity) -> dict[str, Any]: ...
    @abstractmethod
    def list_schemas(self, identity: SupabaseProjectIdentity) -> list[DatabaseSchema]: ...
    @abstractmethod
    def list_tables(self, identity: SupabaseProjectIdentity, schema: str = "public") -> list[DatabaseTable]: ...
    @abstractmethod
    def describe_table(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> DatabaseTable: ...
    @abstractmethod
    def list_columns(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[DatabaseColumn]: ...
    @abstractmethod
    def list_constraints(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[DatabaseConstraint]: ...
    @abstractmethod
    def list_indexes(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[DatabaseIndex]: ...
    @abstractmethod
    def list_views(self, identity: SupabaseProjectIdentity, schema: str = "public") -> list[DatabaseView]: ...
    @abstractmethod
    def list_functions(self, identity: SupabaseProjectIdentity, schema: str = "public") -> list[DatabaseFunction]: ...
    @abstractmethod
    def list_roles(self, identity: SupabaseProjectIdentity) -> list[DatabaseRole]: ...
    @abstractmethod
    def list_grants(self, identity: SupabaseProjectIdentity) -> list[DatabaseGrant]: ...
    @abstractmethod
    def list_rls_policies(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[RLSPolicy]: ...
    @abstractmethod
    def get_rls_status(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> RLSStatus: ...
    @abstractmethod
    def execute_read_sql(self, identity: SupabaseProjectIdentity, sql: str) -> dict[str, Any]: ...


def get_supabase_tool_specs() -> list[ToolSpec]:
    base = dict(
        version="1.0.0",
        description="Read-only Supabase operation",
        category="database",
        risk_level="low",
        supports_read_only=True,
        supports_verification=False,
        supports_remediation=False,
        target_types=("supabase-project",),
        evidence_behavior="summarize",
        timeout_ms=30000,
    )
    return [
        ToolSpec(tool_id="supabase.project.read", name="Supabase Project Read", capabilities_required=("supabase.project.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="supabase.schema.read", name="Supabase Schema Read", capabilities_required=("supabase.schema.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="supabase.table.read", name="Supabase Table Read", capabilities_required=("supabase.table.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="supabase.policy.read", name="Supabase Policy Read", capabilities_required=("supabase.policy.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="supabase.grant.read", name="Supabase Grant Read", capabilities_required=("supabase.grant.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="supabase.function.read", name="Supabase Function Read", capabilities_required=("supabase.function.read",), **base),  # type: ignore[arg-type]
        ToolSpec(tool_id="supabase.view.read", name="Supabase View Read", capabilities_required=("supabase.view.read",), **base),  # type: ignore[arg-type]
    ]


def build_supabase_provenance(
    *,
    identity: SupabaseProjectIdentity,
    invocation_id: str,
    tool_id: str,
    tool_version: str = "1.0.0",
    object_identity: str | None = None,
    content: str | None = None,
    snapshot: SnapshotContext | None = None,
) -> dict[str, Any]:
    from datetime import timezone as _tz

    prov: dict[str, Any] = {
        "source_provider": SOURCE_PROVIDER,
        "project_ref": identity.project_ref,
        "environment": identity.environment,
        "canonical_locator": identity.canonical_locator,
        "invocation_id": invocation_id,
        "tool_id": tool_id,
        "tool_version": tool_version,
        "collected_at": datetime.now(_tz.utc).isoformat(),
        "policy_version": POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
    }
    if object_identity:
        prov["object_identity"] = object_identity
    if content is not None:
        prov["content_digest"] = content_digest(content)
    if snapshot is not None:
        prov["snapshot"] = snapshot.model_dump()
    return prov


class SupabaseService:
    """Core-owned orchestration: scope → registry → policy → port → evidence."""

    def __init__(self, *, port: SupabasePort, policy_engine: Any, registry: ToolRegistry, scope: AuditSupabaseScope, profile: str = "read_only"):
        self._port = port
        self._policy = policy_engine
        self._registry = registry
        self._scope = scope
        self._profile = profile

    def _require(self, *, capability: str, tool_id: str, identity: SupabaseProjectIdentity, audit_id: str, policy_decision_id: str | None) -> str:
        from emo_cyber_agent.core.repository import content_digest as _cd  # noqa: F401 (kept local to avoid cycles at import time)

        assert_supabase_in_scope(self._scope, identity, audit_id=audit_id)
        try:
            spec = self._registry.get(tool_id)
        except ValueError as e:
            raise SupabaseError(SupabaseErrorCode.POLICY_DENIED, f"unknown tool: {tool_id}") from e
        if capability not in spec.capabilities_required:
            raise SupabaseError(SupabaseErrorCode.POLICY_DENIED, f"undeclared capability: {capability} for {tool_id}")
        if capability == "supabase.admin" or "admin" in capability:
            raise SupabaseError(SupabaseErrorCode.POLICY_DENIED, "generic admin capability denied")
        if self._profile != "read_only":
            raise SupabaseError(SupabaseErrorCode.POLICY_DENIED, f"unsupported profile in ECA-T006: {self._profile}")
        if not policy_decision_id:
            raise SupabaseError(SupabaseErrorCode.POLICY_DENIED, "missing policy_decision_id")
        allowed = self._policy.evaluate_policy(audit_id, tool_id, identity.canonical_locator, self._profile, [capability])
        if not allowed:
            raise SupabaseError(SupabaseErrorCode.POLICY_DENIED, f"policy denied {tool_id}:{capability}")
        return policy_decision_id

    def _invocation(self, *, audit_id: str, tool_id: str, identity: SupabaseProjectIdentity, capability: str, policy_decision_id: str) -> ToolInvocation:
        from emo_cyber_agent.core import tool_registry as _tr

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
        inv = inv.transition_to(_tr.ToolInvocationStatus.VALIDATING)
        inv = inv.transition_to(_tr.ToolInvocationStatus.POLICY_CHECK)
        inv = inv.transition_to(_tr.ToolInvocationStatus.APPROVED)
        inv = inv.transition_to(_tr.ToolInvocationStatus.EXECUTING)
        return inv

    def _complete(self, inv: ToolInvocation, *, summary: str) -> ToolInvocation:
        from emo_cyber_agent.core.repository import redact_credentials as _rc

        return inv.update_output(_rc(summary))

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except SupabaseError:
            raise
        except Exception as e:
            raise SupabaseError(SupabaseErrorCode.PROVIDER_ERROR, redact_supabase_secrets(str(e))) from e

    # ---- read operations ----
    def get_project_identity(self, identity: SupabaseProjectIdentity, *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.project.read", tool_id="supabase.project.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.project.read", identity=identity, capability="supabase.project.read", policy_decision_id=pid)
        proj = self._call(self._port.get_project_identity, identity)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.project.read", object_identity=f"project:{identity.project_ref}")
        return proj, self._complete(inv, summary=f"project {identity.project_ref}"), prov

    def list_tables(self, identity: SupabaseProjectIdentity, schema: str = "public", *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.table.read", tool_id="supabase.table.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.table.read", identity=identity, capability="supabase.table.read", policy_decision_id=pid)
        tables = self._call(self._port.list_tables, identity, schema)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.table.read", object_identity=f"schema:{schema}")
        prov["result_count"] = len(tables)
        return tables, self._complete(inv, summary=f"tables in {schema}: {len(tables)}"), prov

    def list_rls_policies(self, identity: SupabaseProjectIdentity, schema: str, table: str, *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.policy.read", tool_id="supabase.policy.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.policy.read", identity=identity, capability="supabase.policy.read", policy_decision_id=pid)
        policies = self._call(self._port.list_rls_policies, identity, schema, table)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.policy.read", object_identity=f"table:{schema}.{table}")
        prov["result_count"] = len(policies)
        return policies, self._complete(inv, summary=f"policies on {schema}.{table}: {len(policies)}"), prov

    def get_rls_status(self, identity: SupabaseProjectIdentity, schema: str, table: str, *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.policy.read", tool_id="supabase.policy.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.policy.read", identity=identity, capability="supabase.policy.read", policy_decision_id=pid)
        status = self._call(self._port.get_rls_status, identity, schema, table)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.policy.read", object_identity=f"rls:{schema}.{table}")
        return status, self._complete(inv, summary=f"rls enabled={status.enabled}"), prov

    def list_grants(self, identity: SupabaseProjectIdentity, *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.grant.read", tool_id="supabase.grant.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.grant.read", identity=identity, capability="supabase.grant.read", policy_decision_id=pid)
        grants = self._call(self._port.list_grants, identity)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.grant.read")
        prov["result_count"] = len(grants)
        return grants, self._complete(inv, summary=f"grants: {len(grants)}"), prov

    def list_views(self, identity: SupabaseProjectIdentity, schema: str = "public", *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.view.read", tool_id="supabase.view.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.view.read", identity=identity, capability="supabase.view.read", policy_decision_id=pid)
        views = self._call(self._port.list_views, identity, schema)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.view.read", object_identity=f"schema:{schema}")
        return views, self._complete(inv, summary=f"views in {schema}: {len(views)}"), prov

    def list_functions(self, identity: SupabaseProjectIdentity, schema: str = "public", *, audit_id: str, policy_decision_id: str | None):
        pid = self._require(capability="supabase.function.read", tool_id="supabase.function.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.function.read", identity=identity, capability="supabase.function.read", policy_decision_id=pid)
        funcs = self._call(self._port.list_functions, identity, schema)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.function.read", object_identity=f"schema:{schema}")
        return funcs, self._complete(inv, summary=f"functions in {schema}: {len(funcs)}"), prov

    def execute_read_sql(self, identity: SupabaseProjectIdentity, sql: str, *, audit_id: str, policy_decision_id: str | None):
        classify_read_only_sql(sql)  # DENY before any policy/invocation work
        pid = self._require(capability="supabase.schema.read", tool_id="supabase.schema.read", identity=identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        inv = self._invocation(audit_id=audit_id, tool_id="supabase.schema.read", identity=identity, capability="supabase.schema.read", policy_decision_id=pid)
        result = self._call(self._port.execute_read_sql, identity, sql)
        prov = build_supabase_provenance(identity=identity, invocation_id=inv.invocation_id, tool_id="supabase.schema.read", content=sql)
        return result, self._complete(inv, summary="read-only sql executed"), prov

    def collect_snapshot(self, identity: SupabaseProjectIdentity, schema: str, table: str, *, audit_id: str, policy_decision_id: str | None) -> tuple[dict[str, Any], ToolInvocation, dict[str, Any]]:
        """Collect tables+RLS+grants with explicit per-section timestamps.

        Mixed collection times are recorded, never silently merged.
        """
        from datetime import timezone as _tz

        stamps: dict[str, str] = {}
        tables, inv_t, _ = self.list_tables(identity, schema, audit_id=audit_id, policy_decision_id=policy_decision_id)
        stamps["tables"] = datetime.now(_tz.utc).isoformat()
        status, _, _ = self.get_rls_status(identity, schema, table, audit_id=audit_id, policy_decision_id=policy_decision_id)
        stamps["rls"] = datetime.now(_tz.utc).isoformat()
        grants, _, _ = self.list_grants(identity, audit_id=audit_id, policy_decision_id=policy_decision_id)
        stamps["grants"] = datetime.now(_tz.utc).isoformat()
        snapshot = SnapshotContext(identity=identity, collected_at=stamps, consistent=True, note="sections collected in one snapshot call; per-section times recorded")
        prov = build_supabase_provenance(identity=identity, invocation_id=inv_t.invocation_id, tool_id="supabase.table.read", snapshot=snapshot)
        return {"tables": tables, "rls": status, "grants": grants, "snapshot": snapshot}, inv_t, prov
