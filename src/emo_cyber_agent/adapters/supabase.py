"""Supabase read-only adapter behind SupabasePort — ECA-T006.

Fetch → map → return. No severity, no classification, no permission logic,
no write/mutation operations (none exist in this module by design).

Transport-agnostic: works with Supabase API, CLI output, or an MCP bridge —
the caller injects `transport(endpoint, params) -> dict`. Core never sees
transport concepts; only normalized models cross the boundary.

Credential boundary: accepts `service_ref` (a reference NAME such as an env
var name), never a raw key/token, and refuses secret-looking values.
"""

from __future__ import annotations

from typing import Any, Callable

from emo_cyber_agent.core.repository import content_digest, mark_untrusted
from emo_cyber_agent.core.supabase import (
    DatabaseColumn,
    DatabaseConstraint,
    DatabaseFunction,
    DatabaseGrant,
    DatabaseIndex,
    DatabaseRole,
    DatabaseSchema,
    DatabaseTable,
    DatabaseView,
    RLSPolicy,
    RLSStatus,
    SupabaseError,
    SupabaseErrorCode,
    SupabasePort,
    SupabaseProject,
    SupabaseProjectIdentity,
    classify_read_only_sql,
    redact_supabase_secrets,
)

Transport = Callable[[str, dict[str, Any]], dict[str, Any]]

_STATUS_MAP = {
    404: SupabaseErrorCode.OBJECT_NOT_FOUND,
    401: SupabaseErrorCode.AUTH_FAILED,
    403: SupabaseErrorCode.ACCESS_DENIED,
    429: SupabaseErrorCode.RATE_LIMITED,
}


class SupabaseAdapter(SupabasePort):
    """Read-only adapter. `service_ref` is a reference, never a secret."""

    def __init__(self, *, service_ref: str | None = None, transport: Transport | None = None):
        if service_ref and len(service_ref) > 128:
            raise ValueError("service_ref must be a reference name, not a secret value")
        if service_ref and any(s in service_ref for s in ("sb_secret_", "eyJ", "ghp_", "service_role:")):
            raise ValueError("service_ref must be a reference name, never a raw secret")
        self._service_ref = service_ref
        self._transport = transport or self._missing_transport

    @staticmethod
    def _missing_transport(endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        raise SupabaseError(SupabaseErrorCode.PROVIDER_ERROR, "no transport configured (offline)")

    def _call(self, endpoint: str, params: dict[str, Any], *, what: str) -> dict[str, Any]:
        try:
            raw = self._transport(endpoint, params)
        except SupabaseError:
            raise
        except Exception as e:
            raise SupabaseError(SupabaseErrorCode.PROVIDER_ERROR, redact_supabase_secrets(str(e))) from e
        if not isinstance(raw, dict):
            raise SupabaseError(SupabaseErrorCode.PROVIDER_ERROR, f"bad {what} payload")
        status = raw.get("_status", 200)
        if status != 200:
            code = _STATUS_MAP.get(status, SupabaseErrorCode.PROVIDER_ERROR)
            raise SupabaseError(code, redact_supabase_secrets(f"{what} failed ({status})"))
        return raw

    def _check(self, identity: SupabaseProjectIdentity) -> None:
        if identity.provider != "supabase":
            raise SupabaseError(SupabaseErrorCode.PROJECT_NOT_FOUND, "not a supabase identity")

    # -- port --
    def get_project_identity(self, identity: SupabaseProjectIdentity) -> SupabaseProject:
        self._check(identity)
        body = self._call("project.get", {"ref": identity.project_ref}, what="project")
        return SupabaseProject(
            identity=identity,
            name=redact_supabase_secrets(str(body.get("name", "")))[:120],
            region=str(body.get("region", ""))[:40],
            status=str(body.get("status", ""))[:40],
        )

    def get_database_metadata(self, identity: SupabaseProjectIdentity) -> dict[str, Any]:
        self._check(identity)
        body = self._call("db.metadata", {"ref": identity.project_ref}, what="metadata")
        return {"postgres_version": str(body.get("postgres_version", "")), "schemas": list(body.get("schemas", ["public"]))}

    def list_schemas(self, identity: SupabaseProjectIdentity) -> list[DatabaseSchema]:
        self._check(identity)
        body = self._call("db.schemas", {"ref": identity.project_ref}, what="schemas")
        return [DatabaseSchema(identity=identity, name=str(s)) for s in body.get("schemas", ["public"])]

    def list_tables(self, identity: SupabaseProjectIdentity, schema: str = "public") -> list[DatabaseTable]:
        self._check(identity)
        body = self._call("db.tables", {"ref": identity.project_ref, "schema": schema}, what="tables")
        out = []
        for t in body.get("tables", []):
            name = str(t.get("name", "")) if isinstance(t, dict) else str(t)
            comment = redact_supabase_secrets(str(t.get("comment", ""))) if isinstance(t, dict) else ""
            out.append(DatabaseTable(identity=identity, db_schema=schema, name=name, comment_untrusted=mark_untrusted(comment) if comment else {}))
        return out

    def describe_table(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> DatabaseTable:
        tables = self.list_tables(identity, schema)
        for t in tables:
            if t.name == table:
                return t
        raise SupabaseError(SupabaseErrorCode.OBJECT_NOT_FOUND, f"no such table: {table}")

    def list_columns(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[DatabaseColumn]:
        self._check(identity)
        body = self._call("db.columns", {"ref": identity.project_ref, "schema": schema, "table": table}, what="columns")
        return [
            DatabaseColumn(identity=identity, db_schema=schema, table=table, name=str(c.get("name", "")), data_type=str(c.get("type", "")), nullable=bool(c.get("nullable", True)))
            for c in body.get("columns", [])
        ]

    def list_constraints(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[DatabaseConstraint]:
        self._check(identity)
        body = self._call("db.constraints", {"ref": identity.project_ref, "schema": schema, "table": table}, what="constraints")
        return [
            DatabaseConstraint(identity=identity, db_schema=schema, table=table, name=str(c.get("name", "")), kind=str(c.get("kind", "")), definition_digest=content_digest(redact_supabase_secrets(str(c.get("definition", "")))))
            for c in body.get("constraints", [])
        ]

    def list_indexes(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[DatabaseIndex]:
        self._check(identity)
        body = self._call("db.indexes", {"ref": identity.project_ref, "schema": schema, "table": table}, what="indexes")
        return [
            DatabaseIndex(identity=identity, db_schema=schema, table=table, name=str(i.get("name", "")), definition_digest=content_digest(redact_supabase_secrets(str(i.get("definition", "")))))
            for i in body.get("indexes", [])
        ]

    def list_views(self, identity: SupabaseProjectIdentity, schema: str = "public") -> list[DatabaseView]:
        self._check(identity)
        body = self._call("db.views", {"ref": identity.project_ref, "schema": schema}, what="views")
        out = []
        for v in body.get("views", []):
            ddl = redact_supabase_secrets(str(v.get("definition", "")))
            sec = v.get("security", {}) if isinstance(v.get("security"), dict) else {}
            out.append(
                DatabaseView(
                    identity=identity,
                    db_schema=schema,
                    name=str(v.get("name", "")),
                    definition_digest=content_digest(ddl),
                    definition_untrusted=mark_untrusted(ddl) if ddl else {},
                    security_metadata={k: redact_supabase_secrets(str(val))[:200] for k, val in sec.items()},
                )
            )
        return out

    def list_functions(self, identity: SupabaseProjectIdentity, schema: str = "public") -> list[DatabaseFunction]:
        self._check(identity)
        body = self._call("db.functions", {"ref": identity.project_ref, "schema": schema}, what="functions")
        out = []
        for f in body.get("functions", []):
            src = redact_supabase_secrets(str(f.get("body", "")))
            out.append(
                DatabaseFunction(
                    identity=identity,
                    db_schema=schema,
                    name=str(f.get("name", "")),
                    language=str(f.get("language", ""))[:40],
                    security_definer=f.get("security_definer"),
                    body_digest=content_digest(src),
                    body_untrusted=mark_untrusted(src) if src else {},
                )
            )
        return out

    def list_roles(self, identity: SupabaseProjectIdentity) -> list[DatabaseRole]:
        self._check(identity)
        body = self._call("db.roles", {"ref": identity.project_ref}, what="roles")
        return [DatabaseRole(identity=identity, name=redact_supabase_secrets(str(r if isinstance(r, str) else r.get("name", "")))[:80]) for r in body.get("roles", [])]

    def list_grants(self, identity: SupabaseProjectIdentity) -> list[DatabaseGrant]:
        self._check(identity)
        body = self._call("db.grants", {"ref": identity.project_ref}, what="grants")
        out = []
        for g in body.get("grants", []):
            out.append(
                DatabaseGrant(
                    identity=identity,
                    role=redact_supabase_secrets(str(g.get("role", "")))[:80],
                    object_schema=str(g.get("schema", ""))[:80],
                    object_name=str(g.get("object", ""))[:120],
                    object_type=str(g.get("object_type", ""))[:40],
                    privilege=str(g.get("privilege", ""))[:40],
                    grantor=redact_supabase_secrets(str(g.get("grantor", "")))[:80],
                )
            )
        return out

    def list_rls_policies(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> list[RLSPolicy]:
        self._check(identity)
        body = self._call("db.policies", {"ref": identity.project_ref, "schema": schema, "table": table}, what="policies")
        out = []
        for p in body.get("policies", []):
            using = redact_supabase_secrets(str(p.get("using", "")))
            check = redact_supabase_secrets(str(p.get("with_check", "")))
            out.append(
                RLSPolicy(
                    identity=identity,
                    db_schema=schema,
                    table=table,
                    name=str(p.get("name", ""))[:120],
                    command=str(p.get("command", ""))[:20],
                    roles=tuple(redact_supabase_secrets(str(r))[:80] for r in p.get("roles", [])),
                    using_digest=content_digest(using),
                    with_check_digest=content_digest(check) if check else "",
                    using_untrusted=mark_untrusted(using),
                    with_check_untrusted=mark_untrusted(check) if check else {},
                    provider_metadata={"source": "supabase-adapter"},
                )
            )
        return out

    def get_rls_status(self, identity: SupabaseProjectIdentity, schema: str, table: str) -> RLSStatus:
        self._check(identity)
        body = self._call("db.rls_status", {"ref": identity.project_ref, "schema": schema, "table": table}, what="rls")
        return RLSStatus(identity=identity, db_schema=schema, table=table, enabled=bool(body.get("enabled", False)), force_row_level_security=bool(body.get("force", False)))

    def execute_read_sql(self, identity: SupabaseProjectIdentity, sql: str) -> dict[str, Any]:
        self._check(identity)
        classify_read_only_sql(sql)  # deny before transport
        body = self._call("db.sql", {"ref": identity.project_ref, "sql_digest": content_digest(sql)}, what="sql")
        return {"rows": [], "row_count": 0, "query_digest": content_digest(sql), "note": redact_supabase_secrets(str(body.get("note", "read-only")))}
