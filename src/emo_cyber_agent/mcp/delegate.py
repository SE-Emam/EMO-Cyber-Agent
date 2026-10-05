"""MCP → Core delegation — ECA-T013.

Translate → validate interface shape → delegate to Core services →
serialize → map errors. No policy, severity, verification, finding, or
execution decisions happen here; every one lives in Core.

Error mapping (Core → MCP tool-result codes):
  INVALID_REQUEST      → INVALID_PARAMS (-32602)
  POLICY_DENIED        → PERMISSION_DENIED (isError result)
  OUT_OF_SCOPE         → PERMISSION_DENIED
  NOT_FOUND            → NOT_FOUND
  TIMEOUT              → TIMEOUT
  SERVICE_UNAVAILABLE  → SERVICE_UNAVAILABLE
  SECURITY_BLOCKED     → SECURITY_BLOCKED
Anything else → INTERNAL_ERROR. No stack traces, no secrets, ever.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from emo_cyber_agent.mcp import protocol as _p
from emo_cyber_agent.mcp.tools import InvalidInput, validate_arguments


def _redact(text: str) -> str:
    from emo_cyber_agent.core.repository import redact_credentials
    from emo_cyber_agent.core.supabase import redact_supabase_secrets

    return redact_supabase_secrets(redact_credentials(text))


def log_event(*, request_id: Any, audit_id: str, tool: str, duration_ms: int, status: str, error_category: str = "") -> None:
    """Sanitized stderr log: ids + tool + timing + outcome only."""
    import sys

    record = {
        "request_id": str(request_id)[:64],
        "audit_id": _redact(audit_id)[:120],
        "tool": _redact(tool)[:40],
        "duration_ms": duration_ms,
        "status": status,
        "error_category": _redact(error_category)[:80],
    }
    print(json.dumps(record, sort_keys=True), file=sys.stderr)


def ok_result(tool: str, audit_id: str, result: dict[str, Any], references: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"status": "ok", "tool": tool, "audit_id": audit_id, "result": result, "references": references or {}}


def error_result(tool: str, audit_id: str, code: str, message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps({"status": "error", "tool": tool, "audit_id": audit_id, "code": code, "message": _redact(message)[:500]}, sort_keys=True)}], "isError": True}


def _auditor():
    from emo_cyber_agent.core.service import FoundationSecurityAuditor

    return FoundationSecurityAuditor()


def _cut(text: str, limit: int = 2000) -> str:
    return _redact(text)[:limit]


def call_audit(args: dict[str, Any]) -> dict[str, Any]:
    auditor = _auditor()
    result = asyncio.run(auditor.audit(target=args["target"], mode=args.get("mode") or "standard", permission_profile="read_only", focus=args.get("focus") or []))
    data = result.model_dump()
    # Output-side redaction is adapter serialization duty: the Core echo of
    # target must never carry credential-looking material to the host.
    return ok_result("cyber_audit", data.get("audit_id", ""), {"audit_id": data.get("audit_id", ""), "status": str(data.get("status", "")), "target": _redact(str(data.get("target", "")))[:512], "mode": data.get("mode", ""), "permission_profile": str(data.get("permission_profile", "")), "findings": [], "limitations": [_redact(str(item))[:300] for item in data.get("limitations", [])]}, {"audit_id": data.get("audit_id", "")})


def call_review(args: dict[str, Any]) -> dict[str, Any]:
    auditor = _auditor()
    result = asyncio.run(auditor.review(target=args["target"], focus=args.get("focus")))
    data = result.model_dump()
    return ok_result("cyber_review", data.get("audit_id", ""), {"audit_id": data.get("audit_id", ""), "status": str(data.get("status", "")), "target": _redact(str(data.get("target", "")))[:512], "findings": [], "evidence_references": []}, {"audit_id": data.get("audit_id", "")})


def call_verify(args: dict[str, Any]) -> dict[str, Any]:
    """Validate → build candidate/request via Core models → plan via
    VerificationService (policy-gated) → return the PLAN. Input is never
    authorization; execution wiring belongs to release integration."""
    from emo_cyber_agent.core.correlation import FindingCandidate
    from emo_cyber_agent.core.policy import StrictPolicyEngine
    from emo_cyber_agent.core.tool_registry import ToolRegistry
    from emo_cyber_agent.core.verification import VerificationRequest, VerificationService, get_verification_tool_specs

    audit_id = args["audit_id"]
    try:
        candidate = FindingCandidate(**args["candidate"])
    except ValueError as e:
        return error_result("cyber_verify", audit_id, _p.DOMAIN_INVALID, f"invalid candidate: {e}")
    if candidate.audit_id != audit_id:
        return error_result("cyber_verify", audit_id, _p.DOMAIN_PERMISSION_DENIED, "candidate audit mismatch")
    try:
        request = VerificationRequest(
            method=args["method"],
            target=args["target"],
            rationale_summary=args["rationale"],
            expected_evidence="",
            statement=args.get("statement", ""),
        )
    except ValueError as e:
        return error_result("cyber_verify", audit_id, _p.DOMAIN_INVALID, f"invalid verification request: {e}")
    registry = ToolRegistry()
    for spec in get_verification_tool_specs():
        registry.register(spec)
    from emo_cyber_agent.core.correlation import EvidenceStore

    service = VerificationService(executor=_approved_only_executor(), policy=StrictPolicyEngine(), registry=registry, store=EvidenceStore(), scope_allows=lambda a, t: a == audit_id and t == args["target"]["locator"])
    try:
        plan = service.plan(candidate=candidate, request=request, audit_id=audit_id)
    except Exception as e:
        return _map_verification_error("cyber_verify", audit_id, e)
    return ok_result(
        "cyber_verify",
        audit_id,
        {"status": "planned", "plan_id": plan.plan_id, "method": request.method.value, "safety_level": plan.safety_level.value, "required_capabilities": list(plan.required_capabilities), "stopping_conditions": list(plan.stopping_conditions), "note": "plan only; execution requires an authorized audit session"},
        {"candidate_id": candidate.candidate_id, "audit_id": audit_id},
    )


class _approved_only_executor:
    """Placeholder harness: verify-via-MCP returns plans, never executes."""

    def run(self, plan: Any) -> Any:
        raise RuntimeError("execution is wired per audit session, not via MCP planning")


def call_report(args: dict[str, Any]) -> dict[str, Any]:
    from emo_cyber_agent.core.findings import SecurityFinding
    from emo_cyber_agent.core.reporting import ReportService

    audit_id = args["audit_id"]
    if not isinstance(args["findings"], list) or len(args["findings"]) > 200:
        return error_result("cyber_report", audit_id, _p.DOMAIN_INVALID, "findings must be a list of at most 200 items")
    try:
        items = [SecurityFinding(**entry) for entry in args["findings"]]
    except ValueError as e:
        return error_result("cyber_report", audit_id, _p.DOMAIN_INVALID, f"invalid finding data: {e}")
    service = ReportService()
    try:
        report = service.generate(audit_id=audit_id, findings=items, include_non_reportable=bool(args.get("include_non_reportable", False)))
    except Exception as e:
        return _map_report_error(audit_id, e)
    fmt = args["format"]
    text = {"json": service.generate_json, "jsonl": service.generate_jsonl, "markdown": service.generate_markdown}[fmt](report)
    if len(text.encode("utf-8")) > 1024 * 1024:
        return error_result("cyber_report", audit_id, _p.DOMAIN_INVALID, "report exceeds 1 MiB; narrow scope")
    return ok_result("cyber_report", audit_id, {"format": fmt, "report": text, "report_version": report.metadata.report_version}, {"audit_id": audit_id})


def call_extensions(args: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only extension view. The adapter translates and projects;
    discovery, validation, trust and resolution stay in the extensions
    layer with code loading disabled."""
    from emo_cyber_agent.extensions import ExtensionError, read_extensions

    action = str(args["action"])
    try:
        body = read_extensions(
            action,
            extension_id=str(args.get("extension_id", "")),
            provide=str(args.get("provide", "")),
        )
    except ExtensionError as e:
        code = getattr(getattr(e, "code", None), "value", str(getattr(e, "code", "")))
        if code in ("EXTENSION_NOT_FOUND", "EXTENSION_VERSION_NOT_FOUND"):
            return error_result("cyber_extensions", "", _p.DOMAIN_NOT_FOUND, str(e))
        if code == "EXTENSION_QUERY_UNKNOWN":
            return error_result("cyber_extensions", "", _p.DOMAIN_INVALID, str(e))
        return error_result("cyber_extensions", "", _p.DOMAIN_INVALID, str(e))
    except Exception:
        return error_result("cyber_extensions", "", "INTERNAL_ERROR", "extension inspection failed")
    return ok_result("cyber_extensions", "", body, {})


def call_status(args: dict[str, Any]) -> dict[str, Any]:
    auditor = _auditor()
    data = asyncio.run(auditor.doctor())
    return ok_result(
        "cyber_status",
        _redact(str(args.get("audit_id", "")))[:120],
        {"status": data.get("status", ""), "version": data.get("version", ""), "policy_engine": data.get("policy_engine", ""), "capabilities": ["cyber_audit", "cyber_review", "cyber_verify", "cyber_report", "cyber_status", "cyber_extensions"]},
        {},
    )


_HANDLERS = {"cyber_audit": call_audit, "cyber_review": call_review, "cyber_verify": call_verify, "cyber_report": call_report, "cyber_status": call_status, "cyber_extensions": call_extensions}


def dispatch(tool_name: str, arguments: Any) -> dict[str, Any]:
    """Validate shape, then delegate. Raises InvalidInput on bad shape."""
    args = validate_arguments(tool_name, arguments)
    handler = _HANDLERS.get(tool_name)
    if handler is None:  # unreachable (validator rejects unknown tools) — defense in depth
        raise InvalidInput(f"unknown tool: {tool_name}")
    started = time.monotonic()
    try:
        return handler(args)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        log_event(request_id="-", audit_id=str(args.get("audit_id", "")), tool=tool_name, duration_ms=duration_ms, status="dispatched")


def _map_verification_error(tool: str, audit_id: str, error: Exception) -> dict[str, Any]:
    from emo_cyber_agent.core.verification import VerificationError, VerificationErrorCode

    if isinstance(error, VerificationError):
        mapping = {
            VerificationErrorCode.POLICY_DENIED: _p.DOMAIN_PERMISSION_DENIED,
            VerificationErrorCode.OUT_OF_SCOPE: _p.DOMAIN_PERMISSION_DENIED,
            VerificationErrorCode.STALE_POLICY: _p.DOMAIN_PERMISSION_DENIED,
            VerificationErrorCode.MISMATCHED_AUDIT: _p.DOMAIN_PERMISSION_DENIED,
            VerificationErrorCode.BUDGET_EXHAUSTED: _p.DOMAIN_TIMEOUT,
            VerificationErrorCode.LOOP_DETECTED: _p.DOMAIN_TIMEOUT,
        }
        return error_result(tool, audit_id, mapping.get(error.code, _p.DOMAIN_INVALID), str(error))
    return error_result(tool, audit_id, "INTERNAL_ERROR", "verification planning failed")


def _map_report_error(audit_id: str, error: Exception) -> dict[str, Any]:
    from emo_cyber_agent.core.reporting import ReportError, ReportErrorCode

    if isinstance(error, ReportError):
        mapping = {
            ReportErrorCode.REPORTABILITY_DENIED: _p.DOMAIN_PERMISSION_DENIED,
            ReportErrorCode.INVALID: _p.DOMAIN_INVALID,
            ReportErrorCode.SCHEMA_ERROR: _p.DOMAIN_INVALID,
            ReportErrorCode.SERIALIZATION_ERROR: _p.DOMAIN_INVALID,
        }
        return error_result("cyber_report", audit_id, mapping.get(error.code, "INTERNAL_ERROR"), str(error))
    return error_result("cyber_report", audit_id, "INTERNAL_ERROR", "report generation failed")
