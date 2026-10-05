"""Universal CLI adapter — ECA-T014.

Thin translator over Core: parses args → calls application/Core services →
projects results to stdout (results) / stderr (diagnostics). No policy,
severity, classification, correlation, verification, permission, shell, or
remediation logic lives here. Findings presence never fails a command.

Exit codes (documented contract):
  0 SUCCESS · 1 AUDIT/DOMAIN FAILURE · 2 INVALID INPUT · 3 POLICY DENIED ·
  4 SECURITY BLOCKED · 5 PROVIDER/TOOL UNAVAILABLE · 6 VERIFICATION
  INCONCLUSIVE · 7 INTERNAL ERROR · 130 interrupted (SIGINT, POSIX standard,
  outside the 0-7 table).
"""

from __future__ import annotations

import functools
import json as _json
import os
import shutil
import sys
import uuid
from contextlib import contextmanager
from typing import Any, Callable

import typer

EXIT_SUCCESS = 0
EXIT_DOMAIN_FAILURE = 1
EXIT_INVALID_INPUT = 2
EXIT_POLICY_DENIED = 3
EXIT_SECURITY_BLOCKED = 4
EXIT_UNAVAILABLE = 5
EXIT_INCONCLUSIVE = 6
EXIT_INTERNAL = 7
EXIT_INTERRUPTED = 130

app = typer.Typer(help="EMO-Cyber-Agent cybersecurity specialist (read-only by default)")


def _version_callback(value: bool) -> None:
    if value:
        from emo_cyber_agent import __version__

        typer.echo(f"emo-cyber-agent {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the release version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """EMO-Cyber-Agent cybersecurity specialist (read-only by default)."""


# ---------------------------------------------------------------------------
# Shared plumbing (translation + output only)
# ---------------------------------------------------------------------------

def _redact(text: str) -> str:
    from emo_cyber_agent.core.repository import redact_credentials
    from emo_cyber_agent.core.supabase import redact_supabase_secrets

    return redact_supabase_secrets(redact_credentials(text))


def _fail(code: int, message: str) -> "typer.Exit":
    typer.echo(_redact(message)[:500], err=True)
    return typer.Exit(code=code)


def _emit(text: str, output: str | None) -> None:
    if output:
        try:
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as e:
            raise _fail_silent(f"cannot write output: {e}")
    else:
        typer.echo(text)


class _CliFailure(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _fail_silent(message: str) -> _CliFailure:
    return _CliFailure(EXIT_INVALID_INPUT, message)


def _safe(fn: Callable[..., None]) -> Callable[..., None]:
    """Signal + failure boundary: KeyboardInterrupt → clean 130, no state to corrupt (stateless)."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except _CliFailure as e:
            typer.echo(_redact(str(e))[:500], err=True)
            raise typer.Exit(code=e.code)
        except KeyboardInterrupt:
            typer.echo("interrupted", err=True)
            raise typer.Exit(code=EXIT_INTERRUPTED)
        except typer.Exit:
            raise
        except Exception as e:  # never leak internals
            typer.echo(f"internal error: {type(e).__name__}", err=True)
            raise typer.Exit(code=EXIT_INTERNAL)

    return wrapper


def _map_core_error(error: Exception) -> _CliFailure:
    from emo_cyber_agent.core.reporting import ReportError, ReportErrorCode
    from emo_cyber_agent.core.verification import VerificationError, VerificationErrorCode

    message = _redact(str(error))[:400]
    if isinstance(error, VerificationError):
        mapping = {
            VerificationErrorCode.POLICY_DENIED: EXIT_POLICY_DENIED,
            VerificationErrorCode.OUT_OF_SCOPE: EXIT_POLICY_DENIED,
            VerificationErrorCode.STALE_POLICY: EXIT_POLICY_DENIED,
            VerificationErrorCode.MISMATCHED_AUDIT: EXIT_POLICY_DENIED,
            VerificationErrorCode.INVALID_REQUEST: EXIT_INVALID_INPUT,
            VerificationErrorCode.BUDGET_EXHAUSTED: EXIT_INCONCLUSIVE,
            VerificationErrorCode.LOOP_DETECTED: EXIT_INCONCLUSIVE,
        }
        return _CliFailure(mapping.get(error.code, EXIT_INTERNAL), message)
    if isinstance(error, ReportError):
        mapping = {
            ReportErrorCode.REPORTABILITY_DENIED: EXIT_POLICY_DENIED,
            ReportErrorCode.INVALID: EXIT_INVALID_INPUT,
            ReportErrorCode.SCHEMA_ERROR: EXIT_INTERNAL,
            ReportErrorCode.SERIALIZATION_ERROR: EXIT_INTERNAL,
        }
        return _CliFailure(mapping.get(error.code, EXIT_INTERNAL), message)
    text = message.lower()
    if "policy" in text or "scope" in text or "denied" in text:
        return _CliFailure(EXIT_POLICY_DENIED, message)
    if "unavailable" in text or "not found" in text and "audit" in text:
        return _CliFailure(EXIT_UNAVAILABLE if "unavailable" in text else EXIT_DOMAIN_FAILURE, message)
    return _CliFailure(EXIT_INTERNAL, message)


# ---------------------------------------------------------------------------
# Progress wiring (display only — never controls execution or policy)
# ---------------------------------------------------------------------------
#
# Fixed lifecycle for CLI runs: STARTED -> phase transitions -> terminal
# (COMPLETED | FAILED | CANCELLED). Phase names and message codes are fixed
# constants only; no scanner output, secrets, prompts, or CoT ever enter
# progress fields. JSON mode: business payload only on stdout, progress on
# stderr. Human mode: concise progress lines on stderr.

_CLI_PROGRESS_PHASES = ("STARTED", "RUNNING", "FINALIZING", "COMPLETED", "FAILED", "CANCELLED")


def _cli_progress_ids(prefix: str) -> tuple[str, str]:
    token = uuid.uuid4().hex[:12]
    return f"{prefix}-{token}", f"audit-{token}"


@contextmanager
def _cli_progress(command: str, format: str):  # noqa: ANN202 — generator yields ProgressReporter
    """Lifecycle helper: emits STARTED/RUNNING/FINALIZING + terminal events.

    Progress is display-only: it never controls execution and never touches
    the PolicyEngine. Human mode prints concise phase lines to stderr;
    JSON mode stays silent (stderr sink only, still attached so events
    exist for observability without polluting stdout).
    """
    from emo_cyber_agent.progress.events import ProgressEventType
    from emo_cyber_agent.progress.reporter import ProgressReporter
    from emo_cyber_agent.progress.state import ProgressState

    run_id, audit_id = _cli_progress_ids(command)
    # Each run emits exactly 4 events on the success path (STARTED + 2
    # progress + 1 terminal), so total=4 makes COMPLETED land at 100%.
    # Failure/cancel paths emit STARTED + terminal (50%), matching the
    # repo's own terminal-state convention (no 100% without completion).
    state = ProgressState(run_id=run_id, audit_id=audit_id, phases=list(_CLI_PROGRESS_PHASES), total=4)
    reporter = ProgressReporter()
    if format == "human":
        def _sink(event: Any) -> None:
            typer.echo(f"[{command}] {event.phase} ({event.message_code})", err=True)

        reporter.add_sink(_sink)
    else:
        reporter.add_sink(lambda event: None)
    try:
        reporter.report(state.advance(phase="STARTED", status="STARTED", message_code="RUN_STARTED"))
        yield reporter
        reporter.report(state.advance(phase="RUNNING", status="RUNNING", message_code="PHASE_STARTED"))
        reporter.report(state.advance(phase="FINALIZING", status="FINALIZING", message_code="PHASE_STARTED"))
    except KeyboardInterrupt:
        reporter.report(
            state.advance(phase="CANCELLED", status="CANCELLED", message_code="OPERATION_CANCELLED", event_type=ProgressEventType.PROGRESS)
        )
        raise
    except (_CliFailure, typer.Exit):
        reporter.report(
            state.advance(phase="FAILED", status="FAILED", message_code="OPERATION_FAILED", event_type=ProgressEventType.ERROR)
        )
        raise
    except Exception:
        reporter.report(
            state.advance(phase="FAILED", status="FAILED", message_code="OPERATION_FAILED", event_type=ProgressEventType.ERROR)
        )
        raise
    else:
        reporter.report(
            state.advance(phase="COMPLETED", status="COMPLETED", message_code="OPERATION_COMPLETE")
        )


# ---------------------------------------------------------------------------
# Configuration (env > file > defaults; provider selection only — never policy)
# ---------------------------------------------------------------------------

CONFIG_ENV_VARS = ("EMO_MODEL", "EMO_PROVIDER_ENDPOINT")
CONFIG_FILE_KEYS = ("model", "provider_endpoint")
_FORBIDDEN_CONFIG_KEYS = ("policy", "capabilities", "permissions", "profile", "allow", "grant", "sudo")


def load_config(explicit: dict[str, Any] | None = None) -> dict[str, Any]:
    """Precedence: explicit CLI values > environment > config file > defaults."""
    config: dict[str, Any] = {}
    path = os.path.expanduser("~/.config/emo-cyber-agent/config.json")
    try:
        with open(path, encoding="utf-8") as fh:
            raw = _json.load(fh)
    except (OSError, ValueError):
        raw = {}
    if not isinstance(raw, dict):
        raise _CliFailure(EXIT_INVALID_INPUT, "configuration file must contain an object")
    for key in raw:
        if key not in CONFIG_FILE_KEYS:
            raise _CliFailure(EXIT_INVALID_INPUT, f"unsupported configuration key: {key}")
        lowered = key.lower()
        if any(bad in lowered for bad in _FORBIDDEN_CONFIG_KEYS):
            raise _CliFailure(EXIT_INVALID_INPUT, f"configuration must not set policy/security: {key}")
    config.update({k: raw[k] for k in CONFIG_FILE_KEYS if k in raw})
    if os.environ.get("EMO_MODEL"):
        config["model"] = os.environ["EMO_MODEL"][:200]
    if os.environ.get("EMO_PROVIDER_ENDPOINT"):
        config["provider_endpoint"] = "configured"  # presence only; URLs may embed secrets
    for key, value in (explicit or {}).items():
        if value is not None:
            config[key] = value
    return config


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
@_safe
def doctor(format: str = typer.Option("human", "--format", help="Output format: human|json")) -> None:
    """Check operational status. Prints presence (CONFIGURED/MISSING/...), never secret values."""
    import json as _js

    from emo_cyber_agent import __version__

    if format not in ("human", "json"):
        raise _fail_silent("invalid format: use human|json")
    import importlib.util

    checks: dict[str, str] = {}
    checks["package"] = f"emo-cyber-agent {__version__}"
    checks["python"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    try:

        checks["core"] = "OK"
    except Exception:
        checks["core"] = "INVALID"
    try:
        from emo_cyber_agent.core.resources import resource_origin, validate_packaged_schemas

        validate_packaged_schemas()
        checks["schemas"] = f"OK ({resource_origin()})"
    except Exception:
        checks["schemas"] = "INVALID"
    try:
        from emo_cyber_agent.core.scanners import get_scanner_tool_specs

        checks["tool_registry"] = f"OK ({len(get_scanner_tool_specs())} scanner specs)"
    except Exception:
        checks["tool_registry"] = "INVALID"
    for tool in ("semgrep", "trivy", "osv-scanner", "gitleaks", "git"):
        checks[f"tool:{tool}"] = "AVAILABLE" if shutil.which(tool) else "UNAVAILABLE"
    checks["github_config"] = "CONFIGURED" if os.environ.get("GITHUB_TOKEN") else "MISSING"
    checks["supabase_config"] = "CONFIGURED" if os.environ.get("SUPABASE_URL") else "MISSING"
    checks["mcp_available"] = "AVAILABLE" if importlib.util.find_spec("mcp") is not None else "UNAVAILABLE (stdio adapter is dependency-free)"
    cfg = load_config()
    checks["provider"] = "CONFIGURED" if cfg.get("model") or cfg.get("provider_endpoint") else "MISSING"
    if format == "json":
        typer.echo(_js.dumps({"status": "ok", "checks": checks}, sort_keys=True))
    else:
        typer.echo("EMO-Cyber-Agent doctor")
        for key in sorted(checks):
            typer.echo(f"  {key}: {checks[key]}")


@app.command()
@_safe
def audit(
    target: str = typer.Argument(..., help="Audit target (project path or repository locator)"),
    mode: str = typer.Option("standard", "--mode", help="Audit mode: quick|standard|deep"),
    focus: str | None = typer.Option(None, "--focus", help="Comma-separated focus areas"),
    format: str = typer.Option("human", "--format", help="Output format: human|json"),
    output: str | None = typer.Option(None, "--output", help="Write result to path instead of stdout"),
) -> None:
    """Run a scoped, read-only security audit via Core. Findings never affect the exit code."""
    import asyncio
    import json as _js

    from emo_cyber_agent.core.service import FoundationSecurityAuditor

    with _cli_progress("audit", format):
        if format not in ("human", "json"):
            raise _fail_silent("invalid format: use human|json")
        if mode not in ("quick", "standard", "deep"):
            raise _fail_silent("invalid mode: use quick|standard|deep")
        if not target or not target.strip():
            raise _fail_silent("target is required")
        auditor = FoundationSecurityAuditor()
        try:
            result = asyncio.run(auditor.audit(target=target.strip(), mode=mode, permission_profile="read_only", focus=[f.strip() for f in (focus or "").split(",") if f.strip()]))
        except Exception as e:
            raise _map_core_error(e)
        data = result.model_dump(mode="json")
        data["target"] = _redact(str(data.get("target", "")))[:512]  # adapter serialization duty: never echo raw target
        if format == "json":
            _emit(_js.dumps({"status": "ok", "result": data}, sort_keys=True), output)
        else:
            _emit(f"audit_id: {data.get('audit_id', '')}\nstatus: {data.get('status', '')}\ntarget: {data.get('target', '')}", output)


@app.command()
@_safe
def review(
    target: str = typer.Argument(..., help="Review target (file, path, or context reference)"),
    focus: str | None = typer.Option(None, "--focus", help="Comma-separated focus areas"),
    format: str = typer.Option("human", "--format", help="Output format: human|json"),
    output: str | None = typer.Option(None, "--output", help="Write result to path instead of stdout"),
) -> None:
    """Run a focused, read-only security review via Core."""
    import asyncio
    import json as _js

    from emo_cyber_agent.core.service import FoundationSecurityAuditor

    with _cli_progress("review", format):
        if format not in ("human", "json"):
            raise _fail_silent("invalid format: use human|json")
        if not target or not target.strip():
            raise _fail_silent("target is required")
        auditor = FoundationSecurityAuditor()
        try:
            result = asyncio.run(auditor.review(target=target.strip(), focus=[f.strip() for f in (focus or "").split(",") if f.strip()]))
        except Exception as e:
            raise _map_core_error(e)
        data = result.model_dump(mode="json")
        data["target"] = _redact(str(data.get("target", "")))[:512]
        if format == "json":
            _emit(_js.dumps({"status": "ok", "result": data}, sort_keys=True), output)
        else:
            _emit(f"audit_id: {data.get('audit_id', '')}\nstatus: {data.get('status', '')}\ntarget: {data.get('target', '')}", output)


@app.command()
@_safe
def verify(
    candidate: str = typer.Option(..., "--candidate", help="Path to a JSON file with a FindingCandidate object"),
    method: str = typer.Option(..., "--method", help="Verification method"),
    kind: str = typer.Option(..., "--kind", help="Target kind"),
    locator: str = typer.Option(..., "--locator", help="Explicit target locator"),
    rationale: str = typer.Option(..., "--rationale", help="Why this verification is needed"),
    audit_id: str = typer.Option(..., "--audit-id", help="Audit scope"),
    format: str = typer.Option("human", "--format", help="Output format: human|json"),
    output: str | None = typer.Option(None, "--output", help="Write result to path instead of stdout"),
) -> None:
    """Request verification planning from Core. Returns a PLAN; input is never authorization."""
    import json as _js

    from emo_cyber_agent.core.correlation import EvidenceStore, FindingCandidate
    from emo_cyber_agent.core.policy import StrictPolicyEngine
    from emo_cyber_agent.core.tool_registry import ToolRegistry
    from emo_cyber_agent.core.verification import VerificationRequest, VerificationService, get_verification_tool_specs

    if format not in ("human", "json"):
        raise _fail_silent("invalid format: use human|json")
    try:
        with open(candidate, encoding="utf-8") as fh:
            raw_candidate = _js.load(fh)
    except (OSError, ValueError) as e:
        raise _fail_silent(f"cannot read candidate file: {e}")
    try:
        cand = FindingCandidate(**raw_candidate)
        request = VerificationRequest(method=method, target={"kind": kind, "locator": locator}, rationale_summary=rationale)
    except ValueError as e:
        raise _fail_silent(f"invalid verification input: {e}")
    if cand.audit_id != audit_id:
        raise _CliFailure(EXIT_POLICY_DENIED, "candidate audit mismatch")
    registry = ToolRegistry()
    for spec in get_verification_tool_specs():
        registry.register(spec)
    from emo_cyber_agent.core.verification import VerificationError

    service = VerificationService(executor=_PlanOnlyExecutor(), policy=StrictPolicyEngine(), registry=registry, store=EvidenceStore(), scope_allows=lambda a, t: a == audit_id and t == locator)
    try:
        plan = service.plan(candidate=cand, request=request, audit_id=audit_id)
    except VerificationError as e:
        raise _map_core_error(e)
    body = {"status": "planned", "plan_id": plan.plan_id, "method": request.method.value, "safety_level": plan.safety_level.value, "required_capabilities": list(plan.required_capabilities), "note": "plan only; execution requires an authorized audit session"}
    if format == "json":
        _emit(_js.dumps({"status": "ok", "result": body}, sort_keys=True), output)
    else:
        _emit(f"plan_id: {plan.plan_id}\nmethod: {request.method.value}\nsafety: {plan.safety_level.value}\ncapabilities: {','.join(plan.required_capabilities)}", output)


class _PlanOnlyExecutor:
    def run(self, plan: Any) -> Any:
        raise RuntimeError("verify-via-CLI returns plans; execution is per-audit release integration")


@app.command()
@_safe
def status(
    audit_id: str = typer.Argument(..., help="Audit identifier to inspect"),
    format: str = typer.Option("human", "--format", help="Output format: human|json"),
) -> None:
    """Read-only status. No persisted audit store exists in this phase, so unknown audits report NOT_FOUND (exit 1) — never another audit's data."""
    import json as _js

    if format not in ("human", "json"):
        raise _fail_silent("invalid format: use human|json")
    if not audit_id or not audit_id.strip():
        raise _fail_silent("audit_id is required")
    body = {"status": "unknown-audit", "audit_id": audit_id.strip(), "note": "no persisted audit store in this phase; audits are synchronous — see audit/report commands"}
    if format == "json":
        typer.echo(_js.dumps(body, sort_keys=True))
    else:
        typer.echo(f"audit_id: {body['audit_id']}\nstatus: unknown-audit\nnote: {body['note']}")
    raise typer.Exit(code=EXIT_DOMAIN_FAILURE)


@app.command()
@_safe
def report(
    findings: str = typer.Option(..., "--findings", help="Path to a JSON file with a list of SecurityFinding objects"),
    format: str = typer.Option("json", "--format", help="Output format: json|jsonl|markdown"),
    output: str | None = typer.Option(None, "--output", help="Write to path instead of stdout"),
    audit_id: str = typer.Option(..., "--audit-id", help="Audit scope all findings must belong to"),
    include_non_reportable: bool = typer.Option(False, "--include-non-reportable", help="Project non-reportable items too (projection choice only)"),
) -> None:
    """Render a report. Thin adapter: parses args, calls Core ReportService, prints."""
    import json as _json

    from emo_cyber_agent.core.findings import SecurityFinding
    from emo_cyber_agent.core.reporting import ReportError, ReportService

    if format not in ("json", "jsonl", "markdown"):
        raise _fail_silent("invalid format: use json|jsonl|markdown")
    try:
        with open(findings, encoding="utf-8") as fh:
            raw = _json.load(fh)
    except (OSError, ValueError) as e:
        raise _fail_silent(f"cannot read findings file: {e}")
    if not isinstance(raw, list):
        raise _fail_silent("findings file must contain a JSON list")
    try:
        items = [SecurityFinding(**entry) for entry in raw]
    except ValueError as e:
        raise _fail_silent(f"invalid finding data: {e}")
    service = ReportService()
    try:
        rep = service.generate(audit_id=audit_id, findings=items, include_non_reportable=include_non_reportable)
        text = {"json": service.generate_json, "jsonl": service.generate_jsonl, "markdown": service.generate_markdown}[format](rep)
    except ReportError as e:
        raise _map_core_error(e)
    _emit(text, output)


@app.command()
@_safe
def extensions(
    action: str = typer.Option("list", "--action", help="Read action: list|describe|resolve|check"),
    extension_id: str = typer.Option("", "--extension-id", help="Extension identity to inspect"),
    version: str = typer.Option("", "--version", help="Exact version to pin"),
    provide: str = typer.Option("", "--provide", help="Provider token to resolve"),
    constraint: str = typer.Option("", "--constraint", help="Version constraint for resolve"),
    policy: str = typer.Option("exact", "--policy", help="Version policy for resolve: exact|highest_compatible"),
    path: str = typer.Option("", "--path", help="Extra directory to scan (metadata only)"),
    format: str = typer.Option("human", "--format", help="Output format: human|json"),
    output: str | None = typer.Option(None, "--output", help="Write result to path instead of stdout"),
) -> None:
    """Inspect extension metadata. Read-only: never installs, loads, trusts, or executes extension code."""
    import json as _js
    from pathlib import Path as _Path

    from emo_cyber_agent.extensions import ExtensionError, read_extensions

    if format not in ("human", "json"):
        raise _fail_silent("invalid format: use human|json")
    if action not in ("list", "describe", "resolve", "check"):
        raise _fail_silent("invalid action: use list|describe|resolve|check")
    if policy not in ("exact", "highest_compatible"):
        raise _fail_silent("invalid policy: use exact|highest_compatible")
    if path:
        target = _Path(path).expanduser()
        if not target.is_dir():
            raise _fail_silent(f"path is not a directory: {path[:200]}")
        path = str(target)
    try:
        body = read_extensions(
            action,
            extension_id=extension_id.strip()[:80],
            version=version.strip()[:32],
            provide=provide.strip()[:120],
            version_constraint=constraint.strip()[:120],
            policy=policy,
            extra_roots=(path,) if path else (),
        )
    except ExtensionError as e:
        code = getattr(getattr(e, "code", None), "value", str(getattr(e, "code", "")))
        if code in ("EXTENSION_NOT_FOUND", "EXTENSION_VERSION_NOT_FOUND"):
            raise _CliFailure(EXIT_DOMAIN_FAILURE, str(e))
        if code in ("EXTENSION_QUERY_UNKNOWN", "EXTENSION_MANIFEST_INVALID", "EXTENSION_IDENTITY_INVALID"):
            raise _CliFailure(EXIT_INVALID_INPUT, str(e))
        raise _CliFailure(EXIT_DOMAIN_FAILURE, str(e))
    if format == "json":
        _emit(_js.dumps(body, sort_keys=True), output)
        return
    lines = [f"action: {body['action']}", f"code_load: {body['code_load']}", f"registered: {body['registered']}"]
    if action == "list":
        entries = body.get("entries", [])
        lines.append(f"count: {len(entries)}")
        for entry in entries:
            lines.append(
                f"  {entry['extension_id']}@{entry['version']}  {entry['extension_type']}  "
                f"{entry['trust']['state']}  {entry['lifecycle']}"
            )
        for conflict in body.get("conflicts", []):
            lines.append(f"  conflict: {conflict['kind']}:{conflict['subject']}")
    elif action in ("describe", "check"):
        view = body.get("extension") or body.get("check") or {}
        lines.append(f"identity: {view.get('identity', '')}")
        lines.append(f"trust: {view.get('trust', '')}")
        lines.append(f"lifecycle: {view.get('lifecycle', '')}")
        lines.append(f"resolvable: {view.get('resolvable', '')}")
        for reason in (view.get("errors") or view.get("trust_reasons") or view.get("reason") or []):
            lines.append(f"  note: {reason}" if isinstance(reason, str) else f"  note: {reason}")
    else:
        resolution = body.get("resolution", {})
        lines.append(f"chosen: {resolution.get('chosen', '') or '∅'}")
        lines.append(f"resolved: {resolution.get('resolved', False)}")
        lines.append(f"eligible: {resolution.get('eligible', False)}")
        for note in resolution.get("notes", []):
            lines.append(f"  note: {note}")
        for conflict in resolution.get("conflicts", []):
            lines.append(f"  conflict: {conflict['kind']}:{conflict['subject']}")
    _emit("\n".join(lines), output)


@app.command()
def mcp() -> None:
    """Start the MCP server over stdio (thin adapter over Core)."""
    from emo_cyber_agent.mcp.server import run_stdio

    raise typer.Exit(code=run_stdio())
