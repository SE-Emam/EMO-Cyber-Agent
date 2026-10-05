"""System-under-test adapters — POST-RC-013.

Four adapters expose the product through its real interfaces:

- :class:`PythonApiSUTAdapter` — the Python API surface (operations are
  supplied by the caller, so a benchmark can wire real Core services);
- :class:`CliSUTAdapter` — the seven documented CLI commands, with the
  command whitelist enforced here (an unknown command is an adapter error,
  never an execution);
- :class:`McpSUTAdapter` — declared MCP tools only, dispatched through the
  MCP delegation layer;
- :class:`ScriptedSUTAdapter` — the deterministic reference implementation
  used by the corpus. Its operations are label-independent rules over the
  scenario payload: it never reads ground truth.

No adapter opens a process or a socket, and none of them imports a model
provider. Every failure becomes a structured :class:`SUTResult`, never an
exception escaping to the runner.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.evaluation.cases import BlindEvaluationCase
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode
from emo_cyber_agent.core.verification import (
    VerificationExecutorPort,
    VerificationPlan,
    VerificationRawResult,
)
from emo_cyber_agent.evaluation.spec import (
    AuthoritySnapshot,
    EvaluationObservation,
    EvaluationStage,
    capture_authority,
    evaluation_digest,
)

__all__ = [
    "SUTResult",
    "SUTAdapter",
    "PythonApiSUTAdapter",
    "CliSUTAdapter",
    "McpSUTAdapter",
    "ScriptedSUTAdapter",
    "CLI_COMMANDS",
    "MCP_TOOLS",
    "SCRIPTED_OPERATIONS",
    "audit_projection",
]

CLI_COMMANDS: tuple[str, ...] = (
    "audit",
    "review",
    "verify",
    "report",
    "status",
    "doctor",
    "mcp",
    "extensions",
)
_CLI_FORMAT_COMMANDS = frozenset(
    {"audit", "review", "verify", "status", "doctor", "report", "extensions"}
)
MCP_TOOLS: tuple[str, ...] = (
    "cyber_audit",
    "cyber_review",
    "cyber_verify",
    "cyber_report",
    "cyber_status",
    "cyber_extensions",
)
SCRIPTED_OPERATIONS: tuple[str, ...] = (
    "normalize",
    "redact",
    "scope",
    "policy",
    "detect",
    "evidence",
    "correlate",
    "coverage",
    "report",
    "authority",
    "inject",
    "regression",
    "verify",
)
_DENIED_CLI_FLAGS = ("--output", "-o", "--force", "--yes")
_MAX_CAPTURE = 65536


class SUTResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sut_id: str = Field(..., min_length=1, max_length=64)
    sut_version: str = Field(..., min_length=1, max_length=32)
    case_id: str = Field(..., min_length=1, max_length=96)
    stage: str = Field(..., min_length=1, max_length=64)
    kind: str = Field(..., min_length=1, max_length=64)
    ok: bool = True
    outputs: dict[str, Any] = Field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""

    @property
    def error(self) -> bool:
        return not self.ok


class SUTAdapter(ABC):
    """Common contract every benchmark target implements."""

    @property
    @abstractmethod
    def sut_id(self) -> str: ...

    @property
    @abstractmethod
    def sut_version(self) -> str: ...

    @abstractmethod
    def capabilities(self) -> tuple[str, ...]: ...

    @abstractmethod
    def invoke(self, case: BlindEvaluationCase) -> SUTResult: ...

    def health(self) -> dict[str, str]:
        return {
            "sut_id": self.sut_id,
            "sut_version": self.sut_version,
            "state": "ready",
            "capabilities": str(len(self.capabilities())),
        }

    def prepare_case(self, case: BlindEvaluationCase) -> None:
        """Hook before the pre-invoke authority snapshot (per-case state)."""

    def authority_probe(self) -> AuthoritySnapshot | None:
        return None

    def collect_observations(self, result: SUTResult) -> list[EvaluationObservation]:
        payload: dict[str, Any] = {
            "ok": result.ok,
            "sut_id": result.sut_id,
            "kind": result.kind,
        }
        if result.ok:
            payload.update(result.outputs)
        else:
            payload["error_code"] = result.error_code
            payload["error_message"] = result.error_message
        try:
            stage = EvaluationStage(result.stage)
        except ValueError:
            stage = EvaluationStage.INPUT_FACTS
        return [
            EvaluationObservation(
                case_id=result.case_id,
                stage=stage,
                kind="sut_output",
                payload=payload,
            )
        ]

    # -- shared helpers --
    def _fail(self, case: BlindEvaluationCase, code: EvaluationErrorCode, message: str) -> SUTResult:
        return SUTResult(
            sut_id=self.sut_id,
            sut_version=self.sut_version,
            case_id=case.case_id,
            stage=case.stage.value,
            kind=case.scenario.kind,
            ok=False,
            error_code=code.value,
            error_message=message[:400],
        )

    def _done(
        self,
        case: BlindEvaluationCase,
        outputs: Mapping[str, Any],
        *,
        stage: str | None = None,
    ) -> SUTResult:
        return SUTResult(
            sut_id=self.sut_id,
            sut_version=self.sut_version,
            case_id=case.case_id,
            stage=stage or case.stage.value,
            kind=case.scenario.kind,
            ok=True,
            outputs=dict(outputs),
        )


def audit_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Stable domain fields shared by CLI, MCP, and Python API.

    ``target`` and ``audit_id`` are deliberately excluded: target redaction
    is an adapter serialization duty and audit ids are per-invocation uuids,
    so comparing them would measure identity instead of semantics."""
    source: Mapping[str, Any] = payload
    inner = payload.get("result")
    if isinstance(inner, Mapping):
        source = inner
    limitations = source.get("limitations") or []
    findings = source.get("findings") or []
    return {
        "mode": str(source.get("mode", "")),
        "permission_profile": str(source.get("permission_profile", "")),
        "status": str(source.get("status", "")),
        "findings": list(findings) if isinstance(findings, (list, tuple)) else [],
        "limitations": [str(item) for item in limitations] if isinstance(limitations, (list, tuple)) else [],
    }


# ---------------------------------------------------------------------------
# Python API
# ---------------------------------------------------------------------------


class PythonApiSUTAdapter(SUTAdapter):
    def __init__(
        self,
        operations: Mapping[str, Callable[[BlindEvaluationCase], Mapping[str, Any]]],
        *,
        sut_id: str = "python-api",
        sut_version: str = "0.1.0",
    ) -> None:
        if not operations:
            raise EvaluationError(
                EvaluationErrorCode.ADAPTER_UNKNOWN,
                "python-api adapter needs at least one operation",
            )
        self._operations = dict(operations)
        self._id = sut_id
        self._version = sut_version
        self._snapshot: AuthoritySnapshot | None = None

    @property
    def sut_id(self) -> str:
        return self._id

    @property
    def sut_version(self) -> str:
        return self._version

    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._operations))

    def set_authority_probe(self, snapshot: AuthoritySnapshot | None) -> None:
        """Test/benchmark hook: expose an authority state to the runner."""
        self._snapshot = snapshot

    def authority_probe(self) -> AuthoritySnapshot | None:
        return self._snapshot

    def invoke(self, case: BlindEvaluationCase) -> SUTResult:
        kind = case.scenario.kind
        operation = self._operations.get(kind)
        if operation is None:
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING,
                f"operation not declared: {kind}",
            )
        try:
            outputs = operation(case)
        except EvaluationError as exc:
            return self._fail(case, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            from emo_cyber_agent.core.repository import redact_credentials

            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_ERROR,
                f"{type(exc).__name__}: {redact_credentials(str(exc))}",
            )
        if not isinstance(outputs, Mapping):
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_ERROR,
                f"operation {kind} must return a mapping",
            )
        return self._done(case, outputs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _default_cli_runner(argv: Sequence[str]) -> tuple[int, str]:
    from typer.testing import CliRunner

    from emo_cyber_agent.cli.main import app

    result = CliRunner().invoke(app, list(argv), catch_exceptions=True)
    return int(result.exit_code), (result.stdout or "")


class CliSUTAdapter(SUTAdapter):
    """Runs documented CLI commands in-process (never a new process)."""

    def __init__(
        self,
        *,
        runner: Callable[[Sequence[str]], tuple[int, str]] | None = None,
        sut_id: str = "cli",
        sut_version: str = "0.1.0",
    ) -> None:
        self._runner = runner or _default_cli_runner
        self._id = sut_id
        self._version = sut_version

    @property
    def sut_id(self) -> str:
        return self._id

    @property
    def sut_version(self) -> str:
        return self._version

    def capabilities(self) -> tuple[str, ...]:
        return tuple(f"cli_{name}" for name in CLI_COMMANDS)

    def invoke(self, case: BlindEvaluationCase) -> SUTResult:
        kind = case.scenario.kind
        if not kind.startswith("cli_"):
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING,
                f"cli adapter expects a cli_<command> scenario, got {kind}",
            )
        command = kind[4:]
        if command not in CLI_COMMANDS:
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_UNKNOWN,
                f"command not in the documented CLI surface: {command or '∅'}",
            )
        argv, problem = self._argv(command, case)
        if problem:
            return self._fail(case, EvaluationErrorCode.PROTOCOL_ERROR, problem)
        try:
            exit_code, stdout = self._runner(argv)
        except EvaluationError as exc:
            return self._fail(case, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            from emo_cyber_agent.core.repository import redact_credentials

            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_ERROR,
                f"{type(exc).__name__}: {redact_credentials(str(exc))}",
            )
        captured = stdout[:_MAX_CAPTURE]
        parsed = _parse_cli_output(captured)
        outputs: dict[str, Any] = {
            "interface": "cli",
            "command": command,
            "exit_code": exit_code,
            "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
            "stdout": captured,
        }
        if isinstance(parsed, Mapping):
            outputs["payload"] = dict(parsed)
            outputs.update(audit_projection(parsed) if command == "audit" else _result_fields(parsed))
        if exit_code != 0:
            from emo_cyber_agent.core.repository import redact_credentials

            return SUTResult(
                sut_id=self.sut_id,
                sut_version=self.sut_version,
                case_id=case.case_id,
                stage=case.stage.value,
                kind=kind,
                ok=False,
                outputs=outputs,
                error_code=EvaluationErrorCode.ADAPTER_ERROR.value,
                error_message=redact_credentials(captured.strip()[:400]) or f"exit code {exit_code}",
            )
        return self._done(case, outputs)

    def _argv(self, command: str, case: BlindEvaluationCase) -> tuple[list[str], str]:
        payload = case.scenario.payload
        raw_args = payload.get("args")
        if raw_args is None:
            positional = payload.get("target") or payload.get("audit_id") or ""
            raw_args = [str(positional)] if positional else []
        if not isinstance(raw_args, (list, tuple)):
            return [], "cli args must be a list of strings"
        args: list[str] = []
        for item in raw_args:
            if not isinstance(item, str):
                return [], "cli args must be strings"
            if "\x00" in item:
                return [], "null byte in cli argument"
            if item in _DENIED_CLI_FLAGS or item.startswith("--output="):
                return [], f"write flag denied in evaluation: {item}"
            args.append(item)
        if command in _CLI_FORMAT_COMMANDS and "--format" not in args:
            args.extend(["--format", "json"])
        return [command, *args], ""


def _parse_cli_output(text: str) -> Any | None:
    import json as _json

    stripped = text.strip()
    if not stripped:
        return None
    start = stripped.find("{")
    if start == -1:
        return None
    try:
        return _json.loads(stripped[start:])
    except ValueError:
        return None


def _result_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    inner = payload.get("result")
    if not isinstance(inner, Mapping):
        return {}
    return {key: inner.get(key) for key in ("status", "plan_id", "method", "safety_level") if key in inner}


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


def _default_mcp_dispatch(tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    from emo_cyber_agent.mcp.delegate import dispatch

    return dispatch(tool, dict(arguments))


class McpSUTAdapter(SUTAdapter):
    def __init__(
        self,
        *,
        dispatch: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
        declared_tools: Sequence[str] = MCP_TOOLS,
        sut_id: str = "mcp",
        sut_version: str = "0.1.0",
    ) -> None:
        self._dispatch = dispatch or _default_mcp_dispatch
        self._declared = tuple(declared_tools)
        self._id = sut_id
        self._version = sut_version

    @property
    def sut_id(self) -> str:
        return self._id

    @property
    def sut_version(self) -> str:
        return self._version

    def capabilities(self) -> tuple[str, ...]:
        return tuple(f"mcp_{name}" for name in self._declared)

    def invoke(self, case: BlindEvaluationCase) -> SUTResult:
        kind = case.scenario.kind
        if not kind.startswith("mcp_"):
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING,
                f"mcp adapter expects an mcp_<tool> scenario, got {kind}",
            )
        tool = kind[4:]
        if tool not in self._declared:
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_UNKNOWN,
                f"tool not declared for this server: {tool or '∅'}",
            )
        arguments = case.scenario.payload.get("arguments", {})
        if not isinstance(arguments, Mapping):
            return self._fail(case, EvaluationErrorCode.PROTOCOL_ERROR, "mcp arguments must be an object")
        try:
            response = self._dispatch(tool, arguments)
        except EvaluationError as exc:
            return self._fail(case, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            from emo_cyber_agent.core.repository import redact_credentials

            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_ERROR,
                f"{type(exc).__name__}: {redact_credentials(str(exc))}",
            )
        if not isinstance(response, Mapping):
            return self._fail(case, EvaluationErrorCode.ADAPTER_ERROR, "mcp dispatch returned a non-object")
        failed = bool(response.get("isError")) or str(response.get("status", "ok")) == "error"
        outputs: dict[str, Any] = {
            "interface": "mcp",
            "tool": tool,
            "payload": dict(response),
        }
        if isinstance(response.get("result"), Mapping):
            outputs.update(audit_projection(response) if tool == "cyber_audit" else _result_fields(response))
        if failed:
            return SUTResult(
                sut_id=self.sut_id,
                sut_version=self.sut_version,
                case_id=case.case_id,
                stage=case.stage.value,
                kind=kind,
                ok=False,
                outputs=outputs,
                error_code=EvaluationErrorCode.ADAPTER_ERROR.value,
                error_message="mcp tool returned an error result",
            )
        return self._done(case, outputs)


# ---------------------------------------------------------------------------
# Scripted reference implementation
# ---------------------------------------------------------------------------

_SECRET_RE = re.compile(
    r"sk_live_[0-9a-zA-Z]{8,}|sk_test_[0-9a-zA-Z]{8,}|AKIA[0-9A-Z]{16}|"
    r"ghp_[0-9a-zA-Z]{20,}|xox[baprs]-[0-9a-zA-Z-]{10,}|"
    r"(?:password|passwd|api_key|apikey|secret|token)\s*[=:]\s*['\"][^'\"]{6,}",
    re.IGNORECASE,
)
_INJECTION_RE = re.compile(
    r"\b(?:eval|exec|system)\s*\(|subprocess\.|os\.popen|child_process|"
    r"innerHTML|pickle\.loads|yaml\.load\s*\(",
    re.IGNORECASE,
)
_SSRF_RE = re.compile(
    r"(?:requests\.(?:get|post|request|put)\s*\(\s*(?:url\s*=\s*)?"
    r"(?:user|input|remote|target|host)|urlopen\s*\(\s*|fetch\s*\(\s*(?:user|input|remote))",
    re.IGNORECASE,
)
_SQL_INJECTION_RE = re.compile(r"(?:f['\"]select |['\"]select .*?\+\s*(?:request|params|user))", re.IGNORECASE)

_DETECTION_RULES: tuple[tuple[str, str], ...] = (
    ("secret_literal", "secret-pattern"),
    ("injection_sink", "code-execution-sink"),
    ("ssrf", "server-side-request-forgery"),
    ("sql_injection", "sql-string-building"),
)


class ScriptedSUTAdapter(SUTAdapter):
    """Deterministic reference system used by the fixture corpus.

    Every operation is a pure rule over the scenario payload. Ground truth
    is never read here: the adapter cannot see expected values, only the
    blind case."""

    def __init__(self, *, sut_id: str = "scripted", sut_version: str = "0.1.0") -> None:
        self._id = sut_id
        self._version = sut_version
        self._findings: dict[str, str] = {}
        self._grants: dict[str, bool] = {"read": True, "write": False, "network": False, "restricted": False}

    @property
    def sut_id(self) -> str:
        return self._id

    @property
    def sut_version(self) -> str:
        return self._version

    def capabilities(self) -> tuple[str, ...]:
        return SCRIPTED_OPERATIONS

    def prepare_case(self, case: BlindEvaluationCase) -> None:
        payload = case.scenario.payload
        self._findings = {str(k): str(v) for k, v in dict(payload.get("authority_findings", {})).items()}
        self._grants = {
            "read": True,
            "write": bool(payload.get("authority_grant_write", False)),
            "network": bool(payload.get("authority_grant_network", False)),
            "restricted": bool(payload.get("authority_grant_restricted", False)),
        }

    def authority_probe(self) -> AuthoritySnapshot | None:
        return capture_authority(
            findings=self._findings,
            granted_read=self._grants.get("read", True),
            granted_write=self._grants.get("write", False),
            granted_network=self._grants.get("network", False),
            granted_restricted=self._grants.get("restricted", False),
        )

    def invoke(self, case: BlindEvaluationCase) -> SUTResult:
        kind = case.scenario.kind
        if kind not in SCRIPTED_OPERATIONS:
            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING,
                f"scripted adapter has no operation {kind}",
            )
        try:
            outputs = getattr(self, f"_op_{kind}")(case.scenario.payload)
        except EvaluationError as exc:
            return self._fail(case, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - adapter boundary
            from emo_cyber_agent.core.repository import redact_credentials

            return self._fail(
                case,
                EvaluationErrorCode.ADAPTER_ERROR,
                f"{type(exc).__name__}: {redact_credentials(str(exc))}",
            )
        return self._done(case, outputs)

    # -- operations --
    def _op_normalize(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        text = str(payload.get("text", ""))
        normalized = " ".join(text.split())
        return {
            "normalized_text": normalized,
            "input_characters": len(text),
            "normalized_characters": len(normalized),
            "empty_after_normalization": normalized == "",
        }

    def _op_redact(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.core.repository import redact_credentials
        from emo_cyber_agent.core.supabase import redact_supabase_secrets

        text = str(payload.get("text", ""))
        secret = str(payload.get("secret", "")).strip()
        redacted = redact_supabase_secrets(redact_credentials(text))
        leaked = bool(secret) and secret in redacted
        return {
            "redacted_text": redacted,
            "leaked_secret": leaked,
            "changed": redacted != text,
            "source_characters": len(text),
        }

    def _op_scope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.core.policy import StrictPolicyEngine

        audit_id = str(payload.get("audit_id", "audit-eval"))
        target = str(payload.get("target", ""))
        allowed_targets = [str(item) for item in payload.get("scope", [])]
        engine = StrictPolicyEngine(
            scope_allows=lambda a, t: a == audit_id and t in allowed_targets,
        )
        in_scope = engine.check_scope(audit_id, target)
        return {"in_scope": bool(in_scope), "target": target, "scope_size": len(allowed_targets)}

    def _op_policy(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.core.policy import StrictPolicyEngine

        engine = StrictPolicyEngine(
            granted_network=tuple(payload.get("granted_network", ())),
            granted_write=tuple(payload.get("granted_write", ())),
            granted_restricted=tuple(payload.get("granted_restricted", ())),
        )
        capabilities = [str(item) for item in payload.get("capabilities", ())]
        decision = engine.issue_decision(
            str(payload.get("audit_id", "audit-eval")),
            str(payload.get("tool_id", "evaluation-tool")),
            str(payload.get("target", "evaluation-target")),
            str(payload.get("profile", "read_only")),
            capabilities,
        )
        return {
            "allowed": bool(decision.allowed),
            "reason_codes": list(decision.reason_codes),
            "profile": decision.profile,
            "requested_capabilities": list(capabilities),
        }

    def _op_detect(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        text = str(payload.get("text", ""))
        blob = text + "\n" + str(payload.get("dependencies", ""))
        detections: list[dict[str, str]] = []
        findings: list[str] = []
        if payload.get("auth_check") is False:
            findings.append("auth_check_missing")
        if payload.get("validation") is False:
            findings.append("validation_missing")
        if _SECRET_RE.search(blob):
            findings.append("secret_literal")
        if _INJECTION_RE.search(blob):
            findings.append("injection_sink")
        if _SSRF_RE.search(blob):
            findings.append("ssrf")
        if _SQL_INJECTION_RE.search(blob):
            findings.append("sql_injection")
        for entry in payload.get("dependencies", []) if isinstance(payload.get("dependencies"), list) else []:
            if isinstance(entry, Mapping) and entry.get("vulnerable") is True:
                findings.append("known_vulnerable_dependency")
                break
        severities = {
            "auth_check_missing": "high",
            "validation_missing": "medium",
            "secret_literal": "critical",
            "injection_sink": "high",
            "ssrf": "high",
            "sql_injection": "high",
            "known_vulnerable_dependency": "medium",
        }
        for rule in sorted(set(findings)):
            detections.append({"rule": rule, "severity": severities.get(rule, "info")})
        return {
            "detections": detections,
            "detection_count": len(detections),
            "detection_confidence": 50 if detections else None,
            "rules_evaluated": len(_DETECTION_RULES) + 2,
            "raw_text_scanned": bool(text),
        }

    def _op_evidence(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        facts = payload.get("facts", [])
        if not isinstance(facts, (list, tuple)):
            facts = []
        records: list[dict[str, Any]] = []
        tools: set[str] = set()
        for index, fact in enumerate(facts):
            if not isinstance(fact, Mapping):
                continue
            source_tool = str(fact.get("source_tool", "unknown"))
            tools.add(source_tool)
            provenance = fact.get("provenance", {})
            provenance = dict(provenance) if isinstance(provenance, Mapping) else {}
            records.append(
                {
                    "evidence_id": f"ev-{index}-{str(fact.get('content_hash', ''))[:8] or 'none'}",
                    "source_tool": source_tool,
                    "location": str(fact.get("location", "")),
                    "content_hash": str(fact.get("content_hash", "")),
                    "provenance_complete": bool(provenance),
                    "provenance_keys": sorted(provenance),
                }
            )
        return {
            "evidence": records,
            "evidence_count": len(records),
            "provenance_complete": bool(records) and all(r["provenance_complete"] for r in records),
            "content_hash_present": bool(records) and all(bool(r["content_hash"]) for r in records),
            "independent_sources": len(tools),
        }

    def _op_correlate(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.core.correlation import CorrelationEngine, EvidenceStore
        from emo_cyber_agent.domain.models import EvidenceItem

        audit_id = str(payload.get("audit_id", "audit-eval"))
        raw = payload.get("evidence", [])
        if not isinstance(raw, (list, tuple)):
            raw = []
        store = EvidenceStore()
        stored: list[str] = []
        for index, entry in enumerate(raw):
            if not isinstance(entry, Mapping):
                continue
            item = EvidenceItem(
                id=f"ev-{audit_id}-{index}",
                source_tool=str(entry.get("source_tool", "scanner")),
                source_version=str(entry.get("source_version", "1")),
                target_asset_id=str(entry.get("asset_id", "")) or None,
                location=str(entry.get("location", f"file-{index}")),
                content_hash=str(entry.get("content_hash", f"hash-{index}")),
                content_summary=str(entry.get("summary", "evaluation fact")),
                provenance=dict(entry.get("provenance", {})) if isinstance(entry.get("provenance"), Mapping) else {},
            )
            stored.append(store.store(item, audit_id=audit_id))
        engine = CorrelationEngine(store)
        observations, candidates, conflicts = engine.correlate(audit_id=audit_id)
        return {
            "stored_evidence": len(stored),
            "observation_count": len(observations),
            "candidate_count": len(candidates),
            "conflict_count": len(conflicts),
            "relation_count": len(engine.relations),
            "candidate_statuses": sorted({c.status.value for c in candidates}),
            "rule_ids": sorted({c.rule_id for c in candidates}),
        }

    def _op_coverage(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.verification.coverage import VerificationControls, assess_coverage

        controls_raw = payload.get("controls", {})
        controls_raw = dict(controls_raw) if isinstance(controls_raw, Mapping) else {}
        controls = VerificationControls(
            positive_control=str(controls_raw.get("positive", "PRESENT")).upper(),
            negative_control=str(controls_raw.get("negative", "PRESENT")).upper(),
        )
        assessment = assess_coverage(
            oracle_outcome=str(payload.get("oracle_outcome", "CONFIRMED")),
            controls=controls,
            operational_result=str(payload.get("operational_result", "OK")),
            response_coverage=str(payload.get("response_coverage", "complete")),
            limitations=tuple(str(item) for item in payload.get("limitations", ())),
        )
        return {
            "coverage": assessment.coverage,
            "conclusion_ceiling": assessment.conclusion_ceiling,
            "coverage_limitations": list(assessment.limitations),
        }

    def _op_report(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.core.findings import SecurityFinding
        from emo_cyber_agent.core.reporting import ReportService

        audit_id = str(payload.get("audit_id", "audit-eval"))
        raw = payload.get("findings", [])
        findings: list[SecurityFinding] = []
        rejected = 0
        if isinstance(raw, (list, tuple)):
            for entry in raw:
                if not isinstance(entry, Mapping):
                    rejected += 1
                    continue
                try:
                    findings.append(SecurityFinding(**dict(entry)))
                except Exception:  # noqa: BLE001 - malformed fixture entry
                    rejected += 1
        service = ReportService()
        report = service.generate(
            audit_id=audit_id,
            findings=findings,
            include_non_reportable=bool(payload.get("include_non_reportable", False)),
        )
        text = service.generate_json(report)
        stable = report.model_dump(mode="json")
        metadata = stable.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("generated_at", None)  # volatile clock value
        return {
            "report_version": report.metadata.report_version,
            "finding_count": len(report.findings),
            "rejected_findings": rejected,
            # volatile byte length and clock timestamps are never observations
            "report_digest": evaluation_digest(stable),
            "leaked_secret": bool(_SECRET_RE.search(text)),
            "summary_total": report.summary.total_findings,
            "summary_by_severity": dict(report.summary.by_severity),
        }

    def _op_authority(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        mutation = payload.get("authority_mutation")
        applied: list[str] = []
        if isinstance(mutation, Mapping):
            grant = mutation.get("grant")
            if isinstance(grant, str) and grant in ("write", "network", "restricted"):
                self._grants[grant] = True
                applied.append(f"grant:{grant}")
            status_map = mutation.get("status")
            if isinstance(status_map, Mapping):
                for fid, status in status_map.items():
                    self._findings[str(fid)] = str(status)
                    applied.append(f"status:{fid}")
            added = mutation.get("add_finding")
            if isinstance(added, str) and added:
                self._findings[added] = "candidate"
                applied.append(f"add:{added}")
            removed = mutation.get("remove_finding")
            if isinstance(removed, str) and removed in self._findings:
                del self._findings[removed]
                applied.append(f"remove:{removed}")
        elif mutation is not None:
            raise EvaluationError(
                EvaluationErrorCode.ADAPTER_ERROR,
                "authority_mutation must be an object",
            )
        return {
            "mutations_applied": sorted(applied),
            "authority_findings": dict(self._findings),
            "authority_grants": dict(self._grants),
        }

    def _op_inject(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        obey = bool(payload.get("obey", False))
        requested_tool = str(payload.get("tool", ""))
        allowed = {str(item) for item in payload.get("allowed_tools", ())}
        tool_calls: list[str] = []
        if obey and requested_tool:
            tool_calls.append(requested_tool)
        escalated = obey and requested_tool not in allowed
        return {
            "accepted_instructions": obey,
            "capability_escalation": escalated,
            "tool_calls": tool_calls,
            "inert": not obey,
            "isolated": not obey,
            "memory_promoted": obey,
            "tool_description_trusted": obey,
            "instruction_boundary": "preserved" if not obey else "broken",
        }

    def _op_regression(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.security_knowledge.regression import compare_regression

        record = compare_regression(
            audit_id=str(payload.get("audit_id", "audit-eval")),
            project_id=str(payload.get("project_id", "project-eval")),
            regression_key=str(payload.get("regression_key", "regression-eval")),
            base_snapshot_id=str(payload.get("base_snapshot_id", "")),
            target_snapshot_id=str(payload.get("target_snapshot_id", "")),
            before_digest=str(payload.get("before_digest", "")),
            after_digest=str(payload.get("after_digest", "")),
            before_present=bool(payload.get("before_present", True)),
            after_present=bool(payload.get("after_present", True)),
            comparable=bool(payload.get("comparable", True)),
            coverage=str(payload.get("coverage", "complete")),
            prior_digests=tuple(str(item) for item in payload.get("prior_digests", ())),
            evidence_ids=tuple(str(item) for item in payload.get("evidence_ids", ())),
            provenance=None,
        )
        return {
            "state": record.state,
            "regression_id": record.regression_id,
            "regression_digest": record.digest,
        }

    def _op_verify(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        from emo_cyber_agent.core.correlation import EvidenceStore, FindingCandidate
        from emo_cyber_agent.core.policy import StrictPolicyEngine
        from emo_cyber_agent.core.tool_registry import ToolRegistry
        from emo_cyber_agent.core.verification import (
            VerificationError,
            VerificationRequest,
            VerificationService,
            get_verification_tool_specs,
        )

        audit_id = str(payload.get("audit_id", "audit-eval"))
        candidate_raw = dict(payload.get("candidate", {}))
        candidate = FindingCandidate(
            audit_id=audit_id,
            hypothesis=str(candidate_raw.get("hypothesis", "evaluation hypothesis")),
            evidence_ids=tuple(str(item) for item in candidate_raw.get("evidence_ids", ("ev-1",))),
            rule_id=str(candidate_raw.get("rule_id", "R3-secret-exposure")),
            provisional_severity=str(candidate_raw.get("provisional_severity", "high")),
        )
        locator = str(payload.get("locator", "evaluation-target"))
        registry = ToolRegistry()
        for spec in get_verification_tool_specs():
            registry.register(spec)
        service = VerificationService(
            executor=_PlanOnlyHarness(),
            policy=StrictPolicyEngine(),
            registry=registry,
            store=EvidenceStore(),
            scope_allows=lambda a, t: a == audit_id and t == locator,
            profile=str(payload.get("profile", "read_only")),
        )
        try:
            request = VerificationRequest(
                method=str(payload.get("method", "static_confirmation")),
                target={"kind": str(payload.get("kind", "repository")), "locator": locator},
                rationale_summary=str(payload.get("rationale", "evaluation verification")),
                statement=str(payload.get("statement", "")),
            )
            plan = service.plan(candidate=candidate, request=request, audit_id=audit_id)
        except VerificationError as exc:
            return {
                "status": "blocked",
                "error_code": str(exc.code.value),
                "method": str(payload.get("method", "")),
                "safety_level": "",
                "required_capabilities": [],
            }
        except ValueError as exc:
            raise EvaluationError(
                EvaluationErrorCode.ADAPTER_ERROR,
                f"verification input invalid: {exc}",
            ) from exc
        return {
            "status": "planned",
            "method": request.method.value,
            "safety_level": plan.safety_level.value,
            "required_capabilities": list(plan.required_capabilities),
            "stopping_conditions": list(plan.stopping_conditions),
            "isolated_constraints": bool(plan.constraints.get("isolated", False)),
        }


class _PlanOnlyHarness(VerificationExecutorPort):
    """Plans only: an evaluation never executes a verification."""

    def run(self, plan: VerificationPlan) -> VerificationRawResult:
        raise EvaluationError(
            EvaluationErrorCode.ADAPTER_ERROR,
            "verification execution is not part of evaluation planning",
        )
