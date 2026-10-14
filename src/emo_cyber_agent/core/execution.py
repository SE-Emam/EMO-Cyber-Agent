"""Tool execution boundary — ECA-T007.

ToolExecutionPort executes ONLY authorized ToolInvocations. It contains no
security reasoning, severity, remediation, or classification logic.

Process boundary guarantees:
- argv arrays only (never shell strings, never shell=True);
- explicit confined cwd (audit root; traversal/absolute/symlink escapes denied);
- environment allowlist (default: NO SECRET ENVIRONMENT);
- execution timeout, stdout/stderr byte limits with truncation metadata;
- exit-code/signal capture; distinct UNAVAILABLE/TIMEOUT/DENIED/FAILED states.

POSIX timeouts terminate the process group. Descendants that retain output
pipes after the direct child exits remain an unresolved cleanup limitation.
Non-POSIX timeout handling kills only the direct child.

ToolExecutor is the only orchestrator: registry resolve → strict-policy
decision → argv build (from trusted ToolSpec + fixed adapter logic, NEVER
from repository content) → port execution → invocation record.
It REFUSES to run with any policy engine that is not StrictPolicyEngine,
so the legacy allow-all DefaultPolicyEngine can never become a workaround.
"""

from __future__ import annotations

# Preserve fail-closed handling for unexpected provider/runtime failures.
UNEXPECTED_EXCEPTION: type[Exception] = Exception

import hashlib
import os
import selectors
import signal
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.core.policy import StrictPolicyEngine
from emo_cyber_agent.core.tool_registry import ToolInvocation, ToolRegistry

# Minimal safe environment. Secrets are NEVER inherited.
SAFE_ENV_ALLOWLIST: tuple[str, ...] = ("NO_COLOR", "LC_ALL", "LANG", "TZ")
SECRET_ENV_BLOCKLIST = ("GITHUB_TOKEN", "GH_TOKEN", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY", "DATABASE_URL", "POSTGRES_PASSWORD", "AWS_SECRET_ACCESS_KEY", "API_KEY", "SECRET", "TOKEN", "PASSWORD")

MAX_STDOUT_BYTES = 256 * 1024
MAX_STDERR_BYTES = 64 * 1024
DEFAULT_TIMEOUT_S = 120


class ExecutionOutcome(StrEnum):
    SUCCESS = "success"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TIMEOUT = "timeout"
    POLICY_DENIED = "policy_denied"
    TOOL_FAILED = "tool_failed"


class ExecutionError(Exception):
    def __init__(self, outcome: ExecutionOutcome, message: str):
        super().__init__(f"{outcome.value}: {message}")
        self.outcome = outcome


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    argv: tuple[str, ...]
    cwd: str
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: int = Field(default=DEFAULT_TIMEOUT_S, ge=1, le=1800)
    stdout_limit: int = Field(default=MAX_STDOUT_BYTES, ge=1024)
    stderr_limit: int = Field(default=MAX_STDERR_BYTES, ge=1024)


class ExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    outcome: ExecutionOutcome = ExecutionOutcome.SUCCESS
    started_at: str = ""
    completed_at: str = ""
    argv_digest: str = ""
    env_fingerprint: str = ""  # sorted key names only, never values


def _run_posix_process(
    process: subprocess.Popen[bytes], request: ExecutionRequest, started: str
) -> ExecutionResult:
    """Drain a POSIX process tree to one absolute deadline with bounded cleanup."""
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    seen = {"stdout": 0, "stderr": 0}
    streams = (
        (process.stdout, "stdout", request.stdout_limit),
        (process.stderr, "stderr", request.stderr_limit),
    )
    selector: selectors.BaseSelector | None = None
    timed_out = False
    cleanup_failed = False
    lifecycle_complete = False
    exit_code: int | None = None

    def retain(name: str, chunk: bytes, limit: int) -> None:
        seen[name] += len(chunk)
        room = max(0, limit - len(captured[name]))
        if room:
            captured[name].extend(chunk[:room])

    try:
        selector = selectors.DefaultSelector()
        for stream, name, limit in streams:
            if stream is None:
                continue
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, limit))

        deadline = time.monotonic() + request.timeout_s
        cleanup_deadline: float | None = None
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if cleanup_deadline is None and now >= deadline and (process.poll() is None or selector.get_map()):
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                cleanup_deadline = now + 0.5
            if cleanup_deadline is not None and now >= cleanup_deadline:
                break
            if not selector.get_map() and process.poll() is not None:
                break

            wait_until = cleanup_deadline if cleanup_deadline is not None else deadline
            timeout = max(0.0, min(0.05, wait_until - now))
            for key, _ in selector.select(timeout=timeout):
                ready_fd = key.fd
                name, limit = key.data
                try:
                    chunk = os.read(ready_fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if chunk:
                    retain(name, chunk, limit)
                else:
                    selector.unregister(key.fileobj)
        lifecycle_complete = not timed_out
    finally:
        # Any failure after Popen must still terminate the isolated process
        # group, reap its leader with a bound, and close our pipe descriptors.
        if process.poll() is None or not lifecycle_complete:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_failed = True
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                cleanup_failed = True
        exit_code = process.poll()
        if selector is not None:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except (KeyError, ValueError):
                    pass
            try:
                selector.close()
            except OSError:
                cleanup_failed = True
        for stream, _, _ in streams:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    cleanup_failed = True

    if cleanup_failed:
        timed_out = True
    return ExecutionResult(
        exit_code=exit_code,
        stdout=bytes(captured["stdout"]).decode("utf-8", errors="replace"),
        stderr=bytes(captured["stderr"]).decode("utf-8", errors="replace"),
        stdout_truncated=seen["stdout"] > request.stdout_limit,
        stderr_truncated=seen["stderr"] > request.stderr_limit,
        timed_out=timed_out,
        outcome=ExecutionOutcome.TIMEOUT if timed_out else (
            ExecutionOutcome.SUCCESS if exit_code == 0 else ExecutionOutcome.TOOL_FAILED
        ),
        started_at=started,
        completed_at=datetime.now(UTC).isoformat(),
        argv_digest=_digest_argv(request.argv),
        env_fingerprint=_env_fingerprint(request.env),
    )


def sanitized_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build the subprocess environment from the allowlist only."""
    env: dict[str, str] = {}
    for key in SAFE_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value[:256]
    for key, value in (extra or {}).items():
        upper = key.upper()
        if key not in SAFE_ENV_ALLOWLIST:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, f"env key not allowlisted: {key}")
        if any(blocked in upper for blocked in SECRET_ENV_BLOCKLIST):
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, f"secret env denied: {key}")
        env[key] = value[:256]
    return env


def confine_path(audit_root: str, target: str) -> str:
    """Resolve target inside audit_root. Escapes → ExecutionError (DENY)."""
    if not target or not target.strip():
        raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "empty target")
    t = target.strip()
    if "\x00" in t:
        raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "null byte in target")
    root = os.path.realpath(audit_root)
    joined = os.path.realpath(os.path.join(root, t)) if not os.path.isabs(t) else os.path.realpath(t)
    if joined != root and not joined.startswith(root + os.sep):
        raise ExecutionError(ExecutionOutcome.POLICY_DENIED, f"filesystem escape denied: {t[:80]}")
    return joined


def _digest_argv(argv: tuple[str, ...]) -> str:
    return hashlib.sha256(("\x00".join(argv)).encode("utf-8", errors="replace")).hexdigest()


def _env_fingerprint(env: dict[str, str]) -> str:
    return hashlib.sha256(("\x00".join(sorted(env.keys()))).encode()).hexdigest()


class ToolExecutionPort(ABC):
    """Executes an authorized argv request. No reasoning, no classification."""

    @abstractmethod
    def run(self, request: ExecutionRequest) -> ExecutionResult: ...


class ProcessExecutionPort(ToolExecutionPort):
    """Real subprocess boundary: argv-only, no shell, confined, limited."""

    def run(self, request: ExecutionRequest) -> ExecutionResult:
        if not request.argv or any(not isinstance(a, str) for a in request.argv):
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "argv must be a non-empty string array")
        if any("\x00" in a for a in request.argv):
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "null byte in argv")
        started = datetime.now(UTC).isoformat()
        try:
            process = subprocess.Popen(
                list(request.argv),
                shell=False,
                cwd=request.cwd,
                env=dict(request.env),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
            )
            if os.name == "posix":
                return _run_posix_process(process, request, started)

            captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
            seen = {"stdout": 0, "stderr": 0}

            def drain(name: str, stream: Any, limit: int) -> None:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    seen[name] += len(chunk)
                    room = max(0, limit - len(captured[name]))
                    if room:
                        captured[name].extend(chunk[:room])

            readers = [
                threading.Thread(target=drain, args=("stdout", process.stdout, request.stdout_limit), daemon=True),
                threading.Thread(target=drain, args=("stderr", process.stderr, request.stderr_limit), daemon=True),
            ]
            for reader in readers:
                reader.start()
            try:
                exit_code = process.wait(timeout=request.timeout_s)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                for reader in readers:
                    reader.join(timeout=1)
                return ExecutionResult(
                    outcome=ExecutionOutcome.TIMEOUT,
                    timed_out=True,
                    stdout=bytes(captured["stdout"]).decode("utf-8", errors="replace"),
                    stderr=bytes(captured["stderr"]).decode("utf-8", errors="replace"),
                    stdout_truncated=seen["stdout"] > request.stdout_limit,
                    stderr_truncated=seen["stderr"] > request.stderr_limit,
                    started_at=started,
                    completed_at=datetime.now(UTC).isoformat(),
                    argv_digest=_digest_argv(request.argv),
                    env_fingerprint=_env_fingerprint(request.env),
                )
            for reader in readers:
                reader.join()
        except FileNotFoundError:
            return ExecutionResult(outcome=ExecutionOutcome.TOOL_UNAVAILABLE, started_at=started, completed_at=datetime.now(UTC).isoformat(), argv_digest=_digest_argv(request.argv), env_fingerprint=_env_fingerprint(request.env), stderr=f"tool unavailable: {request.argv[0][:60]}"[:500])
        except OSError as e:
            return ExecutionResult(outcome=ExecutionOutcome.TOOL_FAILED, started_at=started, completed_at=datetime.now(UTC).isoformat(), argv_digest=_digest_argv(request.argv), env_fingerprint=_env_fingerprint(request.env), stderr=f"execution failed: {e}"[:500])
        stdout = bytes(captured["stdout"]).decode("utf-8", errors="replace")
        stderr = bytes(captured["stderr"]).decode("utf-8", errors="replace")
        outcome = ExecutionOutcome.SUCCESS if exit_code == 0 else ExecutionOutcome.TOOL_FAILED
        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=seen["stdout"] > request.stdout_limit,
            stderr_truncated=seen["stderr"] > request.stderr_limit,
            outcome=outcome,
            started_at=started,
            completed_at=datetime.now(UTC).isoformat(),
            argv_digest=_digest_argv(request.argv),
            env_fingerprint=_env_fingerprint(request.env),
        )


class ToolExecutor:
    """Registry → StrictPolicy → argv (trusted spec + fixed adapter logic) → port → invocation.

    `argv_builder` and `parse` come from the scanner adapter (fixed logic).
    Repository content NEVER influences argv (tested).
    """

    def __init__(self, *, registry: ToolRegistry, policy: StrictPolicyEngine, port: ToolExecutionPort, audit_root: str):
        if not isinstance(policy, StrictPolicyEngine):
            raise TypeError("ToolExecutor requires StrictPolicyEngine (allow-all engines denied)")
        self._registry = registry
        self._policy = policy
        self._port = port
        self._audit_root = os.path.realpath(audit_root)

    def execute(
        self,
        *,
        audit_id: str,
        tool_id: str,
        target: str,
        capability: str,
        profile: str = "read_only",
        policy_decision_id: str | None,
        argv_builder: Any,
        parse: Any | None = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> tuple[Any, ToolInvocation, ExecutionResult]:
        from emo_cyber_agent.core import tool_registry as _tr

        if not policy_decision_id:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "execution without policy decision")
        try:
            spec = self._registry.get(tool_id)
        except ValueError as e:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, f"unregistered execution: {tool_id}") from e
        if capability not in spec.capabilities_required:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, f"undeclared capability: {capability}")
        confined = confine_path(self._audit_root, target)
        decision = self._policy.get_decision(policy_decision_id)
        if decision is None or not decision.allowed:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "missing or denied policy decision")
        if decision.audit_id != audit_id or capability not in decision.requested_capability:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "stale or mismatched policy decision")
        from emo_cyber_agent.core.policy import POLICY_VERSION as _CURRENT_POLICY_VERSION

        if decision.policy_version != _CURRENT_POLICY_VERSION:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "stale policy version")
        if decision.target != target:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "decision bound to a different target")
        argv = tuple(argv_builder(spec, confined))
        if not argv:
            raise ExecutionError(ExecutionOutcome.POLICY_DENIED, "empty argv denied")

        inv = ToolInvocation(audit_id=audit_id, tool_id=tool_id, tool_version=spec.version, target=target, requested_capabilities=(capability,), policy_decision_id=policy_decision_id, profile=profile)
        for state in (_tr.ToolInvocationStatus.VALIDATING, _tr.ToolInvocationStatus.POLICY_CHECK, _tr.ToolInvocationStatus.APPROVED, _tr.ToolInvocationStatus.EXECUTING):
            inv = inv.transition_to(state)
        result = self._port.run(ExecutionRequest(argv=argv, cwd=self._audit_root, env=sanitized_env(), timeout_s=timeout_s))
        if result.outcome == ExecutionOutcome.SUCCESS:
            if result.stdout_truncated or result.stderr_truncated:
                raise ExecutionError(ExecutionOutcome.TOOL_FAILED, f"{tool_id} output exceeded the configured limit")
            try:
                parsed = parse(result.stdout) if parse else {"stdout_digest": hashlib.sha256(result.stdout.encode(errors="replace")).hexdigest()}
            except UNEXPECTED_EXCEPTION as exc:
                raise ExecutionError(ExecutionOutcome.TOOL_FAILED, f"{tool_id} output could not be validated") from exc
            return parsed, inv.update_output(f"{tool_id} exit=0 observations recorded", evidence_ids=()), result
        if result.outcome == ExecutionOutcome.TOOL_UNAVAILABLE:
            raise ExecutionError(ExecutionOutcome.TOOL_UNAVAILABLE, result.stderr[:200])
        if result.outcome == ExecutionOutcome.TIMEOUT:
            raise ExecutionError(ExecutionOutcome.TIMEOUT, f"{tool_id} timed out")
        raise ExecutionError(ExecutionOutcome.TOOL_FAILED, result.stderr[:300] or f"{tool_id} failed")
