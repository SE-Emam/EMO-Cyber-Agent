"""Application service facade.

Implements the SecurityAuditor and PolicyEngine contracts for Phase 2 Tool Registry.
Core domain logic lives in domain models and contracts; adapters remain thin.
"""

from __future__ import annotations

# Preserve fail-closed handling for unexpected provider/runtime failures.
UNEXPECTED_EXCEPTION: type[Exception] = Exception

import os
import shutil
from typing import TYPE_CHECKING, Any

from emo_cyber_agent.core.contracts import PolicyEngine, SecurityAuditor
from emo_cyber_agent.domain.models import (
    AuditJob,
    AuditMode,
    AuditResult,
    AuditResultStatus,
    Coverage,
    EvidenceItem,
    PermissionProfile,
)

if TYPE_CHECKING:
    from emo_cyber_agent.core.tool_registry import ToolRegistry


class DefaultPolicyEngine(PolicyEngine):
    """Default read-only policy engine for foundation."""

    def check_scope(self, audit_id: str, target: str) -> bool:
        return True

    def check_capability(self, tool_id: str, capability: str) -> bool:
        return True

    def check_permission(self, profile: str, tool_id: str, risk_level: str, read_only: bool) -> bool:
        return not (profile in ("read_only", "remediate") and not read_only)

    def check_target(self, target: str) -> bool:
        return bool(target)

    def classify_content(self, content: str) -> str:
        if any(
            keyword in content.lower()
            for keyword in ["exec(", "eval(", "system(", "subprocess."]
        ):
            return "potential-instruction"
        return "code-or-data"

    def evaluate_policy(
        self,
        audit_id: str,
        tool_id: str,
        target: str,
        profile: str,
        capabilities: list[str],
    ) -> bool:
        """Evaluate whether a tool invocation is allowed."""
        # For Phase 2, allow all invocations
        # Phase 3 will implement actual policy evaluation
        return True


class FoundationSecurityAuditor(SecurityAuditor):
    """Concrete SecurityAuditor for Phase 2 Foundation.

    All adapters (MCP, CLI, Python API) call this same interface.
    The Core owns the security investigation workflow after delegation.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        *,
        execution_port: Any | None = None,
        binary_lookup: Any | None = None,
    ) -> None:
        self._policy_engine = policy_engine or DefaultPolicyEngine()
        from .scanners import get_scanner_tool_specs
        from .tool_registry import ToolRegistry

        self._tool_registry = ToolRegistry()
        for spec in get_scanner_tool_specs():
            self._tool_registry.register(spec)
        self._execution_port = execution_port
        self._binary_lookup = binary_lookup or shutil.which

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def tool_registry(self) -> ToolRegistry:
        return self._tool_registry

    async def audit(
        self,
        target: str,
        mode: str = "standard",
        permission_profile: str = "read_only",
        **kwargs: Any,
    ) -> AuditResult:
        """Run a full or scoped security audit.

        Collect local Gitleaks observations through the strict tool boundary.
        This is evidence collection only: results remain partial until the
        finding classification and full coverage workflow is implemented.
        """
        job = AuditJob(
            target=target,
            mode=AuditMode(mode),
            permission_profile=PermissionProfile(permission_profile),
        )

        scanner_runs: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        failures: list[str] = []
        coverage_notes = [
            "partial-evidence-collection-only",
            "semgrep-not-run-until-offline-rule-configuration-is-verified",
            "trivy-and-osv-scanner-not-run",
        ]

        try:
            from pathlib import Path

            from .execution import (
                ExecutionError,
                ExecutionOutcome,
                ExecutionRequest,
                ProcessExecutionPort,
                ToolExecutor,
            )
            from .policy import StrictPolicyEngine
            from .resources import gitleaks_policy_paths
            from .scanners import GitleaksAdapter, observation_to_evidence_fields

            resolved_target = Path(target).expanduser().resolve(strict=True)
            if not resolved_target.exists():
                raise ValueError("target does not exist")
            scan_root = resolved_target if resolved_target.is_dir() else resolved_target.parent
            scan_target = "." if resolved_target.is_dir() else resolved_target.name
            binary = self._binary_lookup("gitleaks")
            if not binary:
                failures.append("gitleaks: tool unavailable")
                scanner_runs.append({"tool": "gitleaks", "status": "unavailable", "observation_count": 0})
            else:
                tool_spec = self._tool_registry.get("gitleaks")
                caller_allowed = all((
                    self._policy_engine.check_scope(job.id, str(resolved_target)),
                    self._policy_engine.check_capability("gitleaks", "scanner.local.execute"),
                    self._policy_engine.check_permission(
                        permission_profile, "gitleaks", tool_spec.risk_level.value, read_only=True
                    ),
                    self._policy_engine.check_target(str(resolved_target)),
                    self._policy_engine.evaluate_policy(
                        job.id, "gitleaks", str(resolved_target), permission_profile, ["scanner.local.execute"]
                    ),
                ))
                if not caller_allowed:
                    failures.append("gitleaks: caller policy denied local scan")
                    scanner_runs.append({"tool": "gitleaks", "status": "policy-denied", "observation_count": 0})
                    result = AuditResult(
                        audit_id=job.id, status=AuditResultStatus.PARTIAL, target=target, mode=AuditMode(mode),
                        permission_profile=PermissionProfile(permission_profile), coverage=Coverage(notes=coverage_notes),
                        tool_failures=failures,
                        limitations=["Scanner observations are unclassified evidence; no EMO findings or severities were inferred."],
                        metadata={"scanner_runs": scanner_runs, "evidence": evidence},
                    )
                    return result
                binary = os.path.realpath(binary)
                version_port = self._execution_port or ProcessExecutionPort()
                version_result = version_port.run(
                    ExecutionRequest(argv=(binary, "version"), cwd=str(scan_root), timeout_s=10)
                )
                if (version_result.outcome != ExecutionOutcome.SUCCESS or version_result.stdout_truncated
                        or version_result.stderr_truncated or not version_result.stdout.strip()):
                    failures.append("gitleaks: local version check failed")
                    scanner_runs.append({"tool": "gitleaks", "status": "version-check-failed", "observation_count": 0})
                else:
                    native_version = version_result.stdout.strip()[:120]
                    spec = self._tool_registry.get("gitleaks").model_copy(update={"version": native_version})
                    registry = type(self._tool_registry)()
                    registry.register(spec)
                    scope_policy = StrictPolicyEngine(
                        scope_allows=lambda audit_id, requested: audit_id == job.id and requested == scan_target
                    )
                    decision = scope_policy.issue_decision(
                        job.id, "gitleaks", scan_target, "read_only", ["scanner.local.execute"]
                    )
                    if not decision.allowed:
                        failures.append("gitleaks: strict policy denied local scan")
                        scanner_runs.append({"tool": "gitleaks", "status": "policy-denied", "observation_count": 0})
                    else:
                        executor = ToolExecutor(
                            registry=registry,
                            policy=scope_policy,
                            port=self._execution_port or ProcessExecutionPort(),
                            audit_root=str(scan_root),
                        )
                        try:
                            with gitleaks_policy_paths() as (config_path, ignore_path):
                                adapter = GitleaksAdapter(
                                    binary_path=binary,
                                    config_path=str(config_path),
                                    ignore_path=str(ignore_path),
                                )
                                parsed, invocation, _execution = executor.execute(
                                    audit_id=job.id,
                                    tool_id="gitleaks",
                                    target=scan_target,
                                    capability="scanner.local.execute",
                                    policy_decision_id=decision.decision_id,
                                    argv_builder=adapter.argv,
                                    parse=adapter.parse,
                                    timeout_s=120,
                                )
                            for observation in parsed["observations"]:
                                fields = observation_to_evidence_fields(
                                    observation,
                                    audit_id=job.id,
                                    asset_id="target",
                                    invocation_id=invocation.invocation_id,
                                    target=scan_target,
                                )
                                evidence_item = EvidenceItem(
                                    source_tool=observation.tool_id,
                                    source_version=native_version,
                                    target_asset_id="target",
                                    location=fields["locator"],
                                    content_hash=fields["content_digest"],
                                    content_summary=fields["summary"],
                                    provenance={
                                        **fields["provenance"],
                                        "audit_id": job.id,
                                        "invocation_id": invocation.invocation_id,
                                        "target": scan_target,
                                        "asset_id": "target",
                                    },
                                )
                                evidence.append(evidence_item.model_dump(mode="json"))
                            scanner_runs.append({
                                "tool": "gitleaks",
                                "version": native_version,
                                "status": invocation.status.value,
                                "invocation_id": invocation.invocation_id,
                                "observation_count": parsed["count"],
                                "result_digest": parsed["result_digest"],
                            })
                        except ExecutionError:
                            failures.append("gitleaks: scan failed, was denied, or output was incomplete")
                            scanner_runs.append({"tool": "gitleaks", "status": "failed", "observation_count": 0})
        except UNEXPECTED_EXCEPTION as exc:
            # Do not copy tool output or repository-controlled exception text
            # into reports; it may contain secrets or hostile content.
            failures.append(f"local scanner collection failed: {type(exc).__name__}")
            scanner_runs.append({"tool": "gitleaks", "status": "failed", "observation_count": 0})

        result = AuditResult(
            audit_id=job.id,
            status=AuditResultStatus.PARTIAL,
            target=target,
            mode=AuditMode(mode),
            permission_profile=PermissionProfile(permission_profile),
            coverage=Coverage(notes=coverage_notes),
            tool_failures=failures,
            limitations=[
                "Scanner observations are unclassified evidence; no EMO findings or severities were inferred.",
                "The security audit remains partial because full control coverage and finding analysis are not implemented.",
            ],
            metadata={"scanner_runs": scanner_runs, "evidence": evidence},
        )
        return result

    async def review(
        self,
        target: str,
        focus: list[str] | None = None,
        **kwargs: Any,
    ) -> AuditResult:
        """Run a focused review of provided code/context.

        Phase 2: Stub only.
        Phase 8+: Full reasoning loop.
        """
        job = AuditJob(
            target=target,
            mode=AuditMode.STANDARD,
            permission_profile=PermissionProfile.READ_ONLY,
        )
        result = AuditResult(
            audit_id=job.id,
            status=AuditResultStatus.PARTIAL,
            target=target,
            mode=AuditMode.STANDARD,
            permission_profile=PermissionProfile.READ_ONLY,
            coverage=Coverage(notes=["review-engine-not-implemented"]),
            tool_failures=["review engine is not connected to security analysis"],
            limitations=["No security review was performed by this foundation implementation."],
        )
        return result

    async def verify(
        self,
        finding_id: str,
        permission_profile: str = "read_only",
        **kwargs: Any,
    ) -> AuditResult:
        """Verify a specific finding using only policy-approved actions.

        Phase 2: Stub only.
        Phase 9+: Full verification loop.
        """
        job = AuditJob(
            target="verification",
            mode=AuditMode.STANDARD,
            permission_profile=PermissionProfile(permission_profile),
        )
        result = AuditResult(
            audit_id=job.id,
            status=AuditResultStatus.PARTIAL,
            target="verification",
            mode=AuditMode.STANDARD,
            permission_profile=PermissionProfile(permission_profile),
            coverage=Coverage(notes=["verification-engine-not-implemented"]),
            tool_failures=["verification engine is not connected to verification execution"],
            limitations=["No finding verification was performed by this foundation implementation."],
        )
        return result

    async     def doctor(self) -> dict[str, Any]:
        """Return runtime capability status without exposing credentials."""
        return {
            "status": "foundation",
            "version": "0.2.2",
            "policy_engine": type(self._policy_engine).__name__,
            "domain_models_available": True,
            "capabilities": ["audit", "review", "verify", "doctor"],
        }
