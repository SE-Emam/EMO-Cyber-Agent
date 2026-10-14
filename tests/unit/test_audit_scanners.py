"""Audit facade integration tests for local scanner evidence collection."""

import asyncio
import json
import os

from emo_cyber_agent.adapters.mock_scanners import SECRET_OUTPUT
from emo_cyber_agent.core.execution import ExecutionOutcome, ExecutionResult
from emo_cyber_agent.core.service import FoundationSecurityAuditor


class AuditScannerPort:
    def __init__(self, scan_output=SECRET_OUTPUT, *, outcome=ExecutionOutcome.SUCCESS, truncated=False):
        self.scan_output = scan_output
        self.outcome = outcome
        self.truncated = truncated
        self.requests = []

    def run(self, request):
        self.requests.append(request)
        is_version = len(request.argv) > 1 and request.argv[1] == "version"
        return ExecutionResult(
            exit_code=0,
            stdout="8.30.1\n" if is_version else self.scan_output,
            stdout_truncated=False if is_version else self.truncated,
            outcome=ExecutionOutcome.SUCCESS if is_version else self.outcome,
            started_at="2026-10-13T00:00:00+00:00",
            completed_at="2026-10-13T00:00:01+00:00",
            argv_digest="test",
            env_fingerprint="test",
        )


def test_audit_runs_local_gitleaks_and_returns_redacted_evidence(tmp_path):
    port = AuditScannerPort()
    auditor = FoundationSecurityAuditor(
        execution_port=port,
        binary_lookup=lambda name: "/opt/homebrew/bin/gitleaks" if name == "gitleaks" else None,
    )

    result = asyncio.run(auditor.audit(str(tmp_path)))

    assert result.status == "completed"
    assert result.completed_at is not None
    assert result.coverage.controls_total == 1
    assert result.coverage.controls_evaluated == 1
    assert result.coverage.controls_not_evaluated == 0
    assert "control-catalog-emo-controls-v1" in result.coverage.notes
    run = result.metadata["scanner_runs"][0]
    assert run["tool"] == "gitleaks" and run["version"] == "8.30.1"
    assert run["status"] == "completed" and run["observation_count"] == 1
    assert run["result_digest"] and run["invocation_id"]
    evidence_json = json.dumps(result.metadata["evidence"])
    assert "SUPERSECRETVALUE999" not in evidence_json
    assert "ghp_REALTOKEN123" not in evidence_json
    assert len(result.findings) == 1  # one observation -> one suspected finding
    finding = result.findings[0]
    assert finding.severity == "high" and finding.status == "suspected"
    assert finding.confidence == 0.75
    assert finding.evidence_ids and finding.id
    findings_json = json.dumps([f.model_dump(mode="json") for f in result.findings])
    assert "SUPERSECRETVALUE999" not in findings_json
    assert "ghp_REALTOKEN123" not in findings_json
    assert len(port.requests) == 2
    assert port.requests[1].argv[0] == os.path.realpath("/opt/homebrew/bin/gitleaks")
    assert "--redact=100" in port.requests[1].argv
    assert "--ignore-gitleaks-allow" in port.requests[1].argv
    config_path = port.requests[1].argv[port.requests[1].argv.index("--config") + 1]
    ignore_path = port.requests[1].argv[port.requests[1].argv.index("--gitleaks-ignore-path") + 1]
    assert config_path.endswith("docs/policies/gitleaks-default.toml")
    assert ignore_path.endswith("docs/policies/empty-gitleaksignore")
    assert evidence_json.find('"invocation_id"') >= 0


def test_audit_fails_closed_for_truncated_scanner_output(tmp_path):
    port = AuditScannerPort(scan_output="[]", truncated=True)
    auditor = FoundationSecurityAuditor(
        execution_port=port,
        binary_lookup=lambda name: "/opt/homebrew/bin/gitleaks" if name == "gitleaks" else None,
    )

    result = asyncio.run(auditor.audit(str(tmp_path)))

    assert result.status == "partial"
    assert result.tool_failures == ["gitleaks: scan failed, was denied, or output was incomplete"]
    assert result.metadata["evidence"] == []
    assert result.metadata["scanner_runs"][-1]["status"] == "failed"


def test_audit_records_unavailable_local_scanner(tmp_path):
    auditor = FoundationSecurityAuditor(binary_lookup=lambda _name: None)

    result = asyncio.run(auditor.audit(str(tmp_path)))

    assert result.status == "partial"
    assert result.tool_failures == ["gitleaks: tool unavailable"]
    assert result.metadata["scanner_runs"] == [{
        "tool": "gitleaks", "status": "unavailable", "observation_count": 0,
    }]


def test_audit_respects_caller_policy_denial(tmp_path):
    from emo_cyber_agent.core.service import DefaultPolicyEngine

    class DenyScope(DefaultPolicyEngine):
        def check_scope(self, _audit_id, _target):
            return False

    port = AuditScannerPort()
    auditor = FoundationSecurityAuditor(
        policy_engine=DenyScope(),
        execution_port=port,
        binary_lookup=lambda _name: "/opt/homebrew/bin/gitleaks",
    )

    result = asyncio.run(auditor.audit(str(tmp_path)))

    assert result.status == "partial"
    assert result.metadata["scanner_runs"][0]["status"] == "policy-denied"
    assert result.tool_failures == ["gitleaks: caller policy denied local scan"]
    assert port.requests == []
