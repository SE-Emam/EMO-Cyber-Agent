"""POST-RC-013 — system-under-test adapters.

The scripted reference implementation (13 operations), the Python API
adapter, and the CLI/MCP adapters with their capability, argument, and
denied-flag handling. Everything runs in-process: no subprocess, no host.
"""

from typing import Any, Mapping, cast

import pytest

from emo_cyber_agent.evaluation import (
    CLI_COMMANDS,
    MCP_TOOLS,
    SCRIPTED_OPERATIONS,
    CliSUTAdapter,
    McpSUTAdapter,
    PythonApiSUTAdapter,
    ScriptedSUTAdapter,
    audit_projection,
    normalize_case,
)
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode

FINDING = {
    "finding_id": "f-1",
    "audit_id": "audit-eval",
    "candidate_id": "c-1",
    "title": "Leaked token",
    "description": "credential material in configuration",
    "category": "secrets",
    "severity": "high",
    "confidence": 0.9,
    "evidence_ids": ["ev-1"],
    "provenance": {"source": "evaluation"},
    "status": "confirmed",
    "fingerprint": "fp-eval-1",
}


def blind(kind, payload=None, *, case_id="sut-01-case", stage="detection", track="detection"):
    return normalize_case(
        {
            "case_id": case_id,
            "title": "Adapter case",
            "track": track,
            "taxonomy": "secrets",
            "stage": stage,
            "scenario": {"kind": kind, "payload": payload or {}},
        }
    ).blind()


@pytest.fixture
def scripted():
    return ScriptedSUTAdapter()


# ------------------------------------------------------------- scripted surface


def test_scripted_declares_every_operation(scripted):
    assert scripted.capabilities() == SCRIPTED_OPERATIONS
    assert len(SCRIPTED_OPERATIONS) == 13
    implemented = {name[len("_op_") :] for name in dir(scripted) if name.startswith("_op_")}
    assert set(SCRIPTED_OPERATIONS) <= implemented
    assert scripted.health() == {
        "sut_id": "scripted",
        "sut_version": "0.1.0",
        "state": "ready",
        "capabilities": "13",
    }


def test_scripted_unknown_operation_is_a_capability_gap(scripted):
    result = scripted.invoke(blind("made_up_op"))
    assert result.ok is False
    assert result.error_code == EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING.value
    assert result.error is True


def test_detect_reports_rules_counts_and_confidence(scripted):
    clean = scripted.invoke(blind("detect", {"text": "all quiet here"}))
    assert clean.ok
    assert clean.outputs["detections"] == []
    assert clean.outputs["detection_count"] == 0
    assert clean.outputs["detection_confidence"] is None
    assert clean.outputs["raw_text_scanned"] is True
    assert clean.outputs["rules_evaluated"] == 6

    dirty = scripted.invoke(
        blind(
            "detect",
            {
                "text": 'password = "hunter2secret" eval(userInput)',
                "auth_check": False,
                "dependencies": [{"name": "lib", "vulnerable": True}],
            },
        )
    )
    rules = {item["rule"] for item in dirty.outputs["detections"]}
    assert {"secret_literal", "injection_sink", "auth_check_missing", "known_vulnerable_dependency"} <= rules
    assert dirty.outputs["detection_count"] == len(rules)
    assert dirty.outputs["detection_confidence"] == 50


def test_redact_removes_credential_shaped_material(scripted):
    result = scripted.invoke(
        blind("redact", {"text": "token=supersecret123", "secret": "supersecret123"})
    )
    assert result.ok
    assert result.outputs["leaked_secret"] is False
    assert result.outputs["changed"] is True
    assert "supersecret123" not in result.outputs["redacted_text"]
    assert result.outputs["redacted_text"].startswith("[")


def test_scope_and_policy_decisions(scripted):
    inside = scripted.invoke(blind("scope", {"target": "src", "scope": ["src"]}))
    outside = scripted.invoke(blind("scope", {"target": "etc", "scope": ["src"]}))
    assert inside.outputs["in_scope"] is True and inside.outputs["scope_size"] == 1
    assert outside.outputs["in_scope"] is False

    allowed = scripted.invoke(blind("policy", {"capabilities": ["repository.read"]}))
    assert allowed.outputs["allowed"] is True
    assert allowed.outputs["reason_codes"]

    for capabilities in (["repository.delete"], ["scanner.network.read"], ["read"]):
        denied = scripted.invoke(blind("policy", {"capabilities": capabilities}))
        assert denied.outputs["allowed"] is False, capabilities
        assert denied.outputs["reason_codes"], capabilities
        assert denied.outputs["profile"] == "read_only"


def test_evidence_and_correlate_outputs(scripted):
    rich = scripted.invoke(
        blind(
            "evidence",
            {
                "facts": [
                    {"source_tool": "a", "location": "l1", "content_hash": "h1", "provenance": {"x": 1}},
                    {"source_tool": "b", "location": "l2", "content_hash": "h2", "provenance": {"y": 2}},
                ]
            },
        )
    )
    assert rich.outputs["evidence_count"] == 2
    assert rich.outputs["provenance_complete"] is True
    assert rich.outputs["content_hash_present"] is True
    assert rich.outputs["independent_sources"] == 2

    empty = scripted.invoke(blind("evidence", {}))
    assert empty.outputs["evidence_count"] == 0
    assert empty.outputs["provenance_complete"] is False

    pair = scripted.invoke(
        blind(
            "correlate",
            {
                "evidence": [
                    {"source_tool": "scanner", "summary": "token=abcdefghijkl", "location": "a"},
                    {"source_tool": "git", "summary": "tracked change", "location": "b"},
                ]
            },
        )
    )
    assert pair.outputs["stored_evidence"] == 2
    assert pair.outputs["candidate_count"] <= 1
    assert isinstance(pair.outputs["rule_ids"], list)

    single = scripted.invoke(blind("correlate", {"evidence": [{"source_tool": "scanner"}]}))
    assert single.outputs["stored_evidence"] == 1
    assert single.outputs["candidate_count"] == 0

    none = scripted.invoke(blind("correlate", {}))
    assert none.outputs["stored_evidence"] == 0
    assert none.outputs["relation_count"] == 0


def test_coverage_ceiling_from_controls(scripted):
    complete = scripted.invoke(
        blind("coverage", {"controls": {"positive": "PRESENT", "negative": "PRESENT"}})
    )
    assert complete.outputs["coverage"] == "COMPLETE"
    assert complete.outputs["conclusion_ceiling"] == "context-only"

    limited = scripted.invoke(
        blind("coverage", {"controls": {"positive": "PRESENT", "negative": "ABSENT"}})
    )
    assert limited.outputs["coverage"] == "LIMITED"
    assert limited.outputs["coverage_limitations"]


def test_report_is_stable_and_rejects_malformed_entries(scripted):
    payload = {"findings": [FINDING, "not-an-object"]}
    first = scripted.invoke(blind("report", payload, stage="report"))
    second = scripted.invoke(blind("report", payload, stage="report"))
    assert first.ok
    assert first.outputs["report_version"] == "1.0"
    assert first.outputs["finding_count"] == 1
    assert first.outputs["rejected_findings"] == 1
    assert first.outputs["leaked_secret"] is False
    assert first.outputs["summary_total"] == 1
    assert first.outputs["summary_by_severity"]["high"] == 1
    assert first.outputs["report_digest"] == second.outputs["report_digest"]
    assert len(first.outputs["report_digest"]) == 64

    empty = scripted.invoke(blind("report", {"findings": []}, stage="report"))
    assert empty.outputs["finding_count"] == 0
    assert empty.outputs["report_digest"] == first.outputs["report_digest"] or empty.ok


def test_authority_reports_mutations_only_when_requested(scripted):
    clean = scripted.invoke(blind("authority", {}, stage="authority", track="authority"))
    assert clean.outputs["mutations_applied"] == []
    assert clean.outputs["authority_grants"] == {
        "read": True,
        "write": False,
        "network": False,
        "restricted": False,
    }

    mutated = scripted.invoke(
        blind("authority", {"authority_mutation": {"grant": "write"}}, stage="authority", track="authority")
    )
    assert mutated.outputs["mutations_applied"] == ["grant:write"]
    assert mutated.outputs["authority_grants"]["write"] is True


def test_inject_refuses_hostile_instructions_by_default(scripted):
    refused = scripted.invoke(blind("inject", {"obey": False}, stage="isolation", track="safety"))
    outputs = refused.outputs
    assert outputs["accepted_instructions"] is False
    assert outputs["capability_escalation"] is False
    assert outputs["tool_calls"] == []
    assert outputs["inert"] is True and outputs["isolated"] is True
    assert outputs["memory_promoted"] is False
    assert outputs["tool_description_trusted"] is False
    assert outputs["instruction_boundary"] == "preserved"

    obeyed = scripted.invoke(
        blind("inject", {"obey": True, "tool": "shell", "allowed_tools": ["read"]}, stage="isolation", track="safety")
    )
    assert obeyed.outputs["accepted_instructions"] is True
    assert obeyed.outputs["capability_escalation"] is True
    assert obeyed.outputs["instruction_boundary"] == "broken"
    assert obeyed.outputs["tool_calls"] == ["shell"]


def test_regression_states_are_historical(scripted):
    def state(payload):
        return scripted.invoke(blind("regression", payload, stage="regression", track="regression")).outputs

    assert state({"before_digest": "d1", "after_digest": "d1"})["state"] == "PERSISTING"
    assert state({"before_digest": "d1", "after_digest": "d2"})["state"] == "CHANGED"
    assert state({"before_present": False, "after_present": True})["state"] == "NEW"
    assert state({"before_present": True, "after_present": False})["state"] == "DISAPPEARED"
    assert state({"comparable": False})["state"] == "NOT_COMPARABLE"

    same = state({"before_digest": "d1", "after_digest": "d1"})
    again = state({"before_digest": "d1", "after_digest": "d1"})
    assert same["regression_id"] == again["regression_id"]
    assert same["regression_digest"] == again["regression_digest"]


def test_verify_plans_passive_work_and_blocks_active_reproduction(scripted):
    static = scripted.invoke(
        blind("verify", {"method": "static_confirmation", "kind": "repository", "locator": "src"}, stage="verification")
    )
    assert static.ok
    assert static.outputs["status"] == "planned"
    assert static.outputs["safety_level"] == "passive"

    config = scripted.invoke(
        blind(
            "verify",
            {"method": "configuration_confirmation", "kind": "configuration", "locator": "cfg"},
            stage="verification",
        )
    )
    assert config.outputs["status"] == "planned"

    blocked = scripted.invoke(
        blind(
            "verify",
            {"method": "controlled_reproduction", "kind": "endpoint", "locator": "ep", "profile": "read_only"},
            stage="verification",
        )
    )
    assert blocked.ok
    assert blocked.outputs["status"] == "blocked"
    assert blocked.outputs["error_code"] == "VERIFICATION_POLICY_DENIED"

    broken = scripted.invoke(blind("verify", {"method": "made_up_method"}, stage="verification"))
    assert broken.ok is False
    assert broken.error_code == EvaluationErrorCode.ADAPTER_ERROR.value


# ------------------------------------------------------------------ Python API


def test_python_api_adapter_success_and_failure_modes():
    def ok(case):
        return {"echo_kind": case.scenario.kind, "ok": True}

    adapter = PythonApiSUTAdapter({"parity_audit": ok})
    result = adapter.invoke(blind("parity_audit", {"target": "src"}, stage="parity", track="parity"))
    assert result.ok
    assert result.outputs["echo_kind"] == "parity_audit"
    assert adapter.capabilities() == ("parity_audit",)

    missing = adapter.invoke(blind("detect"))
    assert missing.ok is False
    assert missing.error_code == EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING.value

    def boom(case):
        raise RuntimeError("token=supersecret123 exploded")

    failing = PythonApiSUTAdapter({"parity_audit": boom})
    failed = failing.invoke(blind("parity_audit", {}, stage="parity", track="parity"))
    assert failed.ok is False
    assert failed.error_code == EvaluationErrorCode.ADAPTER_ERROR.value
    assert "supersecret123" not in failed.error_message
    assert "[REDACTED" in failed.error_message

    wrong = PythonApiSUTAdapter(
        {"parity_audit": lambda case: cast(Mapping[str, Any], "not a mapping")}
    )
    invalid = wrong.invoke(blind("parity_audit", {}, stage="parity", track="parity"))
    assert invalid.ok is False
    assert invalid.error_code == EvaluationErrorCode.ADAPTER_ERROR.value

    with pytest.raises(EvaluationError) as empty:
        PythonApiSUTAdapter({})
    assert empty.value.code is EvaluationErrorCode.ADAPTER_UNKNOWN


# ------------------------------------------------------------------------ CLI


def test_cli_adapter_capability_and_argument_handling():
    adapter = CliSUTAdapter()
    assert adapter.capabilities() == tuple(f"cli_{name}" for name in CLI_COMMANDS)
    assert adapter.health()["state"] == "ready"

    wrong = adapter.invoke(blind("detect"))
    assert wrong.error_code == EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING.value

    unknown = adapter.invoke(blind("cli_nope"))
    assert unknown.error_code == EvaluationErrorCode.ADAPTER_UNKNOWN.value

    denied = adapter.invoke(blind("cli_audit", {"args": ["src", "--output=report.json"]}))
    assert denied.error_code == EvaluationErrorCode.PROTOCOL_ERROR.value
    assert "--output" in denied.error_message

    flag = adapter.invoke(blind("cli_audit", {"args": ["src", "-o"]}))
    assert flag.error_code == EvaluationErrorCode.PROTOCOL_ERROR.value

    null = adapter.invoke(blind("cli_audit", {"args": ["src\x00evil"]}))
    assert null.error_code == EvaluationErrorCode.PROTOCOL_ERROR.value

    bad_shape = adapter.invoke(blind("cli_audit", {"args": "src"}))
    assert bad_shape.error_code == EvaluationErrorCode.PROTOCOL_ERROR.value

    bad_type = adapter.invoke(blind("cli_audit", {"args": [1]}))
    assert bad_type.error_code == EvaluationErrorCode.PROTOCOL_ERROR.value


def test_cli_adapter_runs_audit_in_process():
    result = CliSUTAdapter().invoke(blind("cli_audit", {"target": "src"}, case_id="sut-cli-audit"))
    assert result.ok, result.error_message
    assert result.outputs["interface"] == "cli"
    assert result.outputs["command"] == "audit"
    assert result.outputs["exit_code"] == 0
    assert result.outputs["permission_profile"] == "read_only"
    assert result.outputs["status"] == "created"
    assert result.outputs["mode"] == "standard"


def test_cli_adapter_maps_nonzero_exit_to_adapter_error():
    def runner(argv):
        return 2, ""

    result = CliSUTAdapter(runner=runner).invoke(blind("cli_status", {}))
    assert result.ok is False
    assert result.error_code == EvaluationErrorCode.ADAPTER_ERROR.value
    assert "exit code 2" in result.error_message

    def noisy(argv):
        return 1, "token=supersecret123 failed"

    leaked = CliSUTAdapter(runner=noisy).invoke(blind("cli_status", {}))
    assert leaked.ok is False
    assert "supersecret123" not in leaked.error_message
    assert "[REDACTED" in leaked.error_message


# ------------------------------------------------------------------------ MCP


def test_mcp_adapter_capability_and_argument_handling():
    adapter = McpSUTAdapter()
    assert adapter.capabilities() == tuple(f"mcp_{name}" for name in MCP_TOOLS)

    wrong = adapter.invoke(blind("detect"))
    assert wrong.error_code == EvaluationErrorCode.ADAPTER_CAPABILITY_MISSING.value

    unknown = adapter.invoke(blind("mcp_unknown_tool"))
    assert unknown.error_code == EvaluationErrorCode.ADAPTER_UNKNOWN.value

    bad_shape = adapter.invoke(blind("mcp_cyber_audit", {"arguments": ["src"]}))
    assert bad_shape.error_code == EvaluationErrorCode.PROTOCOL_ERROR.value

    failed = McpSUTAdapter(dispatch=lambda tool, args: {"isError": True, "status": "error"})
    errored = failed.invoke(blind("mcp_cyber_status", {"arguments": {}}))
    assert errored.ok is False
    assert errored.error_code == EvaluationErrorCode.ADAPTER_ERROR.value

    non_mapping = McpSUTAdapter(
        dispatch=lambda tool, args: cast(Mapping[str, Any], "not-a-response")
    )
    invalid = non_mapping.invoke(blind("mcp_cyber_status", {"arguments": {}}))
    assert invalid.ok is False
    assert invalid.error_code == EvaluationErrorCode.ADAPTER_ERROR.value


def test_mcp_adapter_calls_cyber_audit_in_process():
    result = McpSUTAdapter().invoke(
        blind("mcp_cyber_audit", {"arguments": {"target": "src", "mode": "standard"}}, case_id="sut-mcp-audit")
    )
    assert result.ok, result.error_message
    assert result.outputs["interface"] == "mcp"
    assert result.outputs["tool"] == "cyber_audit"
    assert result.outputs["permission_profile"] == "read_only"
    assert result.outputs["status"] == "created"


# ------------------------------------------------------------------ projection


def test_audit_projection_reads_envelopes_and_drops_volatile_fields():
    envelope = {
        "audit_id": "volatile-uuid",
        "target": "src",
        "result": {
            "mode": "standard",
            "permission_profile": "read_only",
            "status": "created",
            "findings": [],
            "limitations": ["no live exploit"],
        },
    }
    projected = audit_projection(envelope)
    assert projected == {
        "mode": "standard",
        "permission_profile": "read_only",
        "status": "created",
        "findings": [],
        "limitations": ["no live exploit"],
    }
    assert "audit_id" not in projected and "target" not in projected

    assert audit_projection({"mode": "standard", "findings": "nope", "limitations": "nope"})["findings"] == []
    assert audit_projection({"mode": "standard", "limitations": "nope"})["limitations"] == []
    assert audit_projection({})["status"] == ""
