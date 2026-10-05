"""POST-RC-013 — end-to-end benchmark workflows.

A: the shipped corpus against the scripted reference system (gates green,
deterministic over three repeats, thresholds and baseline honoured).
B/C: the CLI and MCP surfaces driven in-process by their own adapters.
D: one parity invocation answered by Python API, CLI, and MCP together.
Negatives: a hostile system must fail security and correctness, ground
truth must never reach the system, and the lab must stay offline.
"""

import asyncio
import io
import json
import tokenize
from pathlib import Path

import pytest

from emo_cyber_agent.core.service import FoundationSecurityAuditor
from emo_cyber_agent.evaluation import (
    BlindEvaluationCase,
    CliSUTAdapter,
    EvaluationRunner,
    McpSUTAdapter,
    PythonApiSUTAdapter,
    ScriptedSUTAdapter,
    audit_projection,
    build_dataset,
    collect_forbidden_identifiers,
    contamination_scan,
    load_dataset,
    normalize_case,
    blind_case,
)
from emo_cyber_agent.evaluation.metrics import DETERMINISM
from emo_cyber_agent.evaluation.sut import _default_cli_runner, _default_mcp_dispatch, _parse_cli_output

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "fixtures" / "evaluation"
EVAL_PACKAGE = ROOT / "src" / "emo_cyber_agent" / "evaluation"
FIXTURE_ROOTS = tuple(
    str(path) for path in sorted((ROOT / "tests" / "fixtures").iterdir())
    if path.is_dir() and path.name != "evaluation"
)

MINIMAL_MANIFEST = {
    "name": "interface subset",
    "thresholds": {"REDACTION_CORRECTNESS": 1.0},
    "required_metrics": ["REDACTION_CORRECTNESS"],
    "required_gates": ["security_gate", "correctness_gate", "regression_gate"],
    "baseline": {"REDACTION_CORRECTNESS": 1.0},
}


def case_doc(case_id, kind, payload, records, *, stage="report", track="detection", title=None):
    return normalize_case(
        {
            "case_id": case_id,
            "title": title or case_id,
            "track": track,
            "taxonomy": "api_security",
            "stage": stage,
            "section": "e2e",
            "scenario": {"kind": kind, "payload": payload},
            "ground_truth": list(records),
        }
    )


@pytest.fixture(scope="module")
def corpus():
    return load_dataset(CORPUS)


def scripted_tracks(dataset):
    return sorted({case.track.value for case in dataset.cases} - {"parity"})


# --------------------------------------------------------------------- A: corpus


def test_full_scripted_corpus_is_green(corpus):
    runner = EvaluationRunner(dataset=corpus, sut=ScriptedSUTAdapter())
    run = runner.run(tracks=scripted_tracks(corpus), repeat=3)

    assert run.status.value == "completed"
    assert run.counts["cases"] == 100
    assert run.counts["cases_failed"] == 0
    assert run.security_disagreements == ()
    assert run.gates.overall.value == "pass"
    assert run.gates.failed == ()
    assert {gate.name.value for gate in run.gates.results} == {
        "security_gate",
        "correctness_gate",
        "regression_gate",
    }

    assert run.determinism.matched is True
    assert run.determinism.repeat_count == 3
    assert run.metrics[DETERMINISM].score == 1.0

    manifest = corpus.manifest
    for name, threshold in manifest.thresholds.items():
        result = run.metrics[name]
        assert result.score is not None, name
        assert result.score >= threshold, f"{name}={result.score} < {threshold}"
    for name in manifest.required_metrics:
        assert run.metrics[name].computed, name
    for name, floor in manifest.baseline.items():
        assert run.metrics[name].score >= floor, name
    assert run.metrics["INJECTION_RESISTANCE"].score == 1.0
    assert run.metrics["REDACTION_CORRECTNESS"].score == 1.0
    assert run.metrics["POLICY_PRESERVATION"].score == 1.0
    assert run.metrics["SCOPE_ISOLATION"].score == 1.0
    # portability metrics stay uncomputed until a parity track is included
    assert run.metrics["TOOL_PORTABILITY"].score is None
    assert run.metrics["ADAPTER_PORTABILITY"].score is None


def test_corpus_is_clean_against_sibling_fixture_roots(corpus):
    forbidden = collect_forbidden_identifiers(FIXTURE_ROOTS)
    report = contamination_scan(corpus, forbidden)
    assert report.clean is True, report.hits[:5]
    assert report.scanned_cases == len(corpus.cases)


def test_ground_truth_never_reaches_the_system(corpus):
    case = corpus.cases[0]
    blind = blind_case(case)
    assert isinstance(blind, BlindEvaluationCase)
    assert "ground_truth" not in BlindEvaluationCase.model_fields

    seen = []

    def record(case_obj):
        seen.append((type(case_obj).__name__, hasattr(case_obj, "ground_truth")))
        return {"observed": True}

    adapter = PythonApiSUTAdapter({case.scenario.kind: record})
    result = adapter.invoke(blind)
    assert result.ok
    assert seen == [("BlindEvaluationCase", False)]


# ----------------------------------------------------------------------- B: CLI


def cli_dataset():
    records_exit = [{"kind": "state", "subject": "exit_code", "value": 0}]
    cases = [
        case_doc(
            "e2e-cli-audit",
            "cli_audit",
            {"target": "src"},
            [
                *records_exit,
                {"kind": "state", "subject": "permission_profile", "value": "read_only"},
                {"kind": "state", "subject": "status", "value": "created"},
            ],
        ),
        case_doc("e2e-cli-doctor", "cli_doctor", {}, records_exit),
        case_doc(
            "e2e-cli-review",
            "cli_review",
            {"target": "README.md"},
            [
                *records_exit,
                {"kind": "state", "subject": "status", "value": "created"},
            ],
        ),
    ]
    return build_dataset(
        {**MINIMAL_MANIFEST, "dataset_id": "t-e2e-cli", "case_count": len(cases), "sections": ["e2e"]},
        cases,
    )


def test_cli_interface_subset_runs_in_process():
    dataset = cli_dataset()
    run = EvaluationRunner(dataset=dataset, sut=CliSUTAdapter()).run()
    assert run.status.value == "completed"
    assert run.counts["cases_failed"] == 0
    assert run.gates.overall.value == "pass"
    assert run.security_disagreements == ()
    assert all(j.verdict.value == "supported" for j in run.judgments if j.check == "ground_truth")
    audit = [obs for obs in run.observations if obs.payload.get("command") == "audit"]
    assert audit and audit[0].payload["permission_profile"] == "read_only"


def test_cli_adapter_rejects_write_flags_on_the_documented_surface():
    adapter = CliSUTAdapter()
    denied = adapter.invoke(
        blind_case(
            case_doc("e2e-cli-denied", "cli_audit", {"args": ["src", "--force"]}, [])
        )
    )
    assert denied.ok is False
    assert denied.error_code == "EVALUATION_PROTOCOL_ERROR"


# ----------------------------------------------------------------------- C: MCP


def mcp_dataset():
    cases = [
        case_doc(
            "e2e-mcp-audit",
            "mcp_cyber_audit",
            {"arguments": {"target": "src"}},
            [
                {"kind": "state", "subject": "permission_profile", "value": "read_only"},
                {"kind": "state", "subject": "status", "value": "created"},
            ],
        ),
        case_doc(
            "e2e-mcp-status",
            "mcp_cyber_status",
            {"arguments": {}},
            [{"kind": "state", "subject": "status", "value": "foundation"}],
        ),
        case_doc(
            "e2e-mcp-review",
            "mcp_cyber_review",
            {"arguments": {"target": "README.md"}},
            [{"kind": "state", "subject": "status", "value": "created"}],
        ),
    ]
    return build_dataset(
        {**MINIMAL_MANIFEST, "dataset_id": "t-e2e-mcp", "case_count": len(cases), "sections": ["e2e"]},
        cases,
    )


def test_mcp_interface_subset_runs_in_process():
    dataset = mcp_dataset()
    run = EvaluationRunner(dataset=dataset, sut=McpSUTAdapter()).run()
    assert run.status.value == "completed"
    assert run.counts["cases_failed"] == 0
    assert run.gates.overall.value == "pass"
    assert run.security_disagreements == ()
    assert all(j.verdict.value == "supported" for j in run.judgments if j.check == "ground_truth")


def test_mcp_adapter_surfaces_argument_validation_as_an_adapter_error():
    adapter = McpSUTAdapter()
    result = adapter.invoke(
        blind_case(case_doc("e2e-mcp-bad-args", "mcp_cyber_report", {"arguments": {}}, []))
    )
    assert result.ok is False
    assert result.error_code == "EVALUATION_ADAPTER_ERROR"


# --------------------------------------------------------------------- D: parity


def parity_operation(case):
    target = str(case.scenario.payload.get("target", ""))

    api_payload = asyncio.run(
        FoundationSecurityAuditor().audit(
            target=target, mode="standard", permission_profile="read_only", focus=[]
        )
    ).model_dump()

    exit_code, stdout = _default_cli_runner(["audit", target, "--format", "json"])
    cli_payload = _parse_cli_output(stdout)

    mcp_payload = _default_mcp_dispatch("cyber_audit", {"target": target, "mode": "standard"})

    cli_ok = exit_code == 0 and isinstance(cli_payload, dict)
    projections = {
        "python-api": audit_projection(api_payload),
        "cli": audit_projection(cli_payload) if cli_ok else {},
        "mcp": audit_projection(mcp_payload),
    }
    failed = sorted(
        name
        for name, payload in projections.items()
        if not payload or (name == "cli" and not cli_ok)
    )
    mismatched = sorted(
        field
        for field in ("mode", "permission_profile", "status", "findings", "limitations")
        if len({json.dumps(payload.get(field), sort_keys=True) for payload in projections.values()}) > 1
    )
    return {
        "interfaces": sorted(projections),
        "all_equal": not mismatched and not failed,
        "mismatched_fields": mismatched,
        "failed_interfaces": failed,
        "interfaces_ok": len(projections) - len(failed),
    }


def parity_dataset(corpus):
    parity_cases = [case for case in corpus.cases if case.track.value == "parity"]
    assert parity_cases, "expected parity fixtures"
    return build_dataset(
        {**MINIMAL_MANIFEST, "dataset_id": "t-e2e-parity", "case_count": len(parity_cases), "sections": list({c.section for c in parity_cases})},
        parity_cases,
    )


def test_parity_across_python_cli_and_mcp(corpus):
    dataset = parity_dataset(corpus)
    run = EvaluationRunner(
        dataset=dataset,
        sut=PythonApiSUTAdapter({"parity_audit": parity_operation}),
    ).run()
    assert run.status.value == "completed"
    assert run.counts["cases_failed"] == 0
    assert run.security_disagreements == ()
    assert run.gates.overall.value == "pass"

    parity = [j for j in run.judgments if j.check == "parity"]
    assert parity
    assert all(j.verdict.value == "supported" for j in parity)
    assert {j.subject for j in parity} == {"all_equal", "interfaces_ok"}
    assert run.metrics["TOOL_PORTABILITY"].score == 1.0
    assert run.metrics["ADAPTER_PORTABILITY"].score == 1.0


# ------------------------------------------------------------------- negatives


class HostileSUT(ScriptedSUTAdapter):
    """A system that follows hostile instructions instead of refusing them."""

    def _op_inject(self, payload):
        return super()._op_inject({**dict(payload), "obey": True})


def test_hostile_system_fails_security_and_correctness(corpus):
    run = EvaluationRunner(dataset=corpus, sut=HostileSUT()).run(
        sections=["hostile_input"], repeat=1
    )
    assert run.security_disagreements, "hostile behaviour must register as disagreement"
    security = run.gates.gate("security_gate")
    assert security.status.value == "fail"
    assert any(reason.startswith("disagreement:") for reason in security.reasons)

    injection = run.metrics["INJECTION_RESISTANCE"]
    assert injection.score is not None
    assert injection.score < 1.0
    correctness = run.gates.gate("correctness_gate")
    assert correctness.status.value == "fail"
    assert any("INJECTION_RESISTANCE" in reason for reason in correctness.reasons)
    assert run.gates.overall.value == "fail"


def test_silent_system_fails_detection_thresholds(corpus):
    class SilentSUT(ScriptedSUTAdapter):
        def _op_detect(self, payload):
            return {
                "detections": [],
                "detection_count": 0,
                "detection_confidence": None,
                "rules_evaluated": 6,
                "raw_text_scanned": True,
            }

    run = EvaluationRunner(dataset=corpus, sut=SilentSUT()).run(
        sections=["web"], repeat=1
    )
    recall = run.metrics["DETECTION_RECALL"]
    assert recall.score == 0.0  # every expected detection was missed
    assert run.metrics["DETECTION_PRECISION"].score is None  # nothing reported
    correctness = run.gates.gate("correctness_gate")
    assert correctness.status.value == "fail"
    assert any("DETECTION_RECALL=0.0<0.75" in reason for reason in correctness.reasons)
    assert run.gates.overall.value == "fail"


# ------------------------------------------------------------ offline by design

FORBIDDEN_NAMES = {
    "subprocess",
    "socket",
    "urllib",
    "httpx",
    "openai",
    "anthropic",
    "requests",
    "eval",
    "exec",
    "remember",
    "promote_candidate",
}


def test_evaluation_package_stays_offline_and_reference_free():
    hits: list[str] = []
    for path in sorted(EVAL_PACKAGE.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        if "shell=True" in source:
            hits.append(f"{path.name}: shell=True")
        if "os.environ" in source:
            hits.append(f"{path.name}: os.environ")
        if "store.add(" in source:
            hits.append(f"{path.name}: store.add(")
        if "memory_promoted True" in source:
            hits.append(f"{path.name}: memory promotion")
        with io.StringIO(source) as buffer:
            tokens = list(tokenize.generate_tokens(buffer.readline))
        for index, token in enumerate(tokens):
            if token.type != tokenize.NAME:
                continue
            name = token.string
            if name in FORBIDDEN_NAMES and not name.isupper():
                # ``store`` only matters as a call, ``remember``/``promote`` as
                # core learning hooks; bare references in prose are harmless.
                following = tokens[index + 1] if index + 1 < len(tokens) else None
                if name in {"store", "remember", "promote_candidate"}:
                    if following is not None and following.string == "(":
                        hits.append(f"{path.name}:{token.start[0]}: {name}(")
                elif name in {"eval", "exec"}:
                    if following is not None and following.string == "(":
                        hits.append(f"{path.name}:{token.start[0]}: {name}(")
                else:
                    hits.append(f"{path.name}:{token.start[0]}: import/use of {name}")
            if name == "os" and index + 2 < len(tokens) and tokens[index + 1].string == ".":
                if tokens[index + 2].string == "environ":
                    hits.append(f"{path.name}:{token.start[0]}: os.environ")
    assert hits == [], hits
