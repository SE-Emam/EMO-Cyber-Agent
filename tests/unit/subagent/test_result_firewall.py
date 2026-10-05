"""Result firewall tests — POST-T018 (Agent 7B)."""

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from emo_cyber_agent.subagent.result_firewall import FirewallVerdict, scrub


def _envelope(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": "completed",
        "task_id": "task-01",
        "session_id": "sess-01",
        "audit_id": "audit-01",
        "project_id": "proj-01",
        "snapshot_id": "snap-01",
        "handoff": {
            "audit_id": "audit-01",
            "project_id": "proj-01",
            "snapshot_id": "snap-01",
            "finding_refs": ["F-001"],
            "evidence_refs": ["E-001"],
            "verification_refs": ["V-001"],
            "report_ref": "R-001",
            "limitations": ["limited network view"],
            "recovery_state": "none",
            "provenance": [{"task_id": "task-01", "session_id": "sess-01"}],
        },
        "completed_at": 123,
    }
    base.update(overrides)
    return base


# --- secrets ---


def test_strips_bearer_token():
    v = scrub(_envelope(note="call with bearer abcdefgh1234XYZ"), audit_id="audit-01")
    assert not v.quarantined
    assert "bearer abcdefgh1234XYZ" not in str(v.clean_result)
    assert any(r.startswith("secret:") for r in v.removed)


def test_strips_api_key_assignment():
    v = scrub(_envelope(detail="api_key = sk-test-12345678"), audit_id="audit-01")
    assert "sk-test-12345678" not in str(v.clean_result)
    assert any(r.startswith("secret:") for r in v.removed)


def test_strips_private_key_block():
    v = scrub(_envelope(detail="-----BEGIN RSA PRIVATE KEY-----"), audit_id="audit-01")
    assert "PRIVATE KEY" not in str(v.clean_result)
    assert any(r.startswith("secret:") for r in v.removed)


def test_strips_aws_style_id():
    v = scrub(_envelope(detail="used AKIAIOSFODNN7EXAMPLE here"), audit_id="audit-01")
    assert "AKIAIOSFODNN7EXAMPLE" not in str(v.clean_result)
    assert any(r.startswith("secret:") for r in v.removed)


def test_strips_high_entropy_token_in_secret_key():
    v = scrub(_envelope(client_secret="aB3dEf7hIj9kLmN0pQrStUvWx"), audit_id="audit-01")
    assert v.clean_result["client_secret"] == "[REDACTED]"
    assert any(r.startswith("secret:") for r in v.removed)


# --- POST-T018 review regression (L2): 12-19 char secret-keyed tokens ---


def test_regression_short_secret_key_token_redacted():
    for token in ("Abc123XyZ456", "Abc123XyZ45678XYZa"):
        assert 12 <= len(token) <= 19
        v = scrub(_envelope(api_key=token), audit_id="audit-01")
        assert v.clean_result["api_key"] == "[REDACTED]", token
        assert any(r.startswith("secret:") for r in v.removed)


def test_regression_short_nonsecret_value_untouched():
    v = scrub(_envelope(note="Abc123XyZ45678XY"), audit_id="audit-01")
    assert v.clean_result["note"] == "Abc123XyZ45678XY"
    assert not any(r.startswith("secret:") for r in v.removed)


def test_regression_server_authz_ref_preserved_for_provenance():
    v = scrub(
        _envelope(authorization_ref="authz-handoff-01"),
        audit_id="audit-01",
        trusted_authz_ref="authz-handoff-01",
    )
    assert v.clean_result["authorization_ref"] == "authz-handoff-01"


def test_regression_authz_shape_alone_never_exempts_attacker_token():
    # Attacker-minted shape-matching string under a secret key must redact
    # even though it looks like an authz- ref (L2 carve-out bypass fix).
    evil = "authz-evil-attacker-minted-token"
    v = scrub(_envelope(api_key=evil), audit_id="audit-01")
    assert v.clean_result["api_key"] == "[REDACTED]"
    assert any(r.startswith("secret:") for r in v.removed)


def test_regression_authz_exemption_requires_exact_bound_ref():
    real = "authz-handoff-01"
    evil = "authz-evil-attacker-minted-token"
    # Bound ref preserved only via exact trusted match ...
    v = scrub(
        _envelope(api_key=real),
        audit_id="audit-01",
        trusted_authz_ref=real,
    )
    assert v.clean_result["api_key"] == real
    # ... a different trusted ref does not protect the attacker value.
    v2 = scrub(
        _envelope(api_key=evil),
        audit_id="audit-01",
        trusted_authz_ref=real,
    )
    assert v2.clean_result["api_key"] == "[REDACTED]"
    assert any(r.startswith("secret:") for r in v2.removed)


def test_regression_no_bound_ref_fails_closed_on_shape_string():
    v = scrub(_envelope(api_key="authz-handoff-01"), audit_id="audit-01")
    assert v.clean_result["api_key"] == "[REDACTED]"
    assert any(r.startswith("secret:") for r in v.removed)


# --- CoT / raw output / provider internals / paths ---


def test_strips_cot_fields():
    payload = _envelope(chain_of_thought="step by step...", reasoning="because", thought="hmm")
    v = scrub(payload, audit_id="audit-01")
    for key in ("chain_of_thought", "reasoning", "thought"):
        assert key not in v.clean_result
    assert any(r.startswith("cot:") for r in v.removed)


def test_strips_raw_tool_output():
    payload = _envelope(raw_output="huge dump", raw_tool_output="dump2", tool_stdout="dump3")
    v = scrub(payload, audit_id="audit-01")
    for key in ("raw_output", "raw_tool_output", "tool_stdout"):
        assert key not in v.clean_result
    assert any(r.startswith("raw-output:") for r in v.removed)


def test_caps_filesystem_paths_to_basename():
    payload = _envelope(file_path="/etc/super/secret/config.yaml")
    v = scrub(payload, audit_id="audit-01")
    assert v.clean_result["file_path"] == "config.yaml"
    assert any(r.startswith("path:") for r in v.removed)


def test_drops_provider_internals():
    payload = _envelope(hidden_state=[1, 2], provider_state={"x": 1}, system_prompt="do stuff", _debug="z")
    v = scrub(payload, audit_id="audit-01")
    for key in ("hidden_state", "provider_state", "system_prompt", "_debug"):
        assert key not in v.clean_result
    assert any(r.startswith("provider-internal:") for r in v.removed)


# --- preservation ---


def test_preservation_set_intact():
    v = scrub(_envelope(), audit_id="audit-01")
    assert not v.quarantined
    assert v.clean_result["status"] == "completed"
    handoff = v.clean_result["handoff"]
    assert handoff["finding_refs"] == ["F-001"]
    assert handoff["evidence_refs"] == ["E-001"]
    assert handoff["verification_refs"] == ["V-001"]
    assert handoff["report_ref"] == "R-001"
    assert handoff["limitations"] == ["limited network view"]
    assert handoff["provenance"] == [{"task_id": "task-01", "session_id": "sess-01"}]


# --- cross-audit quarantine ---


def test_cross_audit_top_level_quarantine():
    v = scrub(_envelope(audit_id="audit-02"), audit_id="audit-01")
    assert v.quarantined is True
    assert v.clean_result == {"audit_id": "audit-01", "status": "quarantined"}
    assert any(r.startswith("cross-audit:") for r in v.removed)


def test_cross_audit_nested_handoff_quarantine():
    payload = _envelope()
    payload["handoff"] = dict(payload["handoff"], audit_id="audit-99")
    v = scrub(payload, audit_id="audit-01")
    assert v.quarantined is True
    assert any("handoff.audit_id" in r for r in v.removed)


def test_session_binding_used_for_quarantine():
    class _S:
        audit_id = "audit-01"

    v = scrub(_envelope(audit_id="audit-07"), session=_S())
    assert v.quarantined is True


# --- determinism / oversize / verdict shape ---


def test_determinism_sorted_removed_and_stable_output():
    payload = _envelope(
        reasoning="r",
        raw_output="x",
        detail="api_key = abcdefgh12345678",
        file_path="/tmp/a/b.txt",
    )
    first = scrub(payload, audit_id="audit-01")
    second = scrub(payload, audit_id="audit-01")
    assert first.to_canonical_json() == second.to_canonical_json()
    assert list(first.removed) == sorted(first.removed)
    assert FirewallVerdict.from_dict(first.to_dict()) == first


def test_oversize_cap_truncates_long_strings():
    payload = _envelope(detail="y" * 9000)
    v = scrub(payload, audit_id="audit-01", max_string_chars=100)
    assert len(v.clean_result["detail"]) <= 100 + len("...[truncated]")
    assert any(r.startswith("oversize:") for r in v.removed)


def test_input_not_mutated_and_bad_types_rejected():
    import pytest

    payload = _envelope(detail="ok")
    snapshot = dict(payload)
    scrub(payload, audit_id="audit-01")
    assert payload == snapshot
    with pytest.raises(TypeError):
        scrub("nope", audit_id="audit-01")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        scrub(payload)  # no binding
    with pytest.raises(ValueError):
        scrub(payload, audit_id="audit-01", max_string_chars=0)
