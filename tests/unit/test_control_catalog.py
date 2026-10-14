"""Control catalog v1: completion semantics and classification policy."""

import asyncio
import json

from test_audit_scanners import AuditScannerPort

from emo_cyber_agent.core.control_catalog import (
    CATALOG_CONTROLS,
    CONTROL_CATALOG_VERSION,
    build_secret_exposure_finding,
    catalog_summary,
)
from emo_cyber_agent.core.service import FoundationSecurityAuditor
from emo_cyber_agent.domain.models import EvidenceItem


def test_catalog_pins_one_versioned_control():
    assert CONTROL_CATALOG_VERSION == "emo-controls-v1"
    assert tuple(CATALOG_CONTROLS) == ("C-001",)
    summary = catalog_summary()
    assert summary["catalog_version"] == CONTROL_CATALOG_VERSION
    assert summary["controls"][0]["severity_policy"] == "high"


def test_builder_policy_is_suspected_high_with_evidence_link():
    evidence_item = EvidenceItem(
        source_tool="gitleaks",
        source_version="8.30.1",
        target_asset_id="target",
        location="src/cfg.py:7",
        content_hash="digest",
        content_summary="[gitleaks:generic-api-key] src/cfg.py:7",
    )
    finding = build_secret_exposure_finding(
        observation_rule="generic-api-key",
        locator="src/cfg.py:7",
        content_digest="digest",
        evidence_item=evidence_item,
        audit_id="audit-1",
        index=0,
    )
    assert finding.severity == "high"
    assert finding.status == "suspected"
    assert finding.confidence == 0.75
    assert finding.evidence_ids == [evidence_item.id]
    assert finding.taxonomy["cwe"] == "CWE-798"
    assert "SUPERSECRET" not in json.dumps(finding.model_dump(mode="json"))


def test_clean_tree_completes_with_zero_findings(tmp_path):
    port = AuditScannerPort(scan_output="[]")
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
    assert result.findings == []
    assert result.tool_failures == []
