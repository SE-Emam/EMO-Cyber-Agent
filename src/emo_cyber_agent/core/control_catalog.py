"""Versioned audit control catalog — evidence-first completion semantics.

``emo-controls-v1`` declares exactly what an audit evaluates. An audit is
``completed`` only when every catalog control evaluated successfully;
anything else stays ``partial`` (fail closed). The catalog is intentionally
narrow: one scanner-backed control today, extended only by adding versioned
controls with documented severity policy — never by guessing.

Control C-001 / secret-exposure (Gitleaks full-tree scan):
  - Severity policy: every scanner observation becomes a finding with
    severity ``high``. Rationale: an exposed secret is credential
    compromise material (CWE-798); the scanner cannot assess exploitability,
    so the finding stays ``suspected`` — never confirmed — and carries its
    evidence link for human/tool verification.
  - Confidence ``0.75`` with basis "single deterministic scanner,
    uncorroborated": one independent source, no verification yet.
  - Semgrep, Trivy, and OSV-Scanner are explicitly out of v1 (see notes);
    their absence is recorded, not hidden.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.domain.models import (
    EvidenceItem,
    Finding,
    FindingSeverity,
    FindingStatus,
)

CONTROL_CATALOG_VERSION = "emo-controls-v1"

CONTROL_SECRET_EXPOSURE = "C-001"

CATALOG_CONTROLS: tuple[str, ...] = (CONTROL_SECRET_EXPOSURE,)

CATALOG_NOTES: tuple[str, ...] = (
    "control-catalog-emo-controls-v1",
    "semgrep-not-run-until-offline-rule-configuration-is-verified",
    "trivy-and-osv-scanner-not-run",
)

SEVERITY_FOR_CONTROL: dict[str, FindingSeverity] = {
    CONTROL_SECRET_EXPOSURE: FindingSeverity.HIGH,
}

CONFIDENCE_SINGLE_SCANNER = 0.75
CONFIDENCE_BASIS_SINGLE_SCANNER = (
    "single deterministic scanner, uncorroborated; "
    "no independent source or verification yet"
)

REMEDIATION_SECRET_EXPOSURE = (
    "Revoke the exposed credential, remove it from the repository history, "
    "rotate any reachable systems, and store secrets in a managed secret "
    "provider instead of the working tree."
)


def build_secret_exposure_finding(
    *,
    observation_rule: str,
    locator: str,
    content_digest: str,
    evidence_item: EvidenceItem,
    audit_id: str,
    index: int,
) -> Finding:
    """Build one suspected high-severity finding from a Gitleaks observation.

    All identity comes from redacted scanner metadata (rule, locator,
    digests) — never from secret values, which parsers already dropped.
    """
    rule = observation_rule.strip() or "unclassified-rule"
    finding_id = f"c001-{content_digest[:12]}-{index}"
    return Finding(
        id=finding_id,
        title=f"Possible exposed secret ({rule} in {locator})",
        severity=SEVERITY_FOR_CONTROL[CONTROL_SECRET_EXPOSURE],
        confidence=CONFIDENCE_SINGLE_SCANNER,
        status=FindingStatus.SUSPECTED,
        asset_id="target",
        taxonomy={"cwe": "CWE-798", "owasp": None, "cvss": None},
        description=(
            f"Scanner rule {rule!r} matched at {locator}. "
            "Treat as credential-compromise material until verified; "
            f"confidence basis: {CONFIDENCE_BASIS_SINGLE_SCANNER}."
        ),
        impact=(
            "If genuine, anyone with repository access holds a working "
            "credential (CWE-798: Use of Hard-coded Credentials)."
        ),
        evidence_ids=[evidence_item.id],
        verification=None,
        remediation=REMEDIATION_SECRET_EXPOSURE,
        references=[],
        limitations=[
            (
                "Single-scanner evidence only; human or tool verification required "
                "before confirmation."
            ),
        ],
    )


def catalog_summary() -> dict[str, Any]:
    """Machine-readable catalog description for result metadata."""
    return {
        "catalog_version": CONTROL_CATALOG_VERSION,
        "controls": [
            {
                "id": CONTROL_SECRET_EXPOSURE,
                "name": "secret-exposure",
                "scanner": "gitleaks",
                "severity_policy": "high",
                "confidence": CONFIDENCE_SINGLE_SCANNER,
            }
        ],
    }
