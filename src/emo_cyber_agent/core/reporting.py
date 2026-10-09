"""Reporting & Export Contracts — ECA-T012.

Core Finding → Reportability Gate → Report Projection → Serializer → Output.
Projection only: this module NEVER mutates findings, severity, confidence,
status, evidence, policy, repos, or databases; never runs tools or
verification; never reinterprets security (no scores, no rankings, no LLM).

One generated_at per report; one input snapshot per generation; deterministic
ordering everywhere; provenance and verification states preserved verbatim.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.core.findings import SecurityFinding, is_reportable

REPORT_VERSION = "1.0"
REPORT_SCHEMA_VERSION = "1.0"
EMO_VERSION = "0.2.1"

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportErrorCode(StrEnum):
    INVALID = "REPORT_INVALID"
    SCHEMA_ERROR = "REPORT_SCHEMA_ERROR"
    SERIALIZATION_ERROR = "REPORT_SERIALIZATION_ERROR"
    REDACTION_ERROR = "REPORT_REDACTION_ERROR"
    SOURCE_MISSING = "REPORT_SOURCE_MISSING"
    REPORTABILITY_DENIED = "REPORTABILITY_DENIED"
    CONSISTENCY_ERROR = "REPORT_CONSISTENCY_ERROR"


class ReportError(Exception):
    def __init__(self, code: ReportErrorCode, message: str):
        from emo_cyber_agent.core.repository import redact_credentials

        super().__init__(f"{code.value}: {redact_credentials(message)}")
        self.code = code


# ---------------------------------------------------------------------------
# Report models (export contracts, NOT domain replacements)
# ---------------------------------------------------------------------------

class EvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    evidence_id: str = ""
    tool: str = ""
    location: str = ""
    collected_at: str = ""
    digest: str = ""


class VerificationReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    verification_id: str = ""
    method: str = ""
    status: str = ""
    confidence: float = 0.0


class FindingReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: str
    audit_id: str
    asset_id: str | None = None
    title: str
    description: str
    category: str
    severity: str
    confidence: float
    status: str
    cwe: str | None = None
    owasp: str | None = None
    affected_locations: tuple[str, ...] = ()
    candidate_id: str = ""
    verification_ids: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    evidence: tuple[EvidenceReference, ...] = ()
    verifications: tuple[VerificationReference, ...] = ()
    observed_issue: str = ""
    root_cause: str = ""
    impact: str = "UNASSESSED"
    remediation: dict[str, Any] | None = None
    references: tuple[str, ...] = ()
    fingerprint: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)


class SummaryStats(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    total_findings: int = 0
    confirmed: int = 0
    supported: int = 0
    refuted: int = 0
    inconclusive: int = 0
    blocked: int = 0
    suppressed: int = 0
    duplicate: int = 0
    resolved: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)


class ReportMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    report_version: str = REPORT_VERSION
    schema_version: str = REPORT_SCHEMA_VERSION
    emo_version: str = EMO_VERSION
    generated_at: str = ""
    audit_id: str = ""
    project_identity: str = ""
    policy_version: str = ""
    correlation_rule_version: str = ""
    classification_version: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()


class AuditReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    metadata: ReportMetadata
    summary: SummaryStats
    findings: tuple[FindingReport, ...] = ()
    non_reportable: tuple[FindingReport, ...] = ()


# ---------------------------------------------------------------------------
# Projection (read-only; Core decides reportability)
# ---------------------------------------------------------------------------

def _redact(text: str) -> str:
    from emo_cyber_agent.core.repository import redact_credentials
    from emo_cyber_agent.core.supabase import redact_supabase_secrets

    return redact_supabase_secrets(redact_credentials(text))


def project_finding(finding: SecurityFinding, *, verifications: dict[str, dict[str, Any]] | None = None, evidence: dict[str, dict[str, Any]] | None = None) -> FindingReport:
    """Project ONE finding. Values copied verbatim (null stays null)."""
    verifications = verifications or {}
    evidence = evidence or {}
    ev_refs = tuple(
        EvidenceReference(
            evidence_id=eid,
            tool=_redact(str(evidence.get(eid, {}).get("tool", "")))[:120],
            location=_redact(str(evidence.get(eid, {}).get("location", "")))[:300],
            collected_at=str(evidence.get(eid, {}).get("collected_at", ""))[:40],
            digest=str(evidence.get(eid, {}).get("digest", ""))[:64],
        )
        for eid in finding.evidence_ids
    )
    ver_refs = tuple(
        VerificationReference(
            verification_id=vid,
            method=str(verifications.get(vid, {}).get("method", ""))[:80],
            status=str(verifications.get(vid, {}).get("status", ""))[:40],
            confidence=float(verifications.get(vid, {}).get("confidence", 0.0) or 0.0),
        )
        for vid in finding.verification_ids
    )
    return FindingReport(
        finding_id=finding.finding_id,
        audit_id=finding.audit_id,
        asset_id=finding.asset_id,
        title=_redact(finding.title)[:500],
        description=_redact(finding.description)[:2000],
        category=finding.category.value,
        severity=finding.severity.value,
        confidence=finding.confidence,
        status=finding.status.value,
        cwe=finding.cwe,
        owasp=finding.owasp,
        affected_locations=tuple(_redact(loc)[:300] for loc in finding.affected_locations),
        candidate_id=finding.candidate_id,
        verification_ids=finding.verification_ids,
        observation_ids=finding.observation_ids,
        evidence=ev_refs,
        verifications=ver_refs,
        observed_issue=_redact(finding.observed_issue)[:1000],
        root_cause=_redact(finding.root_cause)[:1000],
        impact=_redact(finding.impact)[:500] if finding.impact else "UNASSESSED",
        remediation=finding.remediation.model_dump() if finding.remediation else None,
        references=tuple(_redact(r)[:300] for r in finding.references if not r.lower().startswith(("javascript:", "data:", "vbscript:"))),
        fingerprint=finding.fingerprint,
        provenance={k: (_redact(str(v))[:300] if isinstance(v, str) else v) for k, v in finding.provenance.items()},
    )


def order_findings(findings: list[FindingReport]) -> list[FindingReport]:
    """Deterministic read-order: severity → category → asset → location → id.
    Ordering is for readability only, never a ranking."""
    def _first_loc(f: FindingReport) -> str:
        return f.affected_locations[0] if f.affected_locations else ""

    return sorted(findings, key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.category, f.asset_id or "", _first_loc(f), f.finding_id))


def summarize(findings: list[FindingReport]) -> SummaryStats:
    counts: dict[str, int] = {}
    sev: dict[str, int] = {}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return SummaryStats(
        total_findings=len(findings),
        confirmed=counts.get("confirmed", 0),
        supported=counts.get("supported", 0),
        refuted=counts.get("refuted", 0),
        inconclusive=counts.get("inconclusive", 0),
        blocked=counts.get("blocked", 0),
        suppressed=counts.get("suppressed", 0),
        duplicate=counts.get("duplicate", 0),
        resolved=counts.get("resolved", 0),
        by_severity={k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
    )


def build_report(
    *,
    audit_id: str,
    findings: list[SecurityFinding],
    scope: dict[str, Any] | None = None,
    project_identity: str = "",
    policy_version: str = "",
    limitations: list[str] | None = None,
    include_non_reportable: bool = False,
    verifications: dict[str, dict[str, Any]] | None = None,
    evidence: dict[str, dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> AuditReport:
    """Single-snapshot build: every section derives from THIS input list."""
    if not audit_id:
        raise ReportError(ReportErrorCode.INVALID, "audit_id required")
    for f in findings:
        if f.audit_id != audit_id:
            raise ReportError(ReportErrorCode.REPORTABILITY_DENIED, f"cross-audit reference denied: {f.finding_id}")
    reportable: list[FindingReport] = []
    non_reportable: list[FindingReport] = []
    for f in findings:
        ok, _ = is_reportable(f)
        (reportable if ok else non_reportable).append(project_finding(f, verifications=verifications, evidence=evidence))
    reportable = order_findings(reportable)
    non_reportable = order_findings(non_reportable)
    stamp = generated_at or datetime.now(timezone.utc).isoformat()
    return AuditReport(
        metadata=ReportMetadata(
            generated_at=stamp,
            audit_id=audit_id,
            project_identity=_redact(project_identity)[:200],
            policy_version=_redact(policy_version)[:40],
            correlation_rule_version="corr-v1",
            classification_version="cls-v1",
            scope=scope or {},
            limitations=tuple(limitations or []),
        ),
        summary=summarize(reportable),
        findings=tuple(reportable),
        non_reportable=tuple(non_reportable) if include_non_reportable else (),
    )


# ---------------------------------------------------------------------------
# Serializers (canonical JSON; JSONL stream; escaped Markdown)
# ---------------------------------------------------------------------------

def to_canonical_json(report: AuditReport) -> str:
    try:
        return json.dumps(report.model_dump(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception as e:
        raise ReportError(ReportErrorCode.SERIALIZATION_ERROR, str(e)) from e


def to_jsonl(report: AuditReport) -> str:
    """Formal stream: metadata record, one finding record per line, summary record."""
    try:
        lines = [json.dumps({"record": "metadata", **report.metadata.model_dump()}, sort_keys=True, ensure_ascii=False)]
        for f in report.findings:
            lines.append(json.dumps({"record": "finding", **f.model_dump()}, sort_keys=True, ensure_ascii=False))
        lines.append(json.dumps({"record": "summary", **report.summary.model_dump()}, sort_keys=True, ensure_ascii=False))
        return "\n".join(lines) + "\n"
    except Exception as e:
        raise ReportError(ReportErrorCode.SERIALIZATION_ERROR, str(e)) from e


_MD_SPECIAL = str.maketrans({"`": "＇", "<": "&lt;", ">": "&gt;", "[": "&#91;", "]": "&#93;", "(": "&#40;", ")": "&#41;", "#": "&#35;", "*": "&#42;", "_": "&#95;", "|": "&#124;"})


def md_escape(text: str, limit: int = 2000) -> str:
    """Inline-escape untrusted content so it can never become Markdown/HTML
    structure. Newlines collapse: single-line contexts must stay single-line
    (protects JSONL-adjacent flows and Markdown line structure)."""
    import re as _re

    collapsed = _re.sub(r"[\r\n]+", " ", text)
    return _redact(collapsed)[:limit].translate(_MD_SPECIAL)


def md_fence(text: str, limit: int = 1000) -> str:
    body = _redact(text)[:limit].replace("```", "＇＇＇")
    return f"```text\n{body}\n```"


def to_markdown(report: AuditReport) -> str:
    m = report.metadata
    out: list[str] = [
        "# EMO-Cyber-Agent Security Report",
        "",
        f"Audit: `{md_escape(m.audit_id, 120)}`",
        f"Generated: `{md_escape(m.generated_at, 60)}` (single snapshot)",
        f"Report version: `{md_escape(m.report_version, 20)}` | Schema: `{md_escape(m.schema_version, 20)}`",
        f"Scope: `{md_escape(json.dumps(m.scope, sort_keys=True)[:300], 300)}`",
        "",
        "## Summary",
        "",
        f"Total findings: {report.summary.total_findings}",
        f"Confirmed: {report.summary.confirmed} | Supported: {report.summary.supported} | Refuted: {report.summary.refuted} | Inconclusive: {report.summary.inconclusive} | Blocked: {report.summary.blocked} | Suppressed: {report.summary.suppressed} | Duplicate: {report.summary.duplicate} | Resolved: {report.summary.resolved}",
        f"By severity: critical={report.summary.by_severity.get('critical', 0)} high={report.summary.by_severity.get('high', 0)} medium={report.summary.by_severity.get('medium', 0)} low={report.summary.by_severity.get('low', 0)} info={report.summary.by_severity.get('info', 0)}",
        "",
        "> Counts are inventory, not a verdict on overall safety. `0 confirmed` never means `0 vulnerabilities` — see Limitations.",
        "",
    ]
    if m.limitations:
        out += ["## Limitations", ""]
        out += [f"- {md_escape(lim, 300)}" for lim in m.limitations]
        out += [""]
    out += ["## Findings", ""]
    if not report.findings:
        out += ["_No reportable findings in this snapshot._", ""]
    for f in report.findings:
        out += [
            f"### {md_escape(f.title, 200)}",
            "",
            f"ID: `{md_escape(f.finding_id, 120)}` | Severity: **{md_escape(f.severity, 20)}** | Confidence: `{f.confidence}` | Status: `{md_escape(f.status, 20)}`",
            f"Category: `{md_escape(f.category, 40)}` | CWE: `{md_escape(f.cwe or 'Not assessed', 40)}` | OWASP: `{md_escape(f.owasp or 'Not assessed', 80)}`",
            f"Location: `{md_escape(f.affected_locations[0] if f.affected_locations else 'n/a', 200)}`",
            "",
            md_escape(f.description, 800),
            "",
            f"Root cause: {md_escape(f.root_cause or 'Unknown', 400)}",
            f"Impact: {md_escape(f.impact, 400)}",
            f"Verification: `{md_escape(', '.join(f.verification_ids) or 'none', 200)}`",
            f"Evidence: `{md_escape(', '.join(e.evidence_id for e in f.evidence) or 'none', 300)}`",
        ]
        if f.remediation:
            out += ["", f"Remediation: {md_escape(str(f.remediation.get('recommendation', '')), 400)}"]
        out += [""]
    if report.non_reportable:
        out += ["## Non-reportable items (kept visible, not hidden)", ""]
        for f in report.non_reportable:
            out += [f"- `{md_escape(f.finding_id, 120)}` status=`{md_escape(f.status, 20)}` severity=`{md_escape(f.severity, 20)}`"]
        out += [""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Template-aware renderer — POST-RC-003 (presentation only, semantics frozen)
#
# Consumes a ResolvedReportTemplate snapshot (duck-typed: no import of
# report_templates here, Core stays dependency-free) for section
# visibility/ordering, finding-field projection, evidence/verification
# render mode, redaction profile, and output-format gating.
# NEVER mutates findings, severity, confidence, status, evidence,
# verification, policy, or state; NEVER scores, ranks, or reinterprets.
# ---------------------------------------------------------------------------

_MANDATORY_TEMPLATE_FIELDS: tuple[str, ...] = (
    "finding.finding_id",
    "finding.status",
    "finding.severity",
    "finding.confidence",
    "finding.evidence_ids",
    "finding.verification_ids",
    "finding.provenance",
)

_ALLOWED_TEMPLATE_CONDITION_PATHS: tuple[str, ...] = (
    "finding.cwe",
    "finding.owasp",
    "finding.severity",
    "finding.status",
    "finding.category",
    "verification.status",
)


def _template_spec_of(resolved: Any) -> Any:
    spec = getattr(resolved, "spec", resolved)
    if spec is None:
        raise ReportError(ReportErrorCode.INVALID, "template snapshot carries no spec")
    return spec


def _finding_view(f: FindingReport) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity": f.severity,
        "confidence": f.confidence,
        "status": f.status,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "locations": list(f.affected_locations),
        "evidence_ids": list(f.verification_ids) and [e.evidence_id for e in f.evidence],
        "verification_ids": list(f.verification_ids),
        "remediation": f.remediation,
        "provenance": dict(f.provenance),
        "asset_id": f.asset_id,
        "candidate_id": f.candidate_id,
        "observed_issue": f.observed_issue,
        "root_cause": f.root_cause,
        "impact": f.impact,
        "references": list(f.references),
    }


def _template_rule_applies(rule: Any, view: dict[str, Any], verification_status: str) -> bool:
    path = str(getattr(rule, "show_if_field", ""))
    op = str(getattr(rule, "operator", ""))
    if path not in _ALLOWED_TEMPLATE_CONDITION_PATHS or op not in ("==", "!=", "in", "not-in"):
        return False
    value = getattr(rule, "value", None)
    if path == "verification.status":
        actual: Any = verification_status
    else:
        key = path[len("finding."):]
        actual = view.get(key)
    if op == "==":
        return actual == value
    if op == "!=":
        return actual != value
    choices = value if isinstance(value, list) else [value]
    if op == "in":
        return actual in choices
    return actual not in choices


def _project_finding_field(f: FindingReport, field: str) -> tuple[str, Any]:
    view = _finding_view(f)
    if field.startswith("finding."):
        key = field[len("finding."):]
        return key, view.get(key)
    if field.startswith("report."):
        return field, None
    if field.startswith("meta."):
        return field, None
    return field, None


def apply_report_template(report: AuditReport, resolved: Any) -> dict[str, Any]:
    """Project an AuditReport through a template snapshot into an ordered
    presentation dict. Deterministic; redacted; provenance preserved."""
    spec = _template_spec_of(resolved)
    if not bool(getattr(spec, "preserve_provenance", True)):
        raise ReportError(ReportErrorCode.CONSISTENCY_ERROR, "template provenance-removal denied")
    if not bool(getattr(spec, "redact_secrets", True)):
        raise ReportError(ReportErrorCode.REDACTION_ERROR, "template redaction-disabled denied")
    if not bool(getattr(spec, "deterministic", True)):
        raise ReportError(ReportErrorCode.CONSISTENCY_ERROR, "template nondeterministic denied")
    sections = list(getattr(spec, "sections", ()) or ())
    order = list(getattr(spec, "section_order", ()) or [s.name for s in sections])
    known = {s.name: s for s in sections}
    ordered_names = [n for n in order if n in known] + [n for n in known if n not in order]
    requested = tuple(getattr(spec, "finding_fields", ()) or ())
    projected_fields = tuple(dict.fromkeys((*requested, *_MANDATORY_TEMPLATE_FIELDS)))
    evidence_mode = str(getattr(spec, "evidence_presentation", "references"))
    verification_mode = str(getattr(spec, "verification_presentation", "status"))
    rendered_sections: list[dict[str, Any]] = []
    for name in ordered_names:
        section = known[name]
        rules = list(getattr(section, "visibility", ()) or ())
        visible = True
        if rules and name not in ("summary", "limitations"):
            visible = any(
                _template_rule_applies(r, _finding_view(f), (f.verifications[0].status if f.verifications else ""))
                for f in report.findings
                for r in rules
            )
        if not visible:
            continue
        if name == "summary":
            rendered_sections.append({"name": name, "summary": report.summary.model_dump()})
        elif name in tuple(getattr(spec, "limitations_sections", ("limitations",)) or ("limitations",)):
            rendered_sections.append({"name": name, "limitations": list(report.metadata.limitations)})
        elif name == "findings":
            items: list[dict[str, Any]] = []
            for f in report.findings:
                entry: dict[str, Any] = {}
                for field in projected_fields:
                    key, val = _project_finding_field(f, field)
                    if field == "finding.evidence_ids":
                        entry[key] = [e.evidence_id for e in f.evidence] if evidence_mode in ("references", "inline") else []
                    elif field == "finding.verification_ids":
                        if verification_mode == "detail":
                            entry[key] = [v.model_dump() for v in f.verifications]
                        else:
                            entry[key] = list(f.verification_ids)
                    elif field.startswith("finding."):
                        entry[key] = val
                items.append(entry)
            rendered_sections.append({"name": name, "findings": items})
        else:
            rendered_sections.append({"name": name, "fields": list(getattr(section, "fields", ()) or ())})
    show_nr = bool(getattr(spec, "show_non_reportable", False))
    non_reportable = [{"finding_id": f.finding_id, "status": f.status, "severity": f.severity} for f in report.non_reportable] if (show_nr and report.non_reportable) else []
    return {
        "template_id": str(getattr(spec, "template_id", "")),
        "template_version": str(getattr(spec, "version", "")),
        "template_digest": str(getattr(resolved, "digest", "")),
        "metadata": report.metadata.model_dump(),
        "summary": report.summary.model_dump(),
        "sections": rendered_sections,
        "non_reportable": non_reportable,
        "appendices": list(getattr(spec, "appendices", ()) or ()),
    }


def to_canonical_json_with_template(report: AuditReport, resolved: Any) -> str:
    spec = _template_spec_of(resolved)
    if "json" not in tuple(getattr(spec, "output_formats", ("json",)) or ("json",)):
        raise ReportError(ReportErrorCode.INVALID, "output format not allowed by template: json")
    try:
        return json.dumps(apply_report_template(report, resolved), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except ReportError:
        raise
    except Exception as e:
        raise ReportError(ReportErrorCode.SERIALIZATION_ERROR, str(e)) from e


def to_markdown_with_template(report: AuditReport, resolved: Any) -> str:
    spec = _template_spec_of(resolved)
    if "markdown" not in tuple(getattr(spec, "output_formats", ("markdown",)) or ("markdown",)):
        raise ReportError(ReportErrorCode.INVALID, "output format not allowed by template: markdown")
    presentation = apply_report_template(report, resolved)
    out: list[str] = [
        "# EMO-Cyber-Agent Security Report",
        "",
        f"Template: `{md_escape(str(presentation['template_id']), 120)}@{md_escape(str(presentation['template_version']), 20)}`",
        f"Audit: `{md_escape(report.metadata.audit_id, 120)}`",
        f"Generated: `{md_escape(report.metadata.generated_at, 60)}` (single snapshot)",
        "",
    ]
    for section in presentation["sections"]:
        out += [f"## {md_escape(str(section['name']), 80)}", ""]
        if "summary" in section:
            s = section["summary"]
            out += [f"Total findings: {s.get('total_findings', 0)}", ""]
        elif "limitations" in section:
            for lim in section["limitations"]:
                out += [f"- {md_escape(str(lim), 300)}"]
            out += [""]
        elif "findings" in section:
            if not section["findings"]:
                out += ["_No reportable findings in this snapshot._", ""]
            for entry in section["findings"]:
                title = md_escape(str(entry.get("title", entry.get("finding_id", ""))), 200)
                out += [f"### {title}", ""]
                out += [f"ID: `{md_escape(str(entry.get('finding_id', '')), 120)}` | Severity: **{md_escape(str(entry.get('severity', '')), 20)}** | Status: `{md_escape(str(entry.get('status', '')), 20)}`", ""]
        else:
            out += ["_See canonical JSON for full detail._", ""]
    if presentation["non_reportable"]:
        out += ["## Non-reportable items (kept visible, not hidden)", ""]
        for item in presentation["non_reportable"]:
            out += [f"- `{md_escape(str(item['finding_id']), 120)}` status=`{md_escape(str(item['status']), 20)}`"]
        out += [""]
    out += ["> Counts are inventory, not a verdict on overall safety.", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Python API (ReportService) — the only Core→Reporting path for CLI/MCP/CI
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Serializer contract: generate_json / generate_jsonl / generate_markdown."""

    def generate_json(self, report: AuditReport) -> str:
        return to_canonical_json(report)

    def generate_jsonl(self, report: AuditReport) -> str:
        return to_jsonl(report)

    def generate_markdown(self, report: AuditReport) -> str:
        return to_markdown(report)

    def generate_json_with_template(self, report: AuditReport, resolved: Any) -> str:
        return to_canonical_json_with_template(report, resolved)

    def generate_markdown_with_template(self, report: AuditReport, resolved: Any) -> str:
        return to_markdown_with_template(report, resolved)


class ReportService:
    """Python API. Adapters call this; they never build reports themselves."""

    def __init__(self, generator: ReportGenerator | None = None):
        self._generator = generator or ReportGenerator()

    def generate(
        self,
        *,
        audit_id: str,
        findings: list[SecurityFinding],
        scope: dict[str, Any] | None = None,
        project_identity: str = "",
        policy_version: str = "",
        limitations: list[str] | None = None,
        include_non_reportable: bool = False,
        verifications: dict[str, dict[str, Any]] | None = None,
        evidence: dict[str, dict[str, Any]] | None = None,
    ) -> AuditReport:
        return build_report(
            audit_id=audit_id, findings=findings, scope=scope, project_identity=project_identity,
            policy_version=policy_version, limitations=limitations,
            include_non_reportable=include_non_reportable, verifications=verifications, evidence=evidence,
        )

    def generate_json(self, report: AuditReport) -> str:
        return self._generator.generate_json(report)

    def generate_jsonl(self, report: AuditReport) -> str:
        return self._generator.generate_jsonl(report)

    def generate_markdown(self, report: AuditReport) -> str:
        return self._generator.generate_markdown(report)

    def generate_json_with_template(self, report: AuditReport, resolved: Any) -> str:
        return self._generator.generate_json_with_template(report, resolved)

    def generate_markdown_with_template(self, report: AuditReport, resolved: Any) -> str:
        return self._generator.generate_markdown_with_template(report, resolved)


def generate_report(**kwargs: Any) -> AuditReport:
    """Functional Python API entry point."""
    return ReportService().generate(**kwargs)
