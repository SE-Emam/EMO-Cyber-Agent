"""Deterministic scanner adapters — ECA-T007.

Four adapters ONLY: semgrep, trivy, osv-scanner, gitleaks. Each provides:
- a ToolSpec (Core contract),
- a fixed argv builder (trusted spec + confined target; NEVER repo content),
- a parser producing normalized ScannerObservation facts (DATA, never verdicts),
- version metadata.

Rules pinned here:
- Scanner output = evidence source. Scanner severity/rule names are recorded
  as scanner-attributed strings; they NEVER become EMO findings directly
  (no Finding/severity/CWE construction in this module).
- Gitleaks: metadata only (rule id, path, line, fingerprint, redacted
  snippet, digest). Raw secrets/tokens/values are dropped before return and
  never enter EvidenceItem, invocations, logs, or reports.
- Network: semgrep/trivy/gitleaks declare scanner.local.execute only.
  osv-scanner declares scanner.network.read (vulnerability DB access) and is
  denied by default unless explicitly granted.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.core.repository import mark_untrusted, redact_credentials
from emo_cyber_agent.core.tool_registry import ToolSpec

SECRET_VALUE_KEYS = ("secret", "token", "value", "password", "key", "credentials", "match")


class ScannerOutputError(ValueError):
    """Scanner output was malformed or outside its verified adapter shape."""


def _json_object_with_list(stdout: str, key: str, tool_id: str) -> list[Any]:
    try:
        body = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ScannerOutputError(f"{tool_id} returned invalid JSON") from exc
    if not isinstance(body, dict) or not isinstance(body.get(key), list):
        raise ScannerOutputError(f"{tool_id} output must contain a {key} array")
    return cast(list[Any], body[key])


def _json_list(stdout: str, tool_id: str) -> list[Any]:
    try:
        body = json.loads(stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ScannerOutputError(f"{tool_id} returned invalid JSON") from exc
    if not isinstance(body, list):
        raise ScannerOutputError(f"{tool_id} output must be a JSON array")
    return body


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _redacted_snippet(text: str, limit: int = 200) -> str:
    return redact_credentials(text[:limit])


# ---------------------------------------------------------------------------
# Normalized scanner models (provider structures never reach Domain)
# ---------------------------------------------------------------------------

class ScannerLocation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    path: str = ""
    line_start: int | None = None
    line_end: int | None = None


class ScannerReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: str = ""  # rule | cve | osv | fingerprint
    value: str = ""


class ScannerArtifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    ecosystem: str = ""
    manifest_path: str = ""


class ScannerObservation(BaseModel):
    """One normalized fact. Scanner-attributed strings kept verbatim as data."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_id: str
    tool_version: str = ""
    adapter_version: str = "eca-t007-v1"
    rule_id: str = ""
    message_untrusted: dict[str, Any] = Field(default_factory=dict)
    location: ScannerLocation = Field(default_factory=ScannerLocation)
    scanner_severity: str = ""  # verbatim from scanner; NOT an EMO finding
    artifact: ScannerArtifact = Field(default_factory=ScannerArtifact)
    references: tuple[ScannerReference, ...] = ()
    raw_digest: str = ""
    collected_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ScannerResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tool_id: str
    tool_version: str = ""
    observations: tuple[ScannerObservation, ...] = ()
    result_digest: str = ""
    truncated: bool = False


def observation_to_evidence_fields(obs: ScannerObservation, *, audit_id: str, asset_id: str, invocation_id: str, target: str) -> dict[str, Any]:
    """Convert ONE observation to EvidenceItem-compatible fields (Core-owned).

    Contains digests, locators, and redacted summaries only — never raw
    secrets (parsers already dropped them; this is the second gate).
    """
    preview = ""
    if obs.message_untrusted:
        preview = redact_credentials(str(obs.message_untrusted.get("content_preview", ""))[:300])
    return {
        "audit_id": audit_id,
        "asset_id": asset_id,
        "tool_id": obs.tool_id,
        "tool_version": obs.tool_version,
        "invocation_id": invocation_id,
        "target": target,
        "collected_at": obs.collected_at,
        "provenance": {
            "source": obs.tool_id,
            "rule_id": obs.rule_id,
            "raw_digest": obs.raw_digest,
            "adapter_version": obs.adapter_version,
            "references": [r.model_dump() for r in obs.references],
        },
        "content_digest": _digest(f"{obs.tool_id}|{obs.rule_id}|{obs.raw_digest}"),
        "summary": redact_credentials(f"[{obs.tool_id}:{obs.rule_id or 'observation'}] {obs.location.path}:{obs.location.line_start or '?'} {preview}"[:500]),
        "locator": f"{obs.location.path}:{obs.location.line_start or ''}",
    }


# ---------------------------------------------------------------------------
# Adapter base + four adapters
# ---------------------------------------------------------------------------

class ScannerAdapterBase:
    tool_id: str = ""
    binary: str = ""
    capability: str = "scanner.local.execute"
    category: str = "scanner"

    def spec(self) -> ToolSpec:
        return ToolSpec(
            tool_id=self.tool_id,
            name=self.tool_id,
            version="1.0.0",
            description=f"Deterministic read-only {self.tool_id} scan",
            category="scanner",  # type: ignore[arg-type]
            risk_level="low",  # type: ignore[arg-type]
            capabilities_required=(self.capability,),
            target_types=("repo",),
            supports_read_only=True,
            supports_verification=False,
            supports_remediation=False,
            evidence_behavior="summarize",  # type: ignore[arg-type]
            timeout_ms=120000,
        )

    def argv(self, spec: ToolSpec, confined_target: str) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str) -> dict[str, Any]:
        raise NotImplementedError


class SemgrepAdapter(ScannerAdapterBase):
    tool_id = "semgrep"
    binary = "semgrep"

    def argv(self, spec: ToolSpec, confined_target: str) -> list[str]:
        return [self.binary, "scan", "--json", "--quiet", confined_target]

    def parse(self, stdout: str) -> dict[str, Any]:
        results = _json_object_with_list(stdout, "results", self.tool_id)
        obs: list[ScannerObservation] = []
        for item in results:
            if not isinstance(item, dict):
                raise ScannerOutputError("semgrep result entries must be objects")
            path = str(item.get("path", ""))[:512]
            start_obj = item.get("start") or {}
            end_obj = item.get("end") or {}
            if not isinstance(start_obj, dict) or not isinstance(end_obj, dict):
                raise ScannerOutputError("semgrep result locations must be objects")
            start = start_obj.get("line")
            end = end_obj.get("line")
            rule = str(item.get("check_id", ""))[:200]
            extra = item.get("extra") or {}
            if not isinstance(extra, dict):
                raise ScannerOutputError("semgrep result extra field must be an object")
            msg = redact_credentials(str(extra.get("message", "")))[:500]
            sev = str(extra.get("severity", ""))[:20]
            obs.append(
                ScannerObservation(
                    tool_id=self.tool_id,
                    rule_id=rule,
                    message_untrusted=mark_untrusted(msg),
                    location=ScannerLocation(path=path, line_start=start, line_end=end),
                    scanner_severity=sev,
                    references=(ScannerReference(kind="rule", value=rule),) if rule else (),
                    raw_digest=_digest(json.dumps(item, sort_keys=True, default=str)),
                )
            )
        result = ScannerResult(tool_id=self.tool_id, observations=tuple(obs), result_digest=_digest(stdout or ""))
        return {"observations": result.observations, "result_digest": result.result_digest, "count": len(obs)}


class TrivyAdapter(ScannerAdapterBase):
    tool_id = "trivy"
    binary = "trivy"

    def argv(self, spec: ToolSpec, confined_target: str) -> list[str]:
        return [self.binary, "fs", "--format", "json", "--quiet", confined_target]

    def parse(self, stdout: str) -> dict[str, Any]:
        results = _json_object_with_list(stdout, "Results", self.tool_id)
        obs: list[ScannerObservation] = []
        for res in results:
            if not isinstance(res, dict):
                raise ScannerOutputError("trivy result entries must be objects")
            target = str(res.get("Target", ""))[:300]
            vulns = res.get("Vulnerabilities", []) or []
            if not isinstance(vulns, list):
                raise ScannerOutputError("trivy Vulnerabilities must be an array")
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    raise ScannerOutputError("trivy vulnerability entries must be objects")
                vid = str(vuln.get("VulnerabilityID", ""))[:80]
                pkg = str(vuln.get("PkgName", ""))[:200]
                obs.append(
                    ScannerObservation(
                        tool_id=self.tool_id,
                        rule_id=vid,
                        message_untrusted=mark_untrusted(redact_credentials(str(vuln.get("Title", "")))[:300]),
                        location=ScannerLocation(path=target),
                        scanner_severity=str(vuln.get("Severity", ""))[:20],
                        artifact=ScannerArtifact(package=pkg, installed_version=str(vuln.get("InstalledVersion", ""))[:60], fixed_version=str(vuln.get("FixedVersion", ""))[:60]),
                        references=(ScannerReference(kind="cve", value=vid),) if vid else (),
                        raw_digest=_digest(json.dumps(vuln, sort_keys=True, default=str)),
                    )
                )
        result = ScannerResult(tool_id=self.tool_id, observations=tuple(obs), result_digest=_digest(stdout or ""))
        return {"observations": result.observations, "result_digest": result.result_digest, "count": len(obs)}


class OsvScannerAdapter(ScannerAdapterBase):
    tool_id = "osv-scanner"
    binary = "osv-scanner"
    capability = "scanner.network.read"  # DB access: denied unless explicitly granted

    def argv(self, spec: ToolSpec, confined_target: str) -> list[str]:
        return [self.binary, "--format", "json", confined_target]

    def parse(self, stdout: str) -> dict[str, Any]:
        results = _json_object_with_list(stdout, "results", self.tool_id)
        obs: list[ScannerObservation] = []
        for res in results:
            if not isinstance(res, dict):
                raise ScannerOutputError("osv result entries must be objects")
            packages = res.get("packages", []) or []
            if not isinstance(packages, list):
                raise ScannerOutputError("osv packages must be an array")
            for pkg in packages:
                if not isinstance(pkg, dict):
                    raise ScannerOutputError("osv package entries must be objects")
                info = pkg.get("package", {}) if isinstance(pkg.get("package"), dict) else {}
                vulns = pkg.get("vulnerabilities", []) or []
                if not isinstance(vulns, list):
                    raise ScannerOutputError("osv vulnerabilities must be an array")
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        raise ScannerOutputError("osv vulnerability entries must be objects")
                    vid = str(vuln.get("id", ""))[:80]
                    obs.append(
                        ScannerObservation(
                            tool_id=self.tool_id,
                            rule_id=vid,
                            message_untrusted=mark_untrusted(redact_credentials(str(vuln.get("summary", "")))[:300]),
                            location=ScannerLocation(path=redact_credentials(str(res.get("source", "")))[:300]),
                            artifact=ScannerArtifact(package=str(info.get("name", ""))[:200], installed_version=str(info.get("version", ""))[:60], ecosystem=str(info.get("ecosystem", ""))[:40], manifest_path=redact_credentials(str(res.get("source", "")))[:300]),
                            references=tuple([ScannerReference(kind="osv", value=vid)] + [ScannerReference(kind="alias", value=str(a)[:80]) for a in vuln.get("aliases", [])][:4]) if vid else (),
                            raw_digest=_digest(json.dumps(vuln, sort_keys=True, default=str)),
                        )
                    )
        result = ScannerResult(tool_id=self.tool_id, observations=tuple(obs), result_digest=_digest(stdout or ""))
        return {"observations": result.observations, "result_digest": result.result_digest, "count": len(obs)}


class GitleaksAdapter(ScannerAdapterBase):
    tool_id = "gitleaks"
    binary = "gitleaks"

    def __init__(self, binary_path: str | None = None, *, config_path: str | None = None, ignore_path: str | None = None) -> None:
        if binary_path:
            self.binary = binary_path
        self.config_path = config_path
        self.ignore_path = ignore_path

    def argv(self, spec: ToolSpec, confined_target: str) -> list[str]:
        # Findings are represented by JSON observations while the process exits
        # successfully; every secret is redacted by the scanner before stdout.
        argv = [
            self.binary, "detect", "--source", confined_target, "--no-git",
            "--report-format", "json", "--report-path", "-",
            "--redact=100", "--exit-code", "0", "--ignore-gitleaks-allow",
        ]
        if self.config_path:
            argv.extend(("--config", self.config_path))
        if self.ignore_path:
            argv.extend(("--gitleaks-ignore-path", self.ignore_path))
        return argv

    def parse(self, stdout: str) -> dict[str, Any]:
        items = _json_list(stdout, self.tool_id)
        obs: list[ScannerObservation] = []
        for item in items:
            if not isinstance(item, dict):
                raise ScannerOutputError("gitleaks result entries must be objects")
            # DROP raw secret material: only fingerprint/rule/path/line/digest survive.
            rule = redact_credentials(str(item.get("RuleID", "")))[:120]
            path = redact_credentials(str(item.get("File", "")))[:512]
            try:
                line = int(item.get("StartLine", 0) or 0) or None
            except (TypeError, ValueError):
                line = None
            fingerprint = redact_credentials(str(item.get("Fingerprint", "")))[:120]
            desc = redact_credentials(str(item.get("Description", "")))[:200]
            for key in SECRET_VALUE_KEYS:
                if key in item:
                    continue  # never read secret-bearing keys into observations
            obs.append(
                ScannerObservation(
                    tool_id=self.tool_id,
                    rule_id=rule,
                    message_untrusted=mark_untrusted(f"{rule} {desc} fp={fingerprint}"[:300]),
                    location=ScannerLocation(path=path, line_start=line),
                    references=(ScannerReference(kind="fingerprint", value=fingerprint),) if fingerprint else (),
                    raw_digest=_digest(f"{rule}|{path}|{line}|{fingerprint}"),
                )
            )
        result = ScannerResult(tool_id=self.tool_id, observations=tuple(obs), result_digest=_digest(stdout or ""))
        return {"observations": result.observations, "result_digest": result.result_digest, "count": len(obs)}


SCANNER_ADAPTERS: dict[str, ScannerAdapterBase] = {
    "semgrep": SemgrepAdapter(),
    "trivy": TrivyAdapter(),
    "osv-scanner": OsvScannerAdapter(),
    "gitleaks": GitleaksAdapter(),
}


def get_scanner_tool_specs() -> list[ToolSpec]:
    return [adapter.spec() for adapter in SCANNER_ADAPTERS.values()]
