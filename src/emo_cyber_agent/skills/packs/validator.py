"""Security pack validator — POST-RC-006 (declarative checks only)."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.skills.packs.pack import PackTrust, SecuritySkillPack, contains_verdict, is_write_capability

_UNSAFE_RE = re.compile(r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|grant\s+\w+\s+access|mark\s+\w+\s+confirmed|disable\s+verification|run\s+(a\s+)?command|export\s+secrets|os\.system|subprocess|__import__|eval\(|exec\()", re.IGNORECASE)
_RESULT_BIAS_RE = re.compile(r"(at least one|must be found|must find|guarantee|ensure .*(high|critical).*(found|confirmed))", re.IGNORECASE)
_CODE_RE = re.compile(r"(\bimport\s+os\b|\bsubprocess\b|\bos\.system\b|__import__|eval\(|exec\(|;\s*rm\s+|-rf\s+/)", re.IGNORECASE)


class PackValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    valid: bool = False
    trust: PackTrust = PackTrust.INVALID
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class PackValidator:
    UNSAFE_MARKERS = ("javascript:", "<script", "exec(", "eval(", "__import__", "os.system", "subprocess", "fetch(", "XMLHttpRequest", "import os", "require(")

    def __init__(self, *, skill_registry: Any = None, tool_registry: Any = None, known_capabilities: set[str] | None = None, known_verification: set[str] | None = None):
        self._skills = skill_registry
        self._tools = tool_registry
        self._known_caps = known_capabilities
        self._known_verification = known_verification or {"static_confirmation", "configuration_confirmation", "dataflow_confirmation", "dependency_confirmation", "policy_confirmation", "read_only_query", "controlled_reproduction"}

    def validate(self, pack: SecuritySkillPack) -> PackValidation:
        from emo_cyber_agent.code_intelligence.provider import PROVIDER_CAPABILITIES
        from emo_cyber_agent.code_intelligence.spec import SINK_KINDS, SOURCE_KINDS

        errors: list[str] = []
        warnings: list[str] = []
        if not pack.purpose.strip():
            errors.append("missing-purpose")
        if not pack.skills:
            errors.append("missing-skills")
        if not pack.checks:
            errors.append("missing-checks")
        # codeintel needs must be real capabilities
        for cap in (*pack.required_code_intelligence, *[c for check in pack.checks for c in check.codeintel_needs]):
            if cap not in PROVIDER_CAPABILITIES:
                errors.append(f"codeintel-unknown:{cap}")
        # taxonomy gates
        for check in pack.checks:
            for kind in check.source_kinds:
                if kind not in SOURCE_KINDS:
                    errors.append(f"source-unknown:{kind}")
            for kind in check.sink_kinds:
                if kind not in SINK_KINDS:
                    errors.append(f"sink-unknown:{kind}")
        # capabilities: known-set membership + no write-ish requests
        for cap in pack.required_capabilities:
            if self._known_caps is not None and cap not in self._known_caps:
                errors.append(f"capability-unknown:{cap}")
            if is_write_capability(cap):
                errors.append(f"capability-escalation:{cap}")
        # verification vocabulary + high-risk handoff completeness
        for method in pack.required_verification:
            if method not in self._known_verification:
                errors.append(f"verification-unknown:{method}")
        for check in pack.checks:
            if not check.evidence_required:
                errors.append(f"evidence-gap:{check.check_id}")
            for method in check.verification_required:
                if method not in self._known_verification:
                    errors.append(f"verification-unknown:{check.check_id}:{method}")
            if check.high_risk and not check.verification_required:
                errors.append(f"verification-gap:{check.check_id}")
        # verdict authority: no severity/confirmation language anywhere
        haystacks = [pack.purpose, *pack.methodology, *[m for check in pack.checks for m in check.methodology], *[c.hypothesis_template for c in pack.checks]]
        for hay in haystacks:
            marker = contains_verdict(hay)
            if marker:
                errors.append(f"verdict-authority:{marker}")
                break
        for hay in haystacks:
            if _RESULT_BIAS_RE.search(hay or ""):
                errors.append("result-bias:methodology-predetermines-outcome")
                break
        # injection quarantine (data-only, still usable)
        quarantined = False
        for hay in haystacks:
            lowered = (hay or "").lower()
            if _UNSAFE_RE.search(hay or "") or _CODE_RE.search(hay or "") or any(m in lowered for m in self.UNSAFE_MARKERS):
                quarantined = True
                break
        # references
        for skill in pack.skills:
            if self._skills is None:
                warnings.append(f"skill-unverified:{skill}")
            else:
                try:
                    self._skills.get(skill)
                except Exception:
                    errors.append(f"skill-missing:{skill}")
        for tool in pack.allowed_tools:
            if self._tools is None:
                warnings.append(f"tool-unverified:{tool}")
            else:
                try:
                    self._tools.get(tool)
                except Exception:
                    errors.append(f"tool-missing:{tool}")
        trust = PackTrust.UNTRUSTED
        if quarantined:
            warnings.append("injection-quarantined")
        if not errors and not quarantined and pack.provenance.get("source") == "official":
            trust = PackTrust.TRUSTED
        return PackValidation(valid=not errors, trust=trust if not errors else PackTrust.INVALID, errors=tuple(errors), warnings=tuple(warnings))
