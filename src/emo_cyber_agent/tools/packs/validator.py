"""Tool pack validator — POST-RC-007 (declarative checks only)."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from emo_cyber_agent.tools.packs.spec import (
    ALLOWED_PACK_CAPABILITIES,
    PackTrust,
    ToolPack,
    contains_shell_semantics,
    is_escalation_capability,
)

_UNSAFE_RE = re.compile(r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|grant\s+\w+\s+access|mark\s+\w+\s+confirmed|disable\s+verification|run\s+(a\s+)?command|export\s+secrets|os\.system|subprocess|__import__|eval\(|exec\()", re.IGNORECASE)
_CODE_RE = re.compile(r"(\bimport\s+os\b|\bsubprocess\b|\bos\.system\b|__import__|eval\(|exec\(|;\s*rm\s+|-rf\s+/)", re.IGNORECASE)


class ToolPackValidation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    valid: bool = False
    trust: PackTrust = PackTrust.INVALID
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class ToolPackValidator:
    UNSAFE_MARKERS = ("javascript:", "<script", "exec(", "eval(", "__import__", "os.system", "subprocess", "fetch(", "XMLHttpRequest", "import os", "require(")

    def validate(self, pack: ToolPack) -> ToolPackValidation:
        errors: list[str] = []
        warnings: list[str] = []
        if not pack.definitions:
            errors.append("missing-definitions")
        # shell semantics banned from every string surface
        haystacks = [pack.description, pack.entrypoint, pack.source_provenance,
                     *[a for d in pack.definitions for a in d.fixed_args],
                     *[f for d in pack.definitions for f in d.value_flags],
                     *[i.name for d in pack.definitions for i in d.inputs.fields]]
        for hay in haystacks:
            marker = contains_shell_semantics(hay)
            if marker:
                errors.append(f"shell-semantics:{marker}")
                break
        # capabilities: allowlist + escalation
        for definition in pack.definitions:
            for cap in definition.capabilities:
                if cap not in ALLOWED_PACK_CAPABILITIES:
                    if is_escalation_capability(cap):
                        errors.append(f"capability-escalation:{definition.definition_id}:{cap}")
                    else:
                        errors.append(f"capability-unknown:{definition.definition_id}:{cap}")
            # fixed args must be shell-safe tokens
            import re as _re

            for arg in definition.fixed_args:
                if not _re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/=:,]*$", arg) or any(m in arg for m in (";", "&", "|", "$", "`", "(", ")", "<", ">", "\n", " ")):
                    errors.append(f"shell-semantics:{definition.definition_id}:fixed-arg")
                    break
            for flag in definition.value_flags:
                if not flag.startswith("--") or " " in flag or any(m in flag for m in (";", "&", "|", "$", "`")):
                    errors.append(f"shell-semantics:{definition.definition_id}:value-flag")
                    break
            # value flags must reference declared scalar inputs
            declared = {i.name: i.type for i in definition.inputs.fields}
            for flag in definition.value_flags:
                ref = flag[2:].replace("-", "_")
                if ref not in declared or declared[ref] not in ("string", "integer", "boolean", "enum", "path"):
                    errors.append(f"input-rejected:{definition.definition_id}:{flag}")
        # remediation/write surface: packs are read-only facts
        for text in [pack.description, *[d.mode for d in pack.definitions]]:
            lowered = text.lower()
            if any(w in lowered for w in ("remediat", "autofix", "auto-fix", "exploit runner", "fix --apply")):
                errors.append(f"remediation-surface:{text[:60]}")
        if not pack.filesystem_read_only:
            errors.append("filesystem-write-denied")
        if pack.secret_handling != "redact-and-never-persist":
            errors.append("secret-handling-denied")
        # injection quarantine (data-only)
        quarantined = False
        for hay in [pack.description, pack.source_provenance, *pack.limitations]:
            lowered = (hay or "").lower()
            if _UNSAFE_RE.search(hay or "") or _CODE_RE.search(hay or "") or any(m in lowered for m in self.UNSAFE_MARKERS):
                quarantined = True
                break
        trust = PackTrust.UNTRUSTED
        if quarantined:
            warnings.append("injection-quarantined")
        if not errors and not quarantined and pack.provenance.get("source") == "official":
            trust = PackTrust.TRUSTED
        return ToolPackValidation(valid=not errors, trust=trust if not errors else PackTrust.INVALID, errors=tuple(errors), warnings=tuple(warnings))
