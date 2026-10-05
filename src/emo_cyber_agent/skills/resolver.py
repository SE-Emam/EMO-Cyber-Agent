"""Skill resolver — POST-RC-001.

Project context → detected technologies → required security domains →
selected skills (with reasons). Deterministic trigger matching; returns
CANDIDATES only. It cannot grant capabilities, override policy, or order
execution — Core Policy decides everything downstream.
"""

from __future__ import annotations

from emo_cyber_agent.skills.registry import SkillRegistry

# signal (lowercased filename or manifest token) → skill ids
TRIGGER_TABLE: dict[str, tuple[str, ...]] = {
    "package.json": ("frontend-security", "api-security", "dependency-security", "supply-chain", "secrets"),
    "package-lock.json": ("dependency-security", "supply-chain"),
    "tsconfig.json": ("frontend-security", "backend-security"),
    "next.config": ("frontend-security", "api-security", "backend-security"),
    ".tsx": ("frontend-security",),
    ".ts": ("frontend-security", "backend-security"),
    ".py": ("backend-security", "injection", "business-logic"),
    "requirements.txt": ("dependency-security", "supply-chain"),
    "pyproject.toml": ("dependency-security", "supply-chain", "configuration"),
    "Dockerfile": ("container-security", "configuration", "secrets"),
    "docker-compose": ("container-security", "configuration"),
    ".tf": ("infrastructure-as-code", "cloud-security", "configuration"),
    "supabase": ("supabase", "database-security", "rls", "auth", "authorization"),
    "schema.sql": ("database-security", "rls"),
    "migration": ("database-security",),
    "auth": ("authentication", "authorization", "api-security"),
    "login": ("authentication", "business-logic"),
    ".env": ("secrets", "configuration"),
    "gitleaks": ("secrets",),
    "jwt": ("authentication", "cryptography", "api-security"),
    "oauth": ("authentication",),
    "mcp": ("mcp-security", "agent-security", "ai-security"),
    "agent": ("agent-security", "ai-security"),
    "prompt": ("ai-security",),
    "payment": ("business-logic", "race-conditions"),
    "workflow": ("business-logic",),
    "s3": ("cloud-security", "data-exposure"),
    "bucket": ("cloud-security", "data-exposure"),
    "cipher": ("cryptography",),
    "threat": ("threat-modeling",),
    "review": ("code-review-security",),
}


class SkillResolver:
    """Deterministic context → skill matching over a registry snapshot."""

    def __init__(self, registry: SkillRegistry):
        self._registry = registry

    def resolve(self, *, files: list[str], objective: str = "") -> list[dict[str, str]]:
        """Return [{skill_id, version, reason}] sorted deterministically."""
        signals = {f.lower() for f in files} | {objective.lower()}
        hits: dict[str, set[str]] = {}
        for signal in signals:
            for trigger, skill_ids in TRIGGER_TABLE.items():
                if trigger in signal:
                    for sid in skill_ids:
                        hits.setdefault(sid, set()).add(trigger)
        resolved = []
        for skill_id in sorted(hits):
            try:
                spec = self._registry.get(skill_id)
            except ValueError:
                continue  # unknown skill: skipped, never invented
            resolved.append({"skill_id": spec.skill_id, "version": spec.version, "reason": f"matched signals: {','.join(sorted(hits[skill_id]))}"})
        return resolved

    def required_capabilities(self, skill_ids: list[str]) -> list[str]:
        """Union of requested (not granted) capabilities for policy review."""
        caps: set[str] = set()
        for sid in skill_ids:
            try:
                caps.update(self._registry.get(sid).required_capabilities)
            except ValueError:
                continue
        return sorted(caps)


def empty_registry() -> SkillRegistry:
    return SkillRegistry()
