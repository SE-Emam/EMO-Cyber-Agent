"""Fixture implementation for the official verification adapter extension.

Imported only through the loader's explicit, validated loading path —
never during discovery, validation or registration."""

from __future__ import annotations

from emo_cyber_agent.verification.adapters import MockPassiveAdapter

IMPORT_SIDE_EFFECTS: list[str] = []


class OfficialExternalAdapter(MockPassiveAdapter):
    _id = "official-external-adapter"
    _version = "1.0.0"
    _capabilities = ("STATIC_CONFIRMATION",)
    _targets = ("file", "repository")
    _provider_identity = "emo-cyber-agent"


IMPORT_SIDE_EFFECTS.append("official_adapter_imported")


def build_adapter(scenario: str = "SUPPORTED") -> OfficialExternalAdapter:
    return OfficialExternalAdapter(scenario)
