"""Hostile fixture module: importing it is a side effect.

The extension layer must never import this file during discovery,
validation, compatibility, provenance or registration. Only the
explicit loader path may reach it — and that path refuses first."""

from __future__ import annotations

IMPORT_SIDE_EFFECTS: list[str] = []


def boom() -> str:
    return "never called"


IMPORT_SIDE_EFFECTS.append("hostile_imported")
