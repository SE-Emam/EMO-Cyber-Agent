"""Delegation input sanitizer — POST-T018.

Pure normalize → validate → sanitize pipeline for Host/delegation text.

- No execution, no shell, no network, no policy mutation. Only ``re``,
  ``unicodedata`` and ``pydantic``. This module never spawns processes,
  never evaluates code, and never decides authorization — it only returns
  a :class:`SanitizedInput` record; Core decides.
- Deterministic: NFKC → ANSI-strip → control-strip → bound → detect.
  Same input bytes always yield the same output record.
- Authority language is flagged, never executed or redacted. Oversized
  payloads are truncated with a marker and flagged. Output text is always
  bounded to ``MAX_INPUT_CHARS`` (64 KiB chars).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field

MAX_INPUT_CHARS: int = 64 * 1024  # 65536 chars bound for all outputs

TRUNCATION_MARKER: str = "\n[...truncated]\n"

DecisionHint = Literal["allow", "sanitize", "quarantine", "deny"]

_ANSI_RE = re.compile(
    r"\x1b\[[0-9;:<=>?]*[A-Za-z]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[@-_][0-9A-Za-z]*"
)

# Confusable folding (G11-M2): small explicit Cyrillic/Greek→Latin lookalike
# map applied in normalize() BEFORE detection. LIMITS: this is an explicit
# map, not full UTS#39 — it covers the single-script homoglyphs that evade
# NFKC for the hostile alphabet (notably Cyrillic і U+0456 in `dіsregard`).
# Mixed-script or unlisted confusables may still evade; defense-in-depth is
# the delegation screen sharing this same normalize().
_CONFUSABLE_MAP: dict[str, str] = {
    "\u0430": "a", "\u0410": "A", "\u03b1": "a", "\u0391": "A",  # a
    "\u0432": "v", "\u0412": "V", "\u03b2": "b", "\u0392": "B",  # b/v
    "\u0441": "c", "\u0421": "C",  # c
    "\u0435": "e", "\u0415": "E", "\u03b5": "e", "\u0395": "E",  # e
    "\u04bb": "h", "\u03b7": "h", "\u0397": "H", "\u043d": "h", "\u041d": "H",  # h
    "\u0456": "i", "\u0406": "I", "\u03b9": "i", "\u0399": "I",  # i (PoC: U+0456)
    "\u0458": "j", "\u0408": "J",  # j
    "\u043a": "k", "\u041a": "K", "\u03ba": "k", "\u039a": "K",  # k
    "\u043c": "m", "\u041c": "M", "\u03bc": "m", "\u039c": "M",  # m
    "\u043e": "o", "\u041e": "O", "\u03bf": "o", "\u039f": "O",  # o
    "\u0440": "p", "\u0420": "P", "\u03c1": "p", "\u03a1": "P",  # p
    "\u0455": "s", "\u0405": "S",  # s
    "\u0442": "t", "\u0422": "T", "\u03c4": "t", "\u03a4": "T",  # t
    "\u0438": "u", "\u0418": "U", "\u03c5": "u", "\u03a5": "U",  # u
    "\u03bd": "v", "\u039d": "V",  # v
    "\u0445": "x", "\u0425": "X", "\u03c7": "x", "\u03a7": "X",  # x
    "\u0443": "y", "\u0423": "Y",  # y
    "\u0437": "z", "\u0417": "Z",  # z
}


# Filler words tolerated between a hostile verb and its object (H1).
# Shared with delegation.py — keep the two screens consistent.
# Separators include whitespace, hyphens and underscores so hyphen/underscore
# -joined evasions match after normalization.
_FILLER = r"(?:all|the|these|those|any|my|our|your|of)[\s\-_]+"

# Authority-language classes. Keys are canonical labels; values are patterns
# applied case-insensitively to the normalized text. Indices refer to the
# sanitized output text. Every delegation hostile class plus system-message
# and role-confusion markers are covered. The hide-finding / grant-write
# families tolerate filler words and inflections (H1/M1).
AUTHORITY_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "ignore policy": (
        re.compile(r"ignore\s+(the\s+|all\s+)?polic\w*", re.IGNORECASE),
        re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
        re.compile(r"ignore\s+system\s+policy", re.IGNORECASE),
        # G11-M1: generalized disregard family — `dis`/`regard` split-tolerant
        # (covers `dis-regard`), hyphen/underscore/slash-tolerant gaps, optional
        # the/all/any filler, polic|previous|prior|above|instruction object.
        re.compile(
            r"dis[\s\-_]*regard[\s\-_/]+"
            r"(the[\s\-_/]+|all[\s\-_/]+|any[\s\-_/]+)?"
            r"(polic\w*|previous|prior|above|instructions?\b)",
            re.IGNORECASE,
        ),
        # G11-M1: do-not family — hyphen/concat-tolerant (`do-not-verify`,
        # `DONOTVERIFY`, `do_not_validate`) with verify/validate/check verbs.
        re.compile(
            r"do[\s\-_]*not[\s\-_]*(verif\w*|validat\w*|check\w*)",
            re.IGNORECASE,
        ),
    ),
    "grant write": (
        re.compile(r"\bgrant(?:ed|ing|s)?\b.{0,40}\bwrite\b", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bgrant(?:ed|ing|s)?\b.{0,40}\bpermission\b", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bescalat\w*", re.IGNORECASE),
    ),
    "disable verification": (
        re.compile(r"disabl\w*\s+verif\w*", re.IGNORECASE),
        re.compile(r"\b(skip|bypass)\w*\s+verif\w*", re.IGNORECASE),
        re.compile(r"disable\s+secur\w*", re.IGNORECASE),
    ),
    "hide finding": (
        re.compile(rf"\bhid\w*[\s\-_]+(?:{_FILLER})*findings?\b", re.IGNORECASE),
        re.compile(rf"\b(suppress|drop|omit|delete)\w*[\s\-_]+(?:{_FILLER})*findings?\b", re.IGNORECASE),
        re.compile(r"mark\s+finding\s+confirmed", re.IGNORECASE),
    ),
    "fake approval": (
        re.compile(r"fake\s+approv\w*", re.IGNORECASE),
        re.compile(r"forg\w*\s+approv\w*", re.IGNORECASE),
        re.compile(r"self[\s\-_]*approv\w*", re.IGNORECASE),
        re.compile(r"auto[\s\-_]*approv\w*", re.IGNORECASE),
        re.compile(r"force\s+confirmation", re.IGNORECASE),
    ),
    "system message": (
        re.compile(r"system\s+message", re.IGNORECASE),
        re.compile(r"developer\s+instruction", re.IGNORECASE),
        re.compile(r"security\s+override", re.IGNORECASE),
        re.compile(r"\btrust\s+me\b", re.IGNORECASE),
    ),
    "role confusion": (
        re.compile(r"you\s+are\s+(now\s+)?(system|developer|admin(?:istrator)?|root)\b", re.IGNORECASE),
        re.compile(r"act\s+as\s+(system|admin(?:istrator)?|root|developer)\b", re.IGNORECASE),
        re.compile(r"pretend\s+(to\s+be|you\s+are)\b", re.IGNORECASE),
        re.compile(r"new\s+role\s+is\b", re.IGNORECASE),
    ),
    "use another audit": (
        re.compile(r"use\s+another\s+audit", re.IGNORECASE),
        re.compile(r"cross[\s\-_]*audit", re.IGNORECASE),
        re.compile(r"\bother\s+audit\b", re.IGNORECASE),
        re.compile(r"\bswitch\s+audits?\b", re.IGNORECASE),
    ),
}

AUTHORITY_CLASSES: tuple[str, ...] = tuple(sorted(AUTHORITY_PATTERNS))

# Cross-audit-flavoured attempts hint quarantine (mirrors delegation
# pipeline); all other authority language hints deny.
_QUARANTINE_CLASSES: frozenset[str] = frozenset({"use another audit"})

_ALLOWED_CONTROLS: frozenset[str] = frozenset({"\n", "\t"})


class FlaggedSpan(BaseModel):
    """One authority-language hit. Indices refer to ``SanitizedInput.text``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = Field(min_length=1, max_length=80)
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    excerpt: str = Field(min_length=1, max_length=160)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)


class SanitizedInput(BaseModel):
    """Bounded, flagged record. Records; permits nothing itself."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str = Field(max_length=MAX_INPUT_CHARS)
    flags: tuple[str, ...] = ()
    truncated: bool = False
    decision_hint: DecisionHint = "allow"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        import json

        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def validate_raw(raw: str) -> str:
    """Type-validate raw input. Raises ``TypeError`` on non-str."""
    if not isinstance(raw, str):
        raise TypeError(f"sanitizer input must be str, got {type(raw).__name__}")
    return raw


def normalize(raw: str) -> str:
    """Deterministic technical normalization (idempotent, pure).

    Steps: NFKC → confusable fold (explicit Cyrillic/Greek→Latin map, not
    full UTS#39 — see ``_CONFUSABLE_MAP`` limits) → ANSI-escape removal →
    control-char stripping (keeps ``\\n`` and ``\\t`` only; any other
    control/format char emits a single ``" "`` separator — collapsing runs
    and suppressing it next to whitespace or string edges so ``\\r``/``\\x0b``/
    ``\\x0c`` can no longer fuse tokens, while ``\\r\\n`` still folds to
    ``\\n``). No truncation, no authority redaction.
    """
    text = validate_raw(raw)
    text = unicodedata.normalize("NFKC", text)
    if _CONFUSABLE_MAP:
        text = "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in text)
    text = _ANSI_RE.sub("", text)
    cleaned: list[str] = []
    n = len(text)
    for i, ch in enumerate(text):
        if ch in _ALLOWED_CONTROLS:
            cleaned.append(ch)
            continue
        if unicodedata.category(ch).startswith("C"):
            # Separator only where deletion would fuse two content chars.
            prev = cleaned[-1] if cleaned else ""
            nxt = text[i + 1] if i + 1 < n else ""
            if prev in ("", " ", "\n", "\t"):
                continue
            if nxt in ("", " ", "\n", "\t"):
                continue
            if nxt and unicodedata.category(nxt).startswith("C") and nxt not in _ALLOWED_CONTROLS:
                continue
            cleaned.append(" ")
            continue
        cleaned.append(ch)
    return "".join(cleaned)


def find_authority_spans(text: str) -> tuple[FlaggedSpan, ...]:
    """Return sorted, deduplicated authority-language spans (pure)."""
    validate_raw(text)
    spans: list[FlaggedSpan] = []
    seen: set[tuple[str, int, int]] = set()
    for label in AUTHORITY_CLASSES:
        for pattern in AUTHORITY_PATTERNS[label]:
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                if end <= start:
                    continue
                key = (label, start, end)
                if key in seen:
                    continue
                seen.add(key)
                excerpt = text[start:end][:80]
                if not excerpt:
                    continue
                spans.append(FlaggedSpan(label=label, start=start, end=end, excerpt=excerpt))
    spans.sort(key=lambda s: (s.start, s.end, s.label))
    return tuple(spans)


def _truncate_with_marker(text: str, *, max_chars: int) -> tuple[str, bool, int]:
    """Truncate to ``max_chars`` with a fixed marker. Returns (text, hit, dropped)."""
    if len(text) <= max_chars:
        return text, False, 0
    keep = max_chars - len(TRUNCATION_MARKER)
    if keep < 0:
        keep = 0
    dropped = len(text) - keep
    return text[:keep] + TRUNCATION_MARKER, True, dropped


def sanitize(raw: str, *, max_chars: int = MAX_INPUT_CHARS) -> SanitizedInput:
    """Full pipeline: normalize → bound → detect → hint (pure, deterministic).

    Authority language is flagged with ``authority:<label>:<start>-<end>``
    spans; technical cleanups add ``ansi:stripped``,
    ``control-chars:stripped`` and ``unicode:normalized`` flags; oversize
    adds ``oversize:truncated:<dropped>`` plus the truncation marker.
    ``decision_hint`` is advisory only: ``quarantine`` for cross-audit,
    ``deny`` for other authority language, ``sanitize`` for technical-only
    cleanups, ``allow`` when clean.
    """
    validate_raw(raw)
    if not isinstance(max_chars, int) or max_chars <= len(TRUNCATION_MARKER):
        raise ValueError("max_chars must be an int larger than the truncation marker")

    # Track technical transformations for flags/hint.
    nfkc = unicodedata.normalize("NFKC", raw)
    folded = "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in nfkc)
    unicode_changed = (nfkc != raw) or (folded != nfkc)
    no_ansi = _ANSI_RE.sub("", folded)
    ansi_stripped = no_ansi != folded
    normalized = normalize(raw)
    controls_stripped = normalized != no_ansi

    bounded, was_truncated, dropped = _truncate_with_marker(normalized, max_chars=max_chars)

    spans = find_authority_spans(bounded)

    flags: list[str] = []
    if unicode_changed:
        flags.append("unicode:normalized")
    if ansi_stripped:
        flags.append("ansi:stripped")
    if controls_stripped:
        flags.append("control-chars:stripped")
    for span in spans:
        flags.append(f"authority:{span.label}:{span.start}-{span.end}")
    if was_truncated:
        flags.append(f"oversize:truncated:{dropped}")
    flags = sorted(set(flags))

    labels = {s.label for s in spans}
    if labels & _QUARANTINE_CLASSES:
        hint: DecisionHint = "quarantine"
    elif labels:
        hint = "deny"
    elif was_truncated or ansi_stripped or controls_stripped or unicode_changed:
        hint = "sanitize"
    else:
        hint = "allow"

    return SanitizedInput(text=bounded, flags=tuple(flags), truncated=was_truncated, decision_hint=hint)


__all__ = [
    "AUTHORITY_CLASSES",
    "AUTHORITY_PATTERNS",
    "MAX_INPUT_CHARS",
    "TRUNCATION_MARKER",
    "FlaggedSpan",
    "SanitizedInput",
    "find_authority_spans",
    "normalize",
    "sanitize",
    "validate_raw",
]
