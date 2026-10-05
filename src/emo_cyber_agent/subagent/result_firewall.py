"""Result firewall — POST-T018 (Agent 7B).

Centralized pre-Host stripping for delegation result envelopes
(:class:`ResultEnvelope <emo_cyber_agent.subagent.handoff.ResultEnvelope>`
dicts). Pure, deterministic, no execution: only ``re``, ``os.path`` and
``pydantic``.

Pipeline for :func:`scrub`:

1. Cross-audit gate — every ``audit_id``-valued field must equal the
   session/expected ``audit_id``; any mismatch → ``quarantined=True``
   with a minimal binding-only ``clean_result`` (fail closed).
2. Recursive strip walk (deterministic key order):

   - *secrets*: regex scrub of credential/token material inside strings
     (API keys, bearer tokens, private-key blocks, AWS-style IDs,
     provider token prefixes, ``secret=``/``token:`` assignments, and
     key-context high-entropy tokens). Conservative: whole-value
     redaction only when the key itself is secret-flavoured; otherwise
     only known-format substrings are replaced.
   - *CoT/reasoning*: drop ``chain_of_thought``/``reasoning``/``thought``
     family keys entirely.
   - *raw tool output*: drop ``raw_output``/``raw_tool_output`` family
     keys entirely.
   - *filesystem paths*: cap path-flavoured values (and absolute-path
     looking strings) to their basename.
   - *provider internals*: drop ``_private``/``provider_*``/``hidden*``/
     ``system_prompt`` family keys entirely.
   - *oversize*: truncate any string longer than ``max_string_chars``.
3. Preservation: finding IDs, evidence/verification/report refs,
   provenance, limitations and status keys always pass through (still
   secret-scrubbed and length-capped, never dropped for content).

Returns :class:`FirewallVerdict` ``{clean_result, removed, quarantined}``.
``removed`` is sorted, so identical inputs always yield identical
verdicts. The input dict is never mutated.
"""

from __future__ import annotations

import copy
import json
import os
import re
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

MAX_RESULT_STRING_CHARS: int = 8000
MAX_RESULT_CHARS: int = 64 * 1024
REDACTED: str = "[REDACTED]"
TRUNCATION_SUFFIX: str = "...[truncated]"

# --- strip-key taxonomies (lowercased exact key match) ---

COT_KEYS: frozenset[str] = frozenset(
    {
        "chain_of_thought",
        "chain-of-thought",
        "cot",
        "reasoning",
        "reasoning_trace",
        "reasoning_content",
        "thought",
        "thoughts",
        "thinking",
        "inner_monologue",
        "scratchpad",
        "internal_reasoning",
        "deliberation",
    }
)

RAW_OUTPUT_KEYS: frozenset[str] = frozenset(
    {
        "raw_output",
        "raw_tool_output",
        "raw_response",
        "raw_result",
        "raw",
        "tool_output_raw",
        "tool_raw_output",
        "stdout_raw",
        "stderr_raw",
        "raw_log",
        "raw_logs",
        "tool_stdout",
        "tool_stderr",
        "full_output",
    }
)

PROVIDER_INTERNAL_KEYS: frozenset[str] = frozenset(
    {
        "hidden_state",
        "hidden_states",
        "provider_state",
        "provider_internal",
        "provider_internals",
        "internal_state",
        "system_prompt",
        "model_weights",
        "logits",
        "attentions",
    }
)

PATH_KEYS: frozenset[str] = frozenset(
    {
        "path",
        "file_path",
        "filepath",
        "filename",
        "file_name",
        "directory",
        "dir",
        "location",
        "working_directory",
        "cwd",
        "abspath",
        "realpath",
    }
)

# Keys whose values pass through by policy (still scrubbed + capped).
PRESERVED_KEYS: frozenset[str] = frozenset(
    {
        "finding_id",
        "finding_ids",
        "finding_refs",
        "evidence_refs",
        "evidence_ids",
        "verification_refs",
        "verification_ids",
        "report_ref",
        "provenance",
        "limitations",
        "status",
    }
)

# --- secret patterns (conservative substring scrub) ---

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_AWS_ACCESS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(
    r"(?:github_pat_[A-Za-z0-9_]+|ghp_[A-Za-z0-9]+|gho_[A-Za-z0-9]+"
    r"|sk-live-[A-Za-z0-9]+|xox[bpras]-[A-Za-z0-9\-]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{8,}")
_APIKEY_ASSIGN_RE = re.compile(
    r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"]?[\w\-.~+/=]{8,}"
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|client_secret|access_token"
    r"|refresh_token|auth_token|credentials?|\btoken\b)\b"
    r"\s*[:=]\s*['\"]?[^\s'\",;]{4,}"
)
_AWS_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\baws_secret\b\s*[:=]\s*['\"]?[^\s'\",;]{4,}"
)

_SUBSTRING_PATTERNS: tuple[re.Pattern[str], ...] = (
    _PRIVATE_KEY_RE,
    _AWS_ACCESS_RE,
    _GITHUB_TOKEN_RE,
    _BEARER_RE,
    _APIKEY_ASSIGN_RE,
    _AWS_SECRET_ASSIGN_RE,
    _SECRET_ASSIGN_RE,
)

# Server-issued authorization references are binding/correlation tokens, not
# credentials: the session's bound ref must survive the firewall for
# provenance integrity (handoff_gate provenance carries one). Exemption is by
# EXACT match against ``trusted_authz_ref`` only — shape alone never exempts.
# Same shape as envelope._AUTHZ_RE (kept for shape reference).
_AUTHZ_REF_RE = re.compile(r"^authz-[a-z0-9][a-z0-9\-]{2,78}$")
_SECRET_KEY_HINT = re.compile(
    r"(?i)(secret|passwd|password|pwd|token|api[_-]?key|apikey"
    r"|auth|credential|private[_-]?key|client_secret|access_token)"
)
# Whole-value redaction applies only under secret-flavoured keys (L2: 12+
# chars; non-secret keys keep conservative substring-only behavior to avoid
# false positives on digests/IDs).
_HIGH_ENTROPY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-+/=]{12,}$")

_ABSOLUTE_PATH_RE = re.compile(
    r"(?:/[A-Za-z0-9_.\-~]+(?:/[A-Za-z0-9_.\-~]+)+"
    r"|~/(?:[A-Za-z0-9_.\-~]+/?)+"
    r"|[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*)"
)


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_HINT.search(key or ""))


def _scrub_secret_substrings(text: str) -> tuple[str, bool]:
    """Replace known-format secret substrings with [REDACTED]."""
    redacted = text
    hit = False
    for pattern in _SUBSTRING_PATTERNS:
        new = pattern.sub(REDACTED, redacted)
        if new != redacted:
            hit = True
            redacted = new
    return redacted, hit


def _scrub_string(
    value: str, key_hint: str, *, trusted_authz_ref: str | None = None
) -> tuple[str, bool]:
    """Scrub one string value. Returns (cleaned, secret_hit)."""
    cleaned, hit = _scrub_secret_substrings(value)
    # Key-context high-entropy token: whole-value redaction. Conservative:
    # only when the key itself is secret-flavoured and the value looks
    # like a standalone long token (avoids nuking digests/IDs elsewhere).
    # L2 carve-out fix: the ONLY exempt value is the session's actual bound
    # authorization_ref (exact match via ``trusted_authz_ref``). Any other
    # shape-matching string (attacker-minted ``authz-…``) is redacted, and
    # with no bound ref (None) there is no exemption — fail closed.
    stripped = cleaned.strip()
    if _is_secret_key(key_hint) and _HIGH_ENTROPY_TOKEN_RE.match(stripped):
        if stripped == REDACTED:
            return cleaned, hit
        if trusted_authz_ref and stripped == trusted_authz_ref:
            return cleaned, hit
        return REDACTED, True
    return cleaned, hit


def _cap_path(value: str) -> tuple[str, bool]:
    """Cap a filesystem path to its basename. Returns (capped, changed)."""
    stripped = value.strip().strip("\"'")
    if not stripped:
        return value, False
    base = os.path.basename(stripped.rstrip("/\\")) or stripped
    if base != value:
        return base, True
    return value, False


def _looks_like_path(value: str) -> bool:
    return bool(_ABSOLUTE_PATH_RE.search(value))


class FirewallVerdict(BaseModel):
    """Outcome of pre-Host result scrubbing. Records; permits nothing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    clean_result: dict[str, Any] = Field(default_factory=dict)
    removed: tuple[str, ...] = ()
    quarantined: bool = False

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _expected_audit_id(*, audit_id: str = "", session: Any = None) -> str:
    if session is not None:
        candidate = getattr(session, "audit_id", "")
        if not isinstance(candidate, str) or not candidate:
            raise ValueError("session carries no usable audit_id")
        return candidate
    if not isinstance(audit_id, str) or not audit_id:
        raise ValueError("audit_id (or session) is required")
    return audit_id


def _collect_audit_mismatches(node: Any, expected: str, path: str = "$") -> list[str]:
    """Recursively collect dotted paths of audit_id fields != expected."""
    mismatches: list[str] = []
    if isinstance(node, dict):
        for key in sorted(node.keys()):
            child_path = f"{path}.{key}"
            if key == "audit_id":
                val = node[key]
                if isinstance(val, str) and val != expected:
                    mismatches.append(child_path)
            mismatches.extend(_collect_audit_mismatches(node[key], expected, child_path))
    elif isinstance(node, (list, tuple)):
        for i, item in enumerate(node):
            mismatches.extend(_collect_audit_mismatches(item, f"{path}[{i}]", f"{path}[{i}]"))
    return mismatches


def _strip_node(
    node: Any,
    *,
    key_hint: str = "",
    path: str = "$",
    max_string_chars: int = MAX_RESULT_STRING_CHARS,
    removed: list[str],
    trusted_authz_ref: str | None = None,
) -> Any:
    """Recursive strip walk. Appends machine-readable labels to ``removed``."""
    if isinstance(node, dict):
        cleaned: dict[str, Any] = {}
        for key in sorted(node.keys()):
            child_path = f"{path}.{key}"
            lowered = str(key).lower()
            if lowered in COT_KEYS:
                removed.append(f"cot:{child_path}")
                continue
            if lowered in RAW_OUTPUT_KEYS:
                removed.append(f"raw-output:{child_path}")
                continue
            if lowered in PROVIDER_INTERNAL_KEYS or str(key).startswith("_"):
                removed.append(f"provider-internal:{child_path}")
                continue
            cleaned[key] = _strip_node(
                node[key],
                key_hint=str(key),
                path=child_path,
                max_string_chars=max_string_chars,
                removed=removed,
                trusted_authz_ref=trusted_authz_ref,
            )
        return cleaned
    if isinstance(node, (list, tuple)):
        return [
            _strip_node(
                item,
                key_hint=key_hint,
                path=f"{path}[{i}]",
                max_string_chars=max_string_chars,
                removed=removed,
                trusted_authz_ref=trusted_authz_ref,
            )
            for i, item in enumerate(node)
        ]
    if isinstance(node, str):
        scrubbed, secret_hit = _scrub_string(node, key_hint, trusted_authz_ref=trusted_authz_ref)
        if secret_hit:
            removed.append(f"secret:{path}")
        # Filesystem path cap: path-flavoured keys, or any absolute-path
        # looking string (basename only). Never expands secrets.
        if key_hint.lower() in PATH_KEYS or _looks_like_path(scrubbed):
            capped, changed = _cap_path(scrubbed)
            if changed:
                removed.append(f"path:{path}")
                scrubbed = capped
        if len(scrubbed) > max_string_chars:
            scrubbed = scrubbed[:max_string_chars] + TRUNCATION_SUFFIX
            removed.append(f"oversize:{path}")
        return scrubbed
    return node


def scrub(
    result: dict[str, Any],
    *,
    audit_id: str = "",
    session: Any = None,
    max_string_chars: int = MAX_RESULT_STRING_CHARS,
    trusted_authz_ref: str | None = None,
) -> FirewallVerdict:
    """Scrub a result-envelope dict before Host release (pure, deterministic).

    - ``result`` must be a dict (typically ``ResultEnvelope.to_dict()``).
    - ``audit_id`` or ``session`` (with ``.audit_id``) binds the expected
      audit; any ``audit_id`` field mismatch → quarantined verdict.
    - ``trusted_authz_ref`` is the session's actual bound authorization ref:
      the ONLY ``authz-`` value exempt from whole-value redaction under
      secret-flavoured keys (exact match). When ``None``, a session-carried
      ``authorization_ref`` attr is used if present; otherwise there is NO
      exemption (fail closed).
    - Never mutates ``result``; never executes anything.
    """
    if not isinstance(result, dict):
        raise TypeError(f"result must be dict, got {type(result).__name__}")
    if not isinstance(max_string_chars, int) or max_string_chars <= 0:
        raise ValueError("max_string_chars must be a positive int")
    expected = _expected_audit_id(audit_id=audit_id, session=session)
    if trusted_authz_ref is None and session is not None:
        candidate = getattr(session, "authorization_ref", None)
        if isinstance(candidate, str) and candidate:
            trusted_authz_ref = candidate

    snapshot = copy.deepcopy(result)
    mismatches = sorted(set(_collect_audit_mismatches(snapshot, expected)))
    if mismatches:
        removed = sorted(f"cross-audit:{m}" for m in mismatches)
        return FirewallVerdict(
            clean_result={"audit_id": expected, "status": "quarantined"},
            removed=tuple(removed),
            quarantined=True,
        )

    removed_list: list[str] = []
    clean = _strip_node(
        snapshot,
        path="$",
        max_string_chars=max_string_chars,
        removed=removed_list,
        trusted_authz_ref=trusted_authz_ref,
    )
    if not isinstance(clean, dict):  # defensive: root is always a dict
        clean = {"value": clean}
    return FirewallVerdict(
        clean_result=clean,
        removed=tuple(sorted(set(removed_list))),
        quarantined=False,
    )


__all__ = [
    "COT_KEYS",
    "MAX_RESULT_CHARS",
    "MAX_RESULT_STRING_CHARS",
    "PATH_KEYS",
    "PRESERVED_KEYS",
    "PROVIDER_INTERNAL_KEYS",
    "RAW_OUTPUT_KEYS",
    "FirewallVerdict",
    "scrub",
]
