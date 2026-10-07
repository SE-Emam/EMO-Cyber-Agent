"""Per-task/per-session tool allowlist enforcement — POST-T018 (Agent 5B).

Pure contract: no execution, no socket, no policy mutation. Decides which
advertised tools a subagent session may reference; enforcement itself stays
in Core.

Contract — ``filter_tools(available, allow, deny)``::

    {"allowed": (...sorted...), "denied_with_reasons": {name: reason, ...sorted...}}

Rules (all fail closed):

* ``deny`` wins over ``allow``.
* Unknown names (not in ``available``) are denied, never granted.
* Empty ``allow`` denies everything (fail closed).
* Wildcards (any name containing ``"*"``) are never expanded — explicit
  names only. Wildcard entries are denied with a ``wildcard-forbidden:``
  reason.
* Deterministic ordering: ``allowed`` is sorted; ``denied_with_reasons``
  is insertion-ordered by sorted name; repeated calls agree.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from emo_cyber_agent.subagent.trust import HostErrorCode, HostIntegrationError

try:  # Tie to discovery subsets when the module is present.
    from emo_cyber_agent.subagent import discovery as _discovery
except Exception:  # pragma: no cover - import-time fallback only
    _discovery = None  # type: ignore[assignment]

# NOTE (fallback): inline minimal mirror of discovery.TASK_TOOL_SUBSETS,
# used only when ``subagent.discovery`` cannot be imported. Keep in sync
# with discovery.py; discovery remains the source of truth when present.
_FALLBACK_TASK_SUBSETS: dict[str, tuple[str, ...]] = {
    "security-review": (
        "cyber_audit",
        "cyber_review",
        "cyber_verify",
        "cyber_report",
        "cyber_status",
    ),
}

_FALLBACK_FULL_TOOLS: tuple[str, ...] = (
    "cyber_audit",
    "cyber_extensions",
    "cyber_report",
    "cyber_review",
    "cyber_status",
    "cyber_threat_intel",
    "cyber_verify",
)

__all__ = ["filter_tools", "tools_for_session"]


def _normalize_list(value: Any, *, field: str) -> tuple[str, ...]:
    """Validate a tool-name list; strip, drop dupes, sort. Wildcards kept
    as-is for the caller to deny (never expanded)."""
    if not isinstance(value, (tuple, list)):
        raise HostIntegrationError(
            HostErrorCode.INVALID,
            f"{field} must be a list of tool names",
        )
    seen: dict[str, None] = {}
    for raw in value:
        if not isinstance(raw, str) or not raw.strip():
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"{field} entries must be non-empty strings",
            )
        name = raw.strip()
        if len(name) > 80:
            raise HostIntegrationError(
                HostErrorCode.INVALID,
                f"{field} entry too long: {name[:32]}",
            )
        seen.setdefault(name, None)
    return tuple(sorted(seen))


def _split_wildcards(names: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Partition names into (explicit, wildcard). Any name containing '*'
    is a wildcard and never allowed."""
    explicit = tuple(n for n in names if "*" not in n)
    wild = tuple(n for n in names if "*" in n)
    return explicit, wild


def filter_tools(
    available: tuple[str, ...] | list[str],
    allow: tuple[str, ...] | list[str],
    deny: tuple[str, ...] | list[str] | None = None,
) -> dict[str, Any]:
    """Per-task/per-session allowlist filter (pure, deterministic).

    Args:
        available: advertised tool names (ground truth).
        allow: explicit per-task/per-session allow-list.
        deny: explicit deny-list; wins over ``allow``.

    Returns:
        ``{"allowed": tuple[str, ...], "denied_with_reasons": dict}``
        with sorted, deterministic ordering.
    """
    available_n = _normalize_list(available, field="available")
    allow_n = _normalize_list(allow, field="allow")
    deny_n = _normalize_list(deny if deny is not None else [], field="deny")

    available_explicit, available_wild = _split_wildcards(available_n)
    allow_explicit, allow_wild = _split_wildcards(allow_n)
    deny_explicit, deny_wild = _split_wildcards(deny_n)

    known: set[str] = set(available_explicit)
    allow_set: set[str] = set(allow_explicit)
    deny_set: set[str] = set(deny_explicit)

    denied: dict[str, str] = {}
    allowed: list[str] = []

    # Wildcard entries are never allowed — denied with explicit reason.
    # (Available-side wildcards are denied too: nothing expands them.)
    for name in sorted(set(allow_wild) | set(deny_wild) | set(available_wild)):
        denied[name] = f"wildcard-forbidden:{name}"

    if not allow_set:
        # Empty allow denies everything (fail closed). An explicit deny
        # entry still reports as denied (deny wins); everything else
        # reports the fail-closed reason.
        for name in sorted(known):
            if name in deny_set:
                denied[name] = f"denied:{name}"
            else:
                denied[name] = "empty-allow:fail-closed"
    else:
        for name in sorted(known):
            if name in deny_set:
                denied[name] = f"denied:{name}"  # deny wins over allow
            elif name not in allow_set:
                denied[name] = f"not-allowed:{name}"
            else:
                allowed.append(name)

    # Unknown names (in allow/deny but not in available) are denied, never
    # granted. Deny-wins applies to known names only; unknown stays unknown.
    for name in sorted((allow_set | deny_set) - known):
        denied[name] = f"unknown-tool:{name}"

    allowed_t = tuple(sorted(allowed))
    denied_ordered = {name: denied[name] for name in sorted(denied)}
    return {"allowed": allowed_t, "denied_with_reasons": denied_ordered}


def _task_subset(task_kind: str) -> tuple[str, ...]:
    """Per-task tool subset, discovery-backed with inline fallback."""
    if not isinstance(task_kind, str) or not task_kind.strip():
        raise HostIntegrationError(
            HostErrorCode.INVALID,
            "task_kind must be a non-empty string",
        )
    key = task_kind.strip()
    if _discovery is not None:
        try:
            tools = _discovery.tools_for_task(key)
        except HostIntegrationError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise HostIntegrationError(
                HostErrorCode.COMPAT_UNKNOWN, f"unknown task kind: {key}"
            ) from exc
        return tuple(t.name for t in tools)
    if key not in _FALLBACK_TASK_SUBSETS:
        raise HostIntegrationError(
            HostErrorCode.COMPAT_UNKNOWN,
            f"unknown task kind: {key}",
        )
    return _FALLBACK_TASK_SUBSETS[key]


def _full_tool_list() -> tuple[str, ...]:
    if _discovery is not None:
        try:
            return tuple(_discovery.list_tools())
        except Exception:  # pragma: no cover - defensive
            pass
    return _FALLBACK_FULL_TOOLS


def _scope_lists(session_scope: Any) -> tuple[tuple[str, ...] | None, tuple[str, ...]]:
    """Extract (allow|None, deny) from a session scope.

    Accepts ``None`` (no session narrowing), a ``Mapping`` with optional
    ``"allow"``/``"deny"`` keys, or an object with ``allow``/``deny``
    attributes. ``allow=None``/missing means 'no session restriction
    beyond the task subset'.
    """
    if session_scope is None:
        return None, ()
    if isinstance(session_scope, Mapping):
        allow_raw = session_scope.get("allow", None)
        deny_raw = session_scope.get("deny", ())
        allow = (
            None
            if allow_raw is None
            else _normalize_list(list(allow_raw), field="session allow")
        )
        deny = _normalize_list(list(deny_raw), field="session deny")
        return allow, deny
    if hasattr(session_scope, "allow") or hasattr(session_scope, "deny"):
        allow_raw = getattr(session_scope, "allow", None)
        deny_raw = getattr(session_scope, "deny", ())
        allow = (
            None
            if allow_raw is None
            else _normalize_list(list(allow_raw), field="session allow")
        )
        deny = _normalize_list(list(deny_raw), field="session deny")
        return allow, deny
    raise HostIntegrationError(
        HostErrorCode.INVALID,
        "session_scope must be None, a mapping with allow/deny, or an object with allow/deny",
    )


def tools_for_session(session_scope: Any, task_kind: str) -> dict[str, Any]:
    """Tool allowlist for one session + task kind (pure, narrowing-only).

    Starts from the discovery per-task subset (inline fallback table when
    discovery is unavailable), then narrows with the session ``allow`` /
    ``deny``. A session can only narrow the task subset — it can never
    widen it to tools outside the task boundary. Unknown task kinds raise.
    """
    subset = _task_subset(task_kind)
    full = _full_tool_list()
    session_allow, session_deny = _scope_lists(session_scope)

    subset_set = set(subset)
    full_set = set(_split_wildcards(full)[0])

    if session_allow is None:
        effective_allow = tuple(sorted(subset_set))
    else:
        # Narrowing-only: session allow intersects the task subset, but
        # truly unknown names are preserved so filter_tools reports them
        # as unknown instead of silently dropping them. Known tools
        # outside the task boundary stay out of allow -> "not-allowed".
        requested = set(a for a in session_allow if "*" not in a)
        wildcards = tuple(sorted({a for a in session_allow if "*" in a}))
        in_scope = requested & subset_set
        unknown = requested - full_set
        effective_allow = tuple(sorted(in_scope | unknown)) + wildcards

    return filter_tools(full, list(effective_allow), list(session_deny))
