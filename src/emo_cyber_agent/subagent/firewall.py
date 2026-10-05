"""Host context firewall — POST-T018.

Admits Host context chunks as DATA ONLY, and only when scope-bound to the
active :class:`SubagentSession` (``audit_id`` + ``project_id`` +
``snapshot_id`` match; source present and kebab-case).

Per-chunk pipeline: scope gate → size gate → normalize + policy gate.

- Scope gate: audit mismatch → ``QUARANTINE`` (cross-audit chunk, fail
  closed); project/snapshot mismatch or unclassified source → ``DENY``
  (unbound reject). Inbound ``classification`` claims are ignored: every
  admitted chunk is labeled ``UNTRUSTED`` regardless of what the Host
  asserted.
- Size gate: chunk text longer than ``max_chunk_chars`` → ``DENY``
  (bounded rejection, never buffered or truncated into admission).
- Policy gate: reuses :mod:`sanitizer` (normalize → detect). Cross-audit
  authority language → ``QUARANTINE``; other authority language
  (instruction smuggling) → ``DENY``; instruction-like content aimed at
  execution sinks → ``DENY``; data-only content → ``ALLOW`` with the
  ``UNTRUSTED`` label.
- Stream gate (:func:`admit_stream`): bounds total admitted chars and
  chunk count; overflow → terminal ``DENY`` (bounded rejection).

Chunks are DATA, never instructions. No execution, no shell, no network,
no policy mutation — only ``re``, ``sanitizer`` and ``pydantic``.
Verdicts record outcomes; they permit nothing themselves (Core decides).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from emo_cyber_agent.subagent.sanitizer import MAX_INPUT_CHARS, sanitize
from emo_cyber_agent.subagent.session import SubagentSession
from emo_cyber_agent.subagent.trust import ContextClassification, SecurityDecision, scan_secret_markers

MAX_CHUNK_CHARS: int = MAX_INPUT_CHARS  # 64 KiB chars per chunk
MAX_STREAM_CHARS: int = 256 * 1024  # 256 KiB admitted chars per stream
MAX_STREAM_CHUNKS: int = 1024  # chunk-count bound per stream

_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")

# Instruction-like content aimed at execution sinks. Direct code-execution
# tokens deny outright; directive patterns require an imperative verb near
# a sink noun so data-only mentions (e.g. "listening on TCP 443") admit.
EXECUTION_SINK_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "os-system": (re.compile(r"os\s*\.\s*system\s*\(", re.IGNORECASE),),
    "subprocess-spawn": (
        re.compile(
            r"subprocess\s*\.\s*(run|call|Popen|check_output|check_call)\s*\(",
            re.IGNORECASE,
        ),
    ),
    "eval-exec": (
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
    ),
    "shell-true": (re.compile(r"shell\s*=\s*True", re.IGNORECASE),),
    "pipe-to-shell": (
        re.compile(r"\|\s*(sh|bash|zsh|powershell|cmd)\b", re.IGNORECASE),
        re.compile(r"\b(curl|wget)\b.{0,80}\|\s*(sh|bash)\b", re.IGNORECASE | re.DOTALL),
    ),
    "execution-directive": (
        re.compile(
            r"\b(run|execute|launch|spawn|invoke)\b.{0,40}\b(shell|command|script|payload|binary|code)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(r"\bopen\b.{0,20}\b(reverse\s+)?shell\b", re.IGNORECASE | re.DOTALL),
        re.compile(
            r"\b(download|fetch)\b.{0,40}\b(and\s+)?(run|execute|pipe)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
}

EXECUTION_SINK_LABELS: tuple[str, ...] = tuple(sorted(EXECUTION_SINK_PATTERNS))


class HostContextChunk(BaseModel):
    """One inbound Host context chunk. DATA ONLY — never an instruction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audit_id: str = Field(min_length=1, max_length=200)
    project_id: str = Field(min_length=1, max_length=200)
    snapshot_id: str = Field(min_length=1, max_length=200)
    source: str = Field(default="", max_length=80)
    text: str = ""
    classification: ContextClassification = ContextClassification.UNTRUSTED

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class FirewallVerdict(BaseModel):
    """Outcome for one chunk (or a stream bound). Records; permits nothing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: SecurityDecision
    reasons: tuple[str, ...] = ()
    text: str = ""  # normalized data admitted; empty unless ALLOW
    classification: ContextClassification = ContextClassification.UNTRUSTED
    sanitized: bool = False

    def requires_quarantine(self) -> bool:
        return self.decision in (SecurityDecision.QUARANTINE, SecurityDecision.DENY)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def find_execution_sinks(text: str) -> tuple[str, ...]:
    """Return sorted execution-sink labels hit in ``text`` (pure)."""
    if not isinstance(text, str):
        raise TypeError(f"firewall input must be str, got {type(text).__name__}")
    return tuple(sorted(label for label, patterns in EXECUTION_SINK_PATTERNS.items() if any(p.search(text) for p in patterns)))


def _authority_labels(flags: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({f.split(":", 2)[1] for f in flags if f.startswith("authority:") and len(f.split(":", 2)) == 3}))


def admit_chunk(
    session: SubagentSession,
    chunk: HostContextChunk,
    *,
    max_chunk_chars: int = MAX_CHUNK_CHARS,
) -> FirewallVerdict:
    """Gate one chunk: scope → size → normalize + policy (pure, no execution)."""
    if not isinstance(session, SubagentSession):
        raise TypeError(f"session must be SubagentSession, got {type(session).__name__}")
    if not isinstance(chunk, HostContextChunk):
        raise TypeError(f"chunk must be HostContextChunk, got {type(chunk).__name__}")
    if not isinstance(max_chunk_chars, int) or max_chunk_chars <= 0:
        raise ValueError("max_chunk_chars must be a positive int")

    # Scope gate: audit mismatch quarantines (cross-audit), anything else
    # unbound denies. Reasons carry labels only, never chunk content.
    if chunk.audit_id != session.audit_id:
        return FirewallVerdict(
            decision=SecurityDecision.QUARANTINE,
            reasons=("cross-audit chunk: audit binding mismatch",),
        )
    if chunk.project_id != session.project_id or chunk.snapshot_id != session.snapshot_id:
        return FirewallVerdict(
            decision=SecurityDecision.DENY,
            reasons=("unbound chunk: project/snapshot binding mismatch",),
        )
    if not _SOURCE_RE.match(chunk.source):
        return FirewallVerdict(
            decision=SecurityDecision.DENY,
            reasons=("unbound chunk: unclassified source",),
        )

    # Size gate: bounded rejection, never buffered into admission.
    if len(chunk.text) > max_chunk_chars:
        return FirewallVerdict(
            decision=SecurityDecision.DENY,
            reasons=(f"oversize chunk: bounded rejection ({len(chunk.text)} > {max_chunk_chars})",),
        )

    # Normalize + policy gate via the shared sanitizer pipeline.
    cleaned = sanitize(chunk.text, max_chars=max_chunk_chars)
    if cleaned.truncated:  # defense in depth (e.g. NFKC expansion past the raw check)
        return FirewallVerdict(
            decision=SecurityDecision.DENY,
            reasons=("oversize chunk: bounded rejection after normalization",),
        )
    # Secret-marker quarantine (L3): credential material is never admitted as
    # data, consistent with the delegation screen's secret-marker quarantine.
    # Checked before authority verdicts to mirror delegation ordering.
    if scan_secret_markers(cleaned.text):
        return FirewallVerdict(
            decision=SecurityDecision.QUARANTINE,
            reasons=("secret markers observed in chunk: quarantined",),
        )
    if cleaned.decision_hint == "quarantine":
        return FirewallVerdict(
            decision=SecurityDecision.QUARANTINE,
            reasons=(f"cross-audit content quarantined: {','.join(_authority_labels(cleaned.flags))}",),
        )
    if cleaned.decision_hint == "deny":
        return FirewallVerdict(
            decision=SecurityDecision.DENY,
            reasons=(f"instruction smuggling denied: {','.join(_authority_labels(cleaned.flags))}",),
        )
    sinks = find_execution_sinks(cleaned.text)
    if sinks:
        return FirewallVerdict(
            decision=SecurityDecision.DENY,
            reasons=(f"execution-sink directive denied: {','.join(sinks)}",),
        )

    reasons = ["scope-bound data-only chunk admitted; labeled untrusted"]
    if cleaned.flags:
        reasons.append("technical normalization applied")
    return FirewallVerdict(
        decision=SecurityDecision.ALLOW,
        reasons=tuple(reasons),
        text=cleaned.text,
        classification=ContextClassification.UNTRUSTED,
        sanitized=True,
    )


def admit_stream(
    session: SubagentSession,
    chunks: Iterable[HostContextChunk],
    *,
    max_chunk_chars: int = MAX_CHUNK_CHARS,
    max_stream_chars: int = MAX_STREAM_CHARS,
    max_chunks: int = MAX_STREAM_CHUNKS,
) -> tuple[FirewallVerdict, ...]:
    """Gate a chunk stream with bounded totals (pure, no execution).

    Each chunk is gated by :func:`admit_chunk`. Admitted chars accumulate;
    breaching ``max_stream_chars`` (or ``max_chunks``) appends one terminal
    ``DENY`` verdict and stops — the oversized tail is rejected, never
    buffered. Non-admitted verdicts (deny/quarantine) pass through inline.
    """
    if not isinstance(max_stream_chars, int) or max_stream_chars <= 0:
        raise ValueError("max_stream_chars must be a positive int")
    if not isinstance(max_chunks, int) or max_chunks <= 0:
        raise ValueError("max_chunks must be a positive int")

    verdicts: list[FirewallVerdict] = []
    admitted_chars = 0
    for chunk in chunks:
        if not isinstance(chunk, HostContextChunk):
            raise TypeError(f"stream chunk must be HostContextChunk, got {type(chunk).__name__}")
        if len(verdicts) >= max_chunks:
            verdicts.append(
                FirewallVerdict(
                    decision=SecurityDecision.DENY,
                    reasons=(f"oversized stream: bounded rejection (>{max_chunks} chunks)",),
                )
            )
            break
        verdict = admit_chunk(session, chunk, max_chunk_chars=max_chunk_chars)
        if verdict.decision == SecurityDecision.ALLOW:
            if admitted_chars + len(verdict.text) > max_stream_chars:
                verdicts.append(
                    FirewallVerdict(
                        decision=SecurityDecision.DENY,
                        reasons=(f"oversized stream: bounded rejection (>{max_stream_chars} chars)",),
                    )
                )
                break
            admitted_chars += len(verdict.text)
        verdicts.append(verdict)
    return tuple(verdicts)


__all__ = [
    "EXECUTION_SINK_LABELS",
    "EXECUTION_SINK_PATTERNS",
    "MAX_CHUNK_CHARS",
    "MAX_STREAM_CHARS",
    "MAX_STREAM_CHUNKS",
    "FirewallVerdict",
    "HostContextChunk",
    "admit_chunk",
    "admit_stream",
    "find_execution_sinks",
]
