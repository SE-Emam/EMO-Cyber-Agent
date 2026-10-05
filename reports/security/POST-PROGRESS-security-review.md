# POST-PROGRESS Security Review — Progress Layer (Red-Team / Boundary)

**Auditor:** Sub-Agent 5 — Progress Security Auditor (READ-ONLY on source)
**Date (UTC):** 2026-10-04
**Scope files:**
- `src/emo_cyber_agent/progress/events.py`
- `src/emo_cyber_agent/progress/state.py`
- `src/emo_cyber_agent/progress/reporter.py`
- `src/emo_cyber_agent/progress/__init__.py`
- `tests/unit/progress/test_progress_events.py`
**Authorized output:** this file only (`reports/security/POST-PROGRESS-security-review.md`). No source files were modified.

---

## 1. Scope

Static behavioral review (no execution of attacks) of the Progress layer only:

1. Secret / credential leakage via event fields, `to_dict()`, `__repr__`, CLI print, MCP notification.
2. Prompt / Chain-of-Thought / raw tool-output leakage through progress fields.
3. Filesystem path overexposure.
4. Project / audit identifier cross-contamination (`run_id`, `audit_id`).
5. Progress events usable as command-and-control (event fields interpreted as code, sink selection, callbacks, policy changes).
6. Event injection via untrusted strings (`phase` / `status` / `message_code` / `run_id` / `event_type` / `timestamp` / `from_dict`).
7. Terminal escape / control-char / newline / Markdown / TTY injection in `cli_sink` `print`.
8. MCP notification injection / JSON framing corruption.
9. Progress-token misuse surface.
10. Unbounded event generation / memory growth (`events` lists).
11. Attacker-controlled phase names.
12. Timestamp nondeterminism effects.
13. Boundary: does Progress mutate source / policy / finding lifecycle? Does any sink grant capability or change `PolicyDecision`?

Cross-module check performed via content search for `ProgressReporter|ProgressEvent|ProgressState|cli_sink|mcp_notification` consumers and for `PolicyDecision|policy|finding|secret|password|token|prompt|open(|subprocess|os.|eval|exec|pickle` inside `src/emo_cyber_agent/progress/`. Result: Progress is self-contained; no policy/finding/source imports; no secret, subprocess, eval/exec, pickle, or filesystem access in the layer.

## 2. Method

- Read all five in-scope files in full.
- Traced every data flow: constructor validation → `to_dict`/`from_dict` → `ProgressState.advance` → `ProgressReporter.report` → `cli_sink` / `mcp_notification`.
- Checked each sink for side effects beyond display/serialization and for any interpretation of event content as code, path, command, Markdown, or JSON framing.
- Checked validation allowlists/denylists, error paths, equality semantics, and unbounded collections.
- Checked test file only for assumed contracts (it does not expand the attack surface; `sys.path.insert` there is test-only and not shipped).
- No files under `src/`, `tests/`, `cli/`, `mcp/` were edited.

## 3. Findings

| ID | Severity | Category | Location (evidence) | Description | Exploitable? |
|----|----------|----------|---------------------|-------------|--------------|
| F1 | Low | Terminal / log injection (defense-in-depth) | `src/emo_cyber_agent/progress/reporter.py:37`; inputs `src/emo_cyber_agent/progress/events.py:62-89` | `cli_sink._sink` interpolates `event.phase` and `event.message_code` verbatim into `print(f"[{bar}] {event.percent:6.2f}% {event.phase} ({event.message_code})")` with no stripping of `\n`, `\r`, `\x1b`, or other control characters. A phase/message containing e.g. `"OK\n[FAKE] 100% DONE"` or `"\x1b[2J\x1b[H"` would emit multi-line / ANSI-escape output, enabling log spoofing or terminal redraw tricks. Mitigating fact: the normal `ProgressState.advance()` path restricts `phase` to the pre-declared `phases` list (`state.py:53-54`), so exploitation requires trusted code to pass untrusted strings either as a `phases` entry or via direct `ProgressEvent(...)` / `from_dict`. Not remotely reachable by itself. | No — requires caller to forward untrusted input; no remote PoC within layer alone. Hardening only. |
| F2 | Low | Unbounded memory growth / DoS hardening | `src/emo_cyber_agent/progress/state.py:20,70`; `src/emo_cyber_agent/progress/reporter.py:17,23` | Both `ProgressState.events` and `ProgressReporter._events` are plain append-only `list`s with no cap, trim, or `clear()` API. A tight loop calling `advance()`/`report()` grows memory without bound. This is a bug-amplified local availability concern, not a remote vuln: the caller must already be able to invoke these methods arbitrarily. `reporter.events` returns a copy (`reporter.py:29-30`), which is good (prevents external mutation), but does not bound growth. | No — no remote trigger; needs code execution / tight loop already. Hardening only. |
| F3 | Low | UI spoofing via free-form phase/status (no allowlist on direct path) | `src/emo_cyber_agent/progress/events.py:62-89,121-138`; contrast `src/emo_cyber_agent/progress/state.py:52-55` | `ProgressEvent.__init__` and `from_dict` accept any non-empty `phase`/`status`/`message_code` (e.g. `phase="COMPLETED"`, `status="COMPLETED"`, `message_code="OPERATION_COMPLETE"`) without allowlisting. Only `ProgressState.advance(phase=...)` enforces `phase in self.phases`. A caller constructing events directly can therefore emit a fake terminal-state event. Impact is display-level misleading only; no lifecycle, policy, or control-flow decision in this layer consumes these strings. | No — spoofing is display-only; does not change any lifecycle or decision. |
| F4 | Info | Audit-trail mixing (shared reporter has no run partitioning) | `src/emo_cyber_agent/progress/reporter.py:15-26`; binding `src/emo_cyber_agent/progress/state.py:14-15,57-59` | `ProgressState` correctly binds `run_id`/`audit_id` at construction and reuses them in every emitted event. `ProgressReporter`, however, aggregates all `report()`ed events into a single `_events` list with no per-`run_id` partitioning or consistency check. If one reporter instance is shared across runs, `reporter.events` interleaves runs. This is expected fan-out behavior, but consumers that assume "one reporter == one run" could misattribute progress. No identifier is overwritten or confused inside an event itself. | No. |
| F5 | Info | Naive timestamp / nondeterminism (auditability, not security) | `src/emo_cyber_agent/progress/events.py:31-41,102,140-155` | Default timestamp is `datetime.now()` (naive, local timezone, no monotonic clock). `__eq__` deliberately excludes `timestamp` (good — equality stays deterministic), but `to_dict` round-trips it and two otherwise-identical events get different timestamps. `fromisoformat` accepts naive strings. Effect is ordering/auditability noise, not a vuln; no security decision uses the timestamp. | No. |
| F6 | Info | No secret / prompt / CoT / tool-output / path surface in layer | `src/emo_cyber_agent/progress/events.py:47-118,157-164`; `src/emo_cyber_agent/progress/reporter.py:32-45` | Event schema is fixed to counters/identifiers/status codes (`run_id`, `audit_id`, `phase`, `phase_index`, `phase_count`, `completed`, `total`, `percent`, `status`, `message_code`, `event_type`, `timestamp`). No secret, password, token, prompt, CoT, tool-output, or filesystem-path fields exist; `__repr__`/`to_dict`/CLI/MCP emit only those fields. Leakage would require upstream code to embed secrets into `status`/`phase`/`message_code` — layer does not do so itself and has no redaction duty beyond not adding such fields (which it honors). | No. |
| F7 | Info | No command/control, JSON framing, or token-confusion surface | `src/emo_cyber_agent/progress/events.py:17-28`; `src/emo_cyber_agent/progress/reporter.py:22-26,41-45` | `event_type` parsing is a strict allowlist (`PROGRESS`/`ERROR`, case/whitespace-tolerant, else `ValueError`). `report()` never interprets event content as code and never selects sinks based on event content — sinks are host-registered callables. `mcp_notification` returns a structured `dict` with hardcoded `method="notifications/progress"` and `params=event.to_dict()`; no string-concatenated JSON, so no framing injection (downstream `json.dumps` escapes content). No `progressToken`/correlation token exists in this layer, so no token fixation/replay surface. | No. |

No Critical, High, or Medium findings. Highest severity: **Low**.

### Notes on items explicitly hunted with no finding

- **Secret/credential leakage:** none. No credential handling, no env access.
- **Prompt/CoT/raw tool output leakage:** none originated in layer. `status`/`message_code` *could* carry arbitrary caller-supplied text (see F1/F3), but layer defines them as short codes (`"PHASE_STARTED"` default, `state.py:49`) and never pulls tool output itself.
- **Filesystem path overexposure:** none. No paths, no `open()`/`os`/`pathlib`.
- **C2 via events:** none. No `eval`/`exec`/`subprocess`/`__import__`/`pickle`, no dynamic dispatch on event fields.
- **Markdown injection:** `cli_sink` prints plain text via `print`, not rendered Markdown; newline/control-char concern is covered by F1 (Low).
- **Event injection via `event_type`:** blocked by allowlist (`events.py:17-28`); invalid values raise `ValueError`, unknown `from_dict` keys are ignored, missing keys raise `ValueError` (`events.py:137-138`).
- **`phase_index`/`phase_count`/`completed`/`total`/`percent` injection:** numeric validation is strict — bool rejected, ranges enforced (`events.py:68-85`), `completed > total` rejected. `percent` coerced via `float()` but range-checked. `filled` bar computation (`reporter.py:35`) is arithmetic on validated `percent`; negative/overflow bar widths are impossible given `[0,100]` enforcement.
- **Attacker-controlled phase names:** partially mitigated — `advance()` allowlists against `self.phases`, but `phases` list entries themselves and direct `ProgressEvent` phases are unvalidated (covered by F1/F3, Low at most).
- **Test file:** `tests/unit/progress/test_progress_events.py` only constructs synthetic events with benign constants; `sys.path.insert` (lines 11, 13) is test-harness-only, not shipped code. No additional surface.

## 4. Boundary Analysis

**Does the Progress layer mutate source / policy / finding lifecycle? No.**

- Imports are limited to `datetime`, `enum`, `typing`, `dataclasses`, and intra-package `.events` (`state.py:7`, `reporter.py:7`, `__init__.py:7-9`). No imports of policy, findings, sources, or lifecycle managers (verified by content search — zero matches).
- `ProgressState` mutates only its own counters (`completed`, `current_phase_index`) and appends to its own `events` list (`state.py:56,70`). `ProgressReporter.report` appends to its own `_events` and invokes host-registered sinks (`reporter.py:22-26`). Neither returns nor accepts a `PolicyDecision`, finding, or source object.
- `__eq__` excludes `timestamp`, so event comparison cannot be swayed by clock games to fake lifecycle transitions.

**Does any sink grant capability or change `PolicyDecision`? No.**

- `cli_sink` (`reporter.py:32-39`) only computes a 20-char `#`/`-` bar from validated `percent` and calls `print`. No return of authority, no file/network access, no policy hook.
- `mcp_notification` (`reporter.py:41-45`) is a pure function returning a notification dict. It performs no I/O and grants no capability; actual delivery is the host's responsibility.
- `add_sink`/`report` accept host-provided callables; event *content* never chooses or escalates a sink. A malicious sink would have to be registered by already-trusted host code — outside this layer's threat model.

**Identifier handling:** `run_id`/`audit_id` are opaque non-empty strings, validated but not allowlisted (correct — they are correlation IDs, not commands). They are echoed verbatim in `to_dict`/`__repr__`/MCP params, which is intended correlation behavior, not cross-contamination: `State` never swaps them (`state.py:58-59`), and `from_dict` preserves them exactly (round-trip tested).

## 5. Verdict

**PASS** — no real exploitable vulnerability with a plausible proof-of-concept confined to this layer. All identified issues are Low (display spoofing / TTY-control hardening, unbounded-list hardening) or Info, each requiring already-trusted code to misuse the API (e.g., forwarding untrusted text into `phase` or looping `advance()` unboundedly). `BLOCKED` is not warranted under the review rule (BLOCKED only for real exploitable vuln with PoC reasoning).

## 6. Minimal fix directions (NOT applied — read-only audit)

If the owning team wants defense-in-depth hardening in a future change (no action taken here):

1. **F1 (TTY/log injection):** sanitize in `cli_sink` only (keep stored event canonical): e.g. `clean = "".join(ch for ch in f"{event.phase} ({event.message_code})" if ch.isprintable() and ch not in "\r\n\x1b")` or a small `_sanitize_for_tty()` helper stripping ANSI CSI sequences (`\x1b\[...`), `\r`, `\n`, and other `Cc` controls; optionally truncate to a max length. Do not reject at `ProgressEvent` construction (stored/serialized form should stay faithful).
2. **F2 (unbounded growth):** cap with `collections.deque(maxlen=N)` or document caller-owned lifecycle with an explicit `clear()` and a `max_events` guard that raises or drops-oldest; apply symmetrically to `ProgressState.events` and `ProgressReporter._events` if long-lived reporters are expected.
3. **F3 (phase spoofing):** where strict pipelines matter, construct display strings from `ProgressState.current_phase` / server-known phase tables rather than raw event `phase`, or add an optional `allowed_phases` validator at the reporting boundary (not in the `ProgressEvent` value object itself, to preserve its transport role).
4. **F4/F5 (hygiene):** document "one reporter per run or filter `reporter.events` by `run_id`"; consider timezone-aware default (`datetime.now(timezone.utc)`) for new timestamps while continuing to accept naive ISO strings for back-compat.

---

*End of report. No source, test, CLI, or MCP files were created or modified; this report file is the sole artifact.*
