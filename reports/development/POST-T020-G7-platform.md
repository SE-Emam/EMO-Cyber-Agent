# POST-T020 G7 Platform Matrix — EMO-Cyber-Agent

- Role: G7-A Platform Matrix Owner for POST-T020.
- Date (UTC): 2026-10-06. Working directory: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`.
- Machine: `Darwin MacBook-Air-Emam.local 25.3.0 … RELEASE_ARM64_T8103 arm64` / Python 3.14.5 / `platform.machine()=arm64`.
- Scope: this file is the single authorized write. No `src/` or `tests/` modifications made.
- Method: every darwin row re-executed on this machine (evidence below); Linux/Windows assessed
  by read-only code inspection only — **never claimed as PASS**.

## 1. Darwin/arm64 — real battery results

Venv: `/tmp/g7venv` (fresh `python3 -m venv`), wheel under test:
`dist/emo_cyber-0.1.0-py3-none-any.whl` (372 entries). Extras `mcp`, `fastapi`, `uvicorn`
installed separately into the venv because the base wheel does not bundle them.

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| D1 | Install wheel into /tmp venv | **PASS** | `pip install dist/emo_cyber-0.1.0-py3-none-any.whl` exit 0; `pip show emo-cyber` → `Version: 0.1.0`; `import emo_cyber_agent` → `__version__ 0.1.0` |
| D2 | CLI `doctor --format human` | **PASS** | exit 0; `schemas: OK (packaged)`, `tool_registry: OK (4 scanner specs)`, `core: OK`; `tool:git/gitleaks/semgrep AVAILABLE`, `tool:osv-scanner/trivy UNAVAILABLE` (this machine) |
| D3 | CLI `doctor --format json` | **PASS** | exit 0; `{"status":"ok","checks":{…}}` valid JSON, sorted keys |
| D4 | CLI `audit … --format json` | **PASS** | exit 0 on `/tmp/g7audit`; stdout is pure `{"status":"ok","result":{…status:created…}}`; stderr silent (by design: JSON mode sinks progress, keeps stdout parseable) |
| D5 | CLI `audit … --format human` | **PASS** | exit 0; stderr progress lifecycle `[audit] STARTED (RUN_STARTED)` → `RUNNING` → `FINALIZING` → `COMPLETED (OPERATION_COMPLETE)`; stdout 3-line summary |
| D6 | MCP stdio `initialize` | **PASS** | `{"id":1,…"serverInfo":{"name":"emo-cyber-agent","version":"0.1.0"}}` |
| D7 | MCP stdio `tools/list` | **PASS** | tools `cyber_audit`, `cyber_review`, `cyber_verify`, `cyber_report…` with `inputSchema`s returned |
| D8 | MCP stdio `tools/call cyber_audit` | **PASS** | `{"id":2,…"content":[{"type":"text","text":"{\"audit_id\":…\"tool\":\"cyber_audit\"…}"}]}`; stderr `dispatched` log; `shutdown … stopped` |
| D9 | MCP protocol rejections | **PASS** | batch → `-32600 batch requests not supported`; `jsonrpc 1.0` → `-32600 jsonrpc must be 2.0`; unknown method → `-32601 unknown method: nope` |
| D10 | HTTP bind (loopback, ephemeral) | **PASS** | `HttpMcpServer().start("127.0.0.1", 0)` → e.g. `http://127.0.0.1:56022/mcp`. **Ran from source tree (`PYTHONPATH=src`): `http_server.py` is NOT in the 0.1.0 wheel** (see gap G2) |
| D11 | HTTP `initialize` + `tools/call` | **PASS** | both `200` with correct JSON-RPC envelopes; `cyber_audit` dispatched (`duration_ms: 11`) |
| D12 | HTTP routing errors | **PASS** | `GET /mcp` → `405`; `POST /nope` → `404` |
| D13 | HTTP non-local bind refusal | **PASS** | `start("0.0.0.0", 0)` → `ValueError: refusing non-local bind '0.0.0.0' without allow_remote=True (fail closed)` |
| D14 | HTTP stop/shutdown + restart | **PASS** | `stop()` clean; fresh instance `ping` → `200 {"id":9,"result":{}}`; second `stop()` clean |
| D15 | Path: spaces + unicode target | **PASS** | `audit "/tmp/g7audit/my project ☃️"` exit 0; `confine_path(root, "my project ☃️/fïle.py")` → `/private/tmp/g7audit/my project ☃️/fïle.py` (macOS `/tmp`→`/private/tmp` realpath correctly resolved) |
| D16 | `confine_path` traversal semantics | **PASS** | `../etc/passwd`, `/etc/passwd`, `..`, `a/../../b`, NUL byte, empty → all `ExecutionError(POLICY_DENIED)`; absolute-inside-root allowed; symlink escape (`link_escape`→`/tmp/g7outside`) → `POLICY_DENIED` (realpath resolution) |
| D17 | `normalize_path` (repository) | **PASS** | `a/../b`, `%2e%2e/x`, `%252e%252e/x`, `/abs`, `C:\win` → `PATH_TRAVERSAL`; `a\b` → `a/b` (backslash normalized, allowed); empty → `FILE_NOT_FOUND` |
| D18 | Subprocess argv boundary | **PASS** | `("echo","hello; touch /tmp/g7pwned")` → stdout literal `hello; touch /tmp/g7pwned`, `/tmp/g7pwned` NOT created (no shell); spaces preserved (`'a b  c'`); missing binary → `TOOL_UNAVAILABLE`; NUL in argv → `POLICY_DENIED` |
| D19 | Env filtering | **PASS** | with `GITHUB_TOKEN=ghp_SUPERSECRET123` in parent env: child env keys == `['LANG']` only, no secret leak; `sanitized_env({"GITHUB_TOKEN":…})` → denied; `sanitized_env({"EVIL_VAR":…})` → denied (not allowlisted) |
| D20 | Timeout | **PASS** | `/bin/sleep 30` with `timeout_s=1` → `TIMEOUT`, `timed_out=True` |
| D21 | Package resources (schemas) | **PASS** | `resource_origin()` → `packaged`; `validate_packaged_schemas()` → all 5 `OK`; `audit-request`/`finding`/`report` re-parsed as JSON |
| D22 | Progress smoke | **PASS** | 4-event lifecycle → last `ProgressEvent percent=100.0`; `reporter.mcp_notification(event)` projects `notifications/progress` params |
| D23 | Recovery smoke | **PASS** | `capture`/`restore` round-trip byte-identical; cross-audit `restore(audit_id="audit-OTHER")` → `ScopeViolationError`; `decide(TRANSIENT)` → `RETRY`; `policy_table()` 10 rows |

Observation (cosmetic, non-blocking): the 0.1.0 wheel reports `emo-cyber-agent 0.1.0` from
`doctor --version`/`checks["package"]` while installed metadata `Name` is `emo-cyber` —
the wheel predates commit `cb71fb8` (dynamic dist-name fix). Consistent with the stale-wheel
finding (gap G2), not a HEAD defect.

## 2. Linux / Windows — portability by inspection (NO execution here)

CI check: `.github/workflows/` contains only `release.yml`; every job is
`runs-on: ubuntu-latest`; **no `strategy.matrix`, no Windows/macOS runners**.
So no OS-matrix evidence exists in CI either.

### 2a. PORTABLE-BY-INSPECTION

| Construct | Location | Judgment |
|---|---|---|
| argv-only subprocess, `shell=False`, `subprocess.run(timeout=…)`; no `shell=True`, `os.system`, `popen` anywhere in `src/` | `core/execution.py:139-146` (+ docstring `:7`) | PORTABLE — timeout is stdlib-managed (TerminateProcess on Windows), no POSIX-signal reliance |
| `confine_path`: `realpath` + `root + os.sep` prefix check | `core/execution.py:107-111,185` | PORTABLE — `os.sep`/`os.path` are per-OS correct; Windows case-only aliasing fails closed (deny), the safe direction |
| `sanitized_env` allowlist (`NO_COLOR,LC_ALL,LANG,TZ`), secret blocklist, 256-char truncation | `core/execution.py:36-37,83-97` | PORTABLE — allowlisted names harmless on all OSes; no `PATH`/`LD_PRELOAD` inheritance |
| `normalize_path`: rejects absolutes, `..`/`.`/empty segments, NUL, single+double percent-encoding; explicit drive-letter deny (`p[1]==":"`); backslash→`/` normalization | `core/repository.py:115-143` | PORTABLE — Windows-specific shapes (`C:\…`, `a\b`) handled explicitly, verified live on darwin in D17 |
| MCP stdio loop: single-line JSON-RPC over `sys.stdin`/`sys.stdout`, `rstrip("\n")`, 1 MiB cap | `mcp/server.py:215-245`, `mcp/protocol.py:23,66-67` | PORTABLE-BY-INSPECTION — universal-newline text mode normalizes `\r\n` on Windows; residual risk only if a host uses binary pipes without newline translation (low) |
| HTTP transport: stdlib `ThreadingHTTPServer`, no `fastapi`/`uvicorn` import, IPv4 loopback default, Host allowlist incl. `::1`, bracket-aware `_normalize_host`, bearer-via-env-ref, 1 MiB cap, bounded oversize drain | `mcp/http_server.py:63,96-112,238-251,358-391` | PORTABLE-BY-INSPECTION — one edge: `ThreadingHTTPServer` defaults to `AF_INET`, so an explicit `::1` bind would fail (minor; default `127.0.0.1` unaffected) |
| `shutil.which` presence checks (doctor + tool resolver); PATH-lookup only, never executes | `cli/main.py:317`, `tools/packs/resolver.py:75-81` | PORTABLE — `shutil.which` is PATHEXT-aware on Windows |
| Config path `~/.config/…` via `os.path.expanduser`; extension roots via `Path.expanduser`, `os.pathsep` split | `cli/main.py:254,538`, `extensions/catalog.py:357-389` | PORTABLE-BY-INSPECTION — `expanduser` works on Windows (`C:\Users\…`); mixed separators accepted by `os.path`/`pathlib` |
| No `signal` import in `src/` (only a docstring mention + `KeyboardInterrupt`→130 mapping) | `cli/main.py:11,117-136` | PORTABLE — `KeyboardInterrupt` exists on all OSes; no `SIGTERM`/`SIGHUP` handlers to break on Windows |
| No `/tmp` hardcoding, no `tempfile`/`mkdtemp` in `src/`; no `chmod`/`umask`/`stat.S_*`; no `os.getuid`/`fork`/`exec`/`kill`/`fcntl`/`msvcrt`/`ctypes.windll` | repo-wide grep (zero hits) | PORTABLE — nothing to behave differently across OSes |
| UTF-8 `errors="replace"` decoding of all subprocess/HTTP bytes; `[\r\n]+` collapsing in reporting | `core/execution.py:150-156`, `mcp/http_server.py:306`, `core/reporting.py:301` | PORTABLE — no line-ending assumption |
| ANSI: only stripped (sanitizer regex), never emitted by Core; `rich`/`typer` own terminal output; `NO_COLOR` allowlisted | `subagent/sanitizer.py:31-33`, `core/execution.py:36` | PORTABLE-BY-INSPECTION — Windows Terminal + `rich` handle ANSI; legacy conhost degradation is cosmetic |
| `_emit` file output `open(path, "w", encoding="utf-8")` | `cli/main.py:96-104` | PORTABLE-BY-INSPECTION — Windows text mode translates `\n`→`\r\n` in markdown/jsonl artifacts (cosmetic; JSON remains parseable) |

### 2b. NEEDS-RUNTIME-PROOF (do NOT treat as PASS)

| # | Item | Location | Reason |
|---|---|---|---|
| N1 | Extension platform vocabulary mismatch: manifest default `platforms=("linux","darwin","win32")` (`sys.platform` vocabulary) vs `host_profile()` producing `platform.system().lower()` → `"windows"` on Windows | `extensions/spec.py:537` vs `extensions/compatibility.py:183-194,214-216` | On Windows, default manifests would evaluate `platform-unsupported` (`"windows" not in (…, "win32")`). Linux/macOS agree in both vocabularies, so this is a **Windows-only defect candidate** — needs a Windows runtime check + a vocabulary-normalization fix |
| N2 | `HostProfile.platform` default `"darwin"` | `extensions/compatibility.py:163` | Darwin-biased default when constructed directly instead of via `host_profile()`; fail direction is benign for default manifests (contain `"darwin"`) but wrong-host attribution on other OSes |
| N3 | All Linux behavior | whole tree | No Linux execution environment on this machine; CI is `ubuntu-latest` for build/test but runs no G7 battery (no CLI/MCP/HTTP/path-matrix job) |
| N4 | All Windows behavior | whole tree | No Windows execution environment; N1 already gives reason to suspect a compat-gate failure there |
| N5 | Scanner-binary availability per OS (`semgrep`, `trivy`, `osv-scanner`, `gitleaks`, `git`) | `cli/main.py:316-317`, `tools/packs/*` | Environment-dependent; even this darwin host lacks `trivy`/`osv-scanner` (D2). Matrix must record per-OS availability, not assume it |
| N6 | IPv6 loopback bind (`::1`) for HTTP transport | `mcp/http_server.py:238-251` | `AF_INET` default + `_require_local_bind` allowlist interaction untested on any OS |
| N7 | Windows `\r\n` stdio framing interop with third-party MCP hosts | `mcp/server.py:219-244` | Reasoning says fine (universal newlines), but no Windows host has ever been exercised (host matrix: 5× Not-tested) |

## 3. Security focus

- **Path traversal semantics**: two independent boundaries, both deny-by-default and both
  demonstrated live (D16/D17). `normalize_path` additionally defeats single- and
  double-percent-encoded traversal (`%2e`, `%252e`) and drive-letter paths; `confine_path`
  defeats symlink escapes via `realpath`. Residual: Windows case-aliasing and ADS
  (`file:stream`) shapes are untested (N4); ADS colon-forms are *not* drive letters
  (`p[1]==":"` only matches `X:`) and would pass `normalize_path` as ordinary names —
  downstream `confine_path` still jails them, but a Windows runtime proof should confirm.
- **argv handling**: single construction site (`tools/packs/executor.py:84-113` → validated
  `tuple[str,…]`, NUL-rejected) → single execution site (`core/execution.py:139`, `shell=False`).
  Repository content never influences argv (fixed adapter logic). Demonstrated inert to
  `;`-injection (D18).
- **Env filtering**: child env is built, never inherited (`sanitized_env`, D19); HTTP bearer
  auth compares against `os.environ[NAME]` by reference, secret never in config/source
  (`mcp/http_server.py:205-216`, fail-closed when unset). CLI surfaces only presence
  (`CONFIGURED`/`MISSING`), never values (`cli/main.py:318-322`); audit targets redacted
  before echo (`cli/main.py:359`).
- **Temp dirs**: no `/tmp` hardcoding and no `tempfile` usage in `src/` — there is no
  temp-dir creation path to hijack (symlink/race) in the product code. Tests were not
  audited for this (out of scope; `src/tests` unmodified per brief).

## 4. Gaps list

- G1. **No OS matrix in CI**: `release.yml` builds/tests/publishes on `ubuntu-latest` only.
  No job runs the G7 battery (install→CLI→MCP→HTTP→paths→subprocess→env→timeouts→
  resources→Progress/Recovery) on any second OS. Recommend `strategy.matrix: [ubuntu-latest,
  windows-latest, macos-latest]` running at least D1–D9 + D15–D21.
- G2. **Shipped 0.1.0 wheel is stale vs HEAD**: lacks `mcp/http_server.py` (and the
  `cb71fb8` dist-name fix), so the HTTP transport (D10–D14) is HEAD-only and could only be
  proven via `PYTHONPATH=src`. Any consumer installing `emo-cyber 0.1.0` from PyPI gets
  stdio-only MCP. Next release cut must rebuild from HEAD.
- G3. **Windows platform-vocabulary defect candidate** (N1): `win32` vs `windows` mismatch
  between `ExtensionCompatibility.platforms` default and `host_profile()`.
- G4. **Linux/Windows verdicts are inspection-only** (N3/N4): honest ceiling for this report
  is PORTABLE-BY-INSPECTION / NEEDS-RUNTIME-PROOF — no untested OS is marked PASS.
- G5. **Scanner availability is per-machine truth** (N5, D2): `trivy`/`osv-scanner`
  unavailable even here; matrix tooling must treat `UNAVAILABLE` as expected-variance, not failure.
- G6. Minor edges carried as notes, not failures: `_emit` newline translation on Windows,
  `AF_INET`-only HTTP bind vs `::1` (N6), `HostProfile` darwin default (N2).

## Verdict

- **darwin/arm64: 23/23 PASS with live evidence** (D1–D23), subject to two non-blocking notes
  (stale release wheel G2; cosmetic dist-name display from that stale wheel).
- **Linux: PORTABLE-BY-INSPECTION** for all reviewed constructs; full battery **NEEDS-RUNTIME-PROOF** (no Linux runner here; CI has no matrix job).
- **Windows: PORTABLE-BY-INSPECTION** for subprocess/env/path/stdio/HTTP primitives, **but
  NEEDS-RUNTIME-PROOF overall**, with one concrete defect candidate (N1 platform vocabulary)
  that should block any Windows-compatible claim until fixed and runtime-verified.
