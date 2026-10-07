# POST-T020-G6 — Python Version Matrix (EMO-Cyber-Agent)

Owner: G6-A (Python Matrix Owner) · Date: 2026-10-06 · Working dir: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`

## 1. Declared support range (from `pyproject.toml`, no invented versions)

- `requires-python = ">=3.11"` → **minimum supported: Python 3.11** (open upper bound).
- Classifiers explicitly list: `3.11`, `3.12`, `3.13`, `3.14` (plus generic `Python :: 3`).
- Corroborating floors: `ruff target-version = "py311"`, `mypy python_version = "3.11"`.
- **Tested stables claimed by metadata: 3.11 / 3.12 / 3.13 / 3.14.** No other versions are declared or implied.

## 2. Locally available Pythons (discovery)

| Interpreter | Version | Source |
|---|---|---|
| `python3.11` | 3.11.15 | `~/.local/bin` (uv-managed) |
| `python3.12` | 3.12.7 | `~/.local/bin` (uv-managed) |
| `python3.13` | 3.13.13 | `/opt/homebrew` |
| `python3.14` | 3.14.5 | `/opt/homebrew` (default `python3`) |
| `/usr/bin/python3` | 3.9.6 | macOS system — **below minimum, out of scope** |

All four in-range versions were present, so all four were tested. Nothing in range was unavailable.

## 3. Method (bounded, identical per version)

Per interpreter: fresh venv under `/tmp` (`post-t020-g6-py311`, `py312uv`, `py313`, `py314`;
3.12's uv-managed base rejects `ensurepip`, so its venv was created via `uv venv --python 3.12` —
same CPython 3.12.7), `pip install -e ".[dev]"`, then:

1. `import emo_cyber_agent` → version check,
2. `cyber-agent --version` (console script; note: `python -m emo_cyber_agent.cli.main` has no
   `__main__` guard and prints nothing — entry point is the `cyber-agent` script),
3. `pytest tests/unit/subagent/test_contracts.py tests/unit/progress` (53 tests),
4. MCP `tools/list` smoke via `run_stdio()` JSON-RPC round-trip
   (also no `__main__` guard; exercised in-process through `create_server().run_stdio()`).

No repo files modified; all venvs live in `/tmp`.

## 4. Results

| Python | Install | Import | `cyber-agent --version` | pytest subset | MCP `tools/list` | Verdict |
|---|---|---|---|---|---|---|
| 3.11.15 | OK | `0.1.0` | `emo-cyber 0.1.0`, rc 0 | **53 passed** | rc 0, 6 tools | **PASS** |
| 3.12.7 | OK (via uv venv) | `0.1.0` | `emo-cyber 0.1.0`, rc 0 | **53 passed** | rc 0, 6 tools | **PASS** |
| 3.13.13 | OK | `0.1.0` | `emo-cyber 0.1.0`, rc 0 | **53 passed** | rc 0, 6 tools | **PASS** |
| 3.14.5 | OK | `0.1.0` | `emo-cyber 0.1.0`, rc 0 | **53 passed, 1 warning** | rc 0, 6 tools | **PASS** |

MCP tools on all versions: `cyber_audit, cyber_review, cyber_verify, cyber_report, cyber_status, cyber_extensions`.
No version was unavailable, so no NOT SUPPORTED/UNTESTED rows apply within the declared range.
`/usr/bin/python3` (3.9.6) is below `requires-python` and was not tested — correctly excluded, not a failure.

## 5. Version-specific breakage

- **None in repo source.** No `SyntaxError`, no `typing.Self` / `zip(strict=)` / `tomllib`-style
  version gates observed on any of 3.11–3.14.
- **3.14 note (third-party, non-blocking):** one `DeprecationWarning` from `pytest-asyncio`'s plugin
  (`asyncio.get_event_loop_policy` deprecated, slated for removal in Python 3.16), emitted at
  `pytest_asyncio/plugin.py:1216` during fixture setup. Originates in the test dependency, not in
  `emo_cyber_agent` code. Tests still pass (53/53). Worth tracking when pytest-asyncio or the
  3.16 horizon moves, but not a product defect.
- **3.12 environment note (not a product issue):** the local `python3.12` base is uv-managed
  (`externally-managed-environment`), so stdlib `venv`+`ensurepip` fails there; a `uv`-created
  venv with the same CPython 3.12.7 works and the package installs/tests cleanly.

## 6. Minimum-supported statement

**Minimum supported Python is 3.11** (per `requires-python = ">=3.11"`, consistent with the ruff/mypy
py311 floors). **All declared stables — 3.11, 3.12, 3.13, 3.14 — PASS** the bounded matrix
(import + CLI `--version` + 53-test subset + MCP `tools/list`) in fresh isolated venvs. No
version-specific breakage in package code; the single 3.14 warning comes from the `pytest-asyncio`
test dependency.
