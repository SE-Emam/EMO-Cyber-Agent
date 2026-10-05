# POST-T017 — Git Repository Forensics (EMO-Cyber-Agent Release Recovery)

**Agent:** Agent 1 — Git Repository Forensics
**Date:** 2026-10-05 (UTC)
**Scope:** READ-ONLY investigation. No `add`/`commit`/`push`/`reset`/`clean`/`checkout` executed.
**Method:** read-only git commands only (`rev-parse`, `status`, `log`, `remote`, `tag`, `check-ignore`, `ls-files`), plus read-only `ls` of filesystem.

---

## 1. Repo-root answers

| Question | Finding |
|---|---|
| `pwd` (project dir) | `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent` |
| `git rev-parse --show-toplevel` from project dir | `/Users/emamabdullaziz` |
| `git rev-parse --show-toplevel` from `/Users/emamabdullaziz` | `/Users/emamabdullaziz` |
| Is `/Users/emamabdullaziz` really the repo root? | **YES.** The entire home directory is a single git repo (`/Users/emamabdullaziz/.git`). |
| `Desktop/EMO-Cyber-Agent/.git` exists (own repo)? | **NO.** `ls` returns `No such file or directory`. The project has no independent `.git`. |
| Git dir / absolute git dir (from home) | `.git` → `/Users/emamabdullaziz/.git` |
| Current branch | `main` (no upstream symbolic ref: `refs/remotes/origin/HEAD` is not a symbolic ref) |
| Remote URL(s) | `origin  https://github.com/emam2025/Tech-Makers.git` (fetch + push). **Note: remote points at Tech-Makers, not an EMO-Cyber-Agent repo.** |
| Last 5 commits (home repo) | `9f6ba34 feat: complete extension compatibility contract per POST-RC-014` · `d2cf50c security: add cyber security, web isolation, meta-web, and context regulation` · `2b2c8dd feat: deployment backup/restore, secret rotation flow, prod baseline and DR runbook (UAG-028, NOT GREEN)` · `84e3e81 feat: generic observability layer with safe correlation, metrics, logs, SLOs (UAG-027)` · `1b61dc0 docs: regression totals correction with machine-verified ledger (no code, no tags moved)` — all UAG/Emo-AI-Gateway work, none touch `Desktop/EMO-Cyber-Agent` (`git log --oneline -- Desktop/EMO-Cyber-Agent` returns only `9f6ba34`, incidental). |
| Tags relevant to emo / any `v0.1.0`? | **NONE for EMO-Cyber-Agent. No `v0.1.0`, no `emo*`, no `ECA*` tags.** All 17 tags are `uag-*-green` (`uag-009.5-green` … `uag-027-green`). `git tag --list | grep -Ei "v0.1.0|emo|ECA|emo-cyber"` returns empty. |

### Tracked vs untracked (project scope)

- `git ls-files -- Desktop/EMO-Cyber-Agent` → **only 2 tracked files**: `Desktop/EMO-Cyber-Agent/CHANGELOG.md` and `Desktop/EMO-Cyber-Agent/reports/security/ECA-T016-invariant-release-gate.md`.
- Everything else in the project is **untracked**: 957 entries with `--exclude-standard`, 982 without excludes (delta = files ignored only by nested rules: `dist/*` via `dist/.gitignore`, `.pytest_cache/*` via its own `.gitignore`).
- `git status --short -- Desktop/EMO-Cyber-Agent` collapses to **21 top-level lines** (whole dirs shown as `?? docs/`, `?? src/`, etc.), but the true file count underneath is ~957.

---

## 2. `.gitignore` status

| Location | Exists? | Content / effect |
|---|---|---|
| `Desktop/EMO-Cyber-Agent/.gitignore` | **NO** | Missing — project has no ignore file of its own. |
| `/Users/emamabdullaziz/.gitignore` (repo root) | **NO** | Missing — home-dir repo has no root ignore file at all. |
| Nested ignores that DO exist | Yes, incidental | `Desktop/EMO-Cyber-Agent/dist/.gitignore` (`*` — covers `dist/` build outputs incl. `emo_cyber_agent-0.1.0` wheel/sdist), `Desktop/EMO-Cyber-Agent/.pytest_cache/.gitignore` (`*`), plus `.gitignore` files under `Desktop/Emo-AI-Gateway/**` (irrelevant to this project). |

`git check-ignore -v` probe results (paths tested, run from home root):

- `Desktop/EMO-Cyber-Agent/dist/x` → **ignored** via `Desktop/EMO-Cyber-Agent/dist/.gitignore:1:*`
- `Desktop/EMO-Cyber-Agent/.pytest_cache/d` → **ignored** via its own `.gitignore`
- `Desktop/EMO-Cyber-Agent/__pycache__/a.pyc` → **NOT ignored** (`::` = no match)
- `Desktop/EMO-Cyber-Agent/.venv/b` → **NOT ignored** (no `.venv` exists on disk today, but nothing would exclude one)
- `Desktop/EMO-Cyber-Agent/.DS_Store` → **NOT ignored**
- `Desktop/EMO-Cyber-Agent/reports/development/test.md` → **NOT ignored** (correct — reports must be committable)

### Gap list (what is NOT covered anywhere)

1. `__pycache__/` + `*.pyc` — **306 junk files** would be added by any directory-scoped `git add` (observed live under `src/**`, `scripts/**`, `tests/**`).
2. `.DS_Store` — **5 files** (`./`, `reports/`, `reports/.DS_Store`, `docs/`, `scripts/`, `src/` variants) unignored.
3. `.venv/` — no rule; absent today but one `pip install` away from a multi-thousand-file accident.
4. `.pytest_cache/` — covered only by its own nested file; fragile if cache is ever recreated without it.
5. Build leftovers outside `dist/` (e.g. `*.egg-info/`, `build/`) — no rule.
6. IDE/editor droppings (`.vscode/`, `*.swp`) — no rule.
7. **Home-dir dotfiles/caches as a class** — no root ignore, so every `.config/`, `.npm/`, `.cache/` etc. shows as `??` (see §4).

**Recommendation (for the committer, NOT executed):** create a root `.gitignore` (or at minimum `Desktop/EMO-Cyber-Agent/.gitignore`) with `__pycache__/`, `*.pyc`, `.DS_Store`, `.venv/`, `.pytest_cache/`, `*.egg-info/`, `build/` before any broad add. Until then, only explicit-file pathspecs are safe (see §5).

---

## 3. Scoped status: Progress + Recovery + reports

All paths below are relative to the repo root `/Users/emamabdullaziz` (prefix `Desktop/EMO-Cyber-Agent/`), verified via `git ls-files --others --exclude-standard`.

### 3a. New package sources (12 files)

**`progress` (4):**

- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/__init__.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/events.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/reporter.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/state.py`

**`recovery` (8):**

- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/__init__.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/actions.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/checkpoint.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/classification.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/errors.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/manager.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/policy.py`
- `Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/reporting.py`

### 3b. Progress/Recovery tests (5 files)

- `Desktop/EMO-Cyber-Agent/tests/unit/progress/test_progress_events.py`
- `Desktop/EMO-Cyber-Agent/tests/unit/recovery/test_recovery_contracts.py`
- `Desktop/EMO-Cyber-Agent/tests/unit/test_cli_progress.py`
- `Desktop/EMO-Cyber-Agent/tests/unit/test_mcp_progress.py`
- `Desktop/EMO-Cyber-Agent/tests/unit/test_progress_e2e.py`

### 3c. Reports (6 files, incl. this one)

- `Desktop/EMO-Cyber-Agent/reports/development/POST-PROGRESS-core-review.md`
- `Desktop/EMO-Cyber-Agent/reports/development/POST-PROGRESS-final-review.md`
- `Desktop/EMO-Cyber-Agent/reports/development/POST-PROGRESS-git-hygiene.md`
- `Desktop/EMO-Cyber-Agent/reports/development/POST-T016-postrelease-progress-recovery-assessment.md`
- `Desktop/EMO-Cyber-Agent/reports/security/POST-PROGRESS-security-review.md`
- `Desktop/EMO-Cyber-Agent/reports/development/POST-T017-git-forensics.md` (this report)

### 3d. Deliberately EXCLUDED from this scoped set

- `src/emo_cyber_agent/cli/main.py` and `src/emo_cyber_agent/mcp/server.py` reference progress/recovery but are part of the much larger untracked `src/` tree; including them requires pulling in the full package (out of scope for a Progress+Recovery commit — owner to decide).
- `__pycache__/*.pyc` alongside every package above (306 files project-wide) — must never be added.
- `.DS_Store` files (5) — must never be added.
- `dist/` build artifacts (`emo_cyber_agent-0.1.0-py3-none-any.whl`, `.tar.gz`) — ignored by nested rule; leave untracked.
- Everything else untracked in the project (`docs/`, `templates/`, `examples/`, `scripts/`, rest of `src/`, `tests/`, `release/`, top-level `README.md`/`pyproject.toml`/`Makefile`/`LICENSE`/`SECURITY.md`/`CONTRIBUTING.md`, `Alignment`) — belongs to a later full-import commit, not this scoped one.

**Intended scoped file count: 12 + 5 + 6 = 23 files.**

---

## 4. Blast-radius assessment: can the project be managed without sweeping home-dir files?

**YES — but ONLY with explicit pathspecs run from the repo root.** Evidence:

- Total pending entries repo-wide: **~172–173 top-level `git status --short` lines**.
- Of those, only **21** belong to `Desktop/EMO-Cyber-Agent`; **151 are unrelated** (other projects, Desktop files, home dotfiles/caches).
- A bare `git add .` from `/Users/emamabdullaziz` (or `git add -A`) would stage essentially the entire home directory: dotfiles (`.zshrc`, `.gitconfig`, `.ssh/`), caches (`.npm/`, `.cache/`, `.cargo/`, `.docker/`, `.ollama/`), sibling projects (`Desktop/Emo-AI-Gateway/**` incl. its 14 modified files, `B-Class/`, `Applications/`), and media (`Desktop/*.png`, `Desktop/60540.webp`). **This must never be run.**
- Even `git add Desktop/EMO-Cyber-Agent` (whole dir) is unsafe today: with no project/root `.gitignore`, it would pull in 306 `__pycache__`/`.pyc` files + 5 `.DS_Store` files.
- Scoped `git status --short -- Desktop/EMO-Cyber-Agent` and `git ls-files --others --exclude-standard -- <path>` both work correctly from the root, so fine-grained pathspecs are fully supported.

---

## 5. Recommended exact `git add` command (for a human committer — NOT executed)

Run from repo root `/Users/emamabdullaziz`. Explicit file paths only; the only directory arguments are the two new leaf package dirs, and they REQUIRE a `.gitignore` (or `--dry-run` verification) first because of co-located `__pycache__`. Safest form — **no directory wildcards at all**:

```sh
git add -- \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/__init__.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/events.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/reporter.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress/state.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/__init__.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/actions.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/checkpoint.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/classification.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/errors.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/manager.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/policy.py \
  Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery/reporting.py \
  Desktop/EMO-Cyber-Agent/tests/unit/progress/test_progress_events.py \
  Desktop/EMO-Cyber-Agent/tests/unit/recovery/test_recovery_contracts.py \
  Desktop/EMO-Cyber-Agent/tests/unit/test_cli_progress.py \
  Desktop/EMO-Cyber-Agent/tests/unit/test_mcp_progress.py \
  Desktop/EMO-Cyber-Agent/tests/unit/test_progress_e2e.py \
  Desktop/EMO-Cyber-Agent/reports/development/POST-PROGRESS-core-review.md \
  Desktop/EMO-Cyber-Agent/reports/development/POST-PROGRESS-final-review.md \
  Desktop/EMO-Cyber-Agent/reports/development/POST-PROGRESS-git-hygiene.md \
  Desktop/EMO-Cyber-Agent/reports/development/POST-T016-postrelease-progress-recovery-assessment.md \
  Desktop/EMO-Cyber-Agent/reports/security/POST-PROGRESS-security-review.md \
  Desktop/EMO-Cyber-Agent/reports/development/POST-T017-git-forensics.md
```

Pre-flight (still read-only, recommended before the add):

```sh
git status --short -- Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/progress Desktop/EMO-Cyber-Agent/src/emo_cyber_agent/recovery
git add --dry-run -- <paths above>
```

---

## 6. Files outside the project that must NEVER be committed

| Category | Examples observed in `git status` (non-exhaustive) |
|---|---|
| Shell/credential dotfiles | `.zshrc`, `.zshenv`, `.zprofile`, `.bash_history`, `.profile`, `.gitconfig`, `.ssh/`, `.emulator_console_auth_token`, `.forge-permissions.json` |
| Package/tool caches | `.npm/`, `.cache/`, `.cargo/`, `.rustup/`, `.nvm/`, `.bun/`, `.pub-cache/`, `.gradle/`, `.matplotlib/`, `.kaggle/` |
| Cloud/secret stores | `.supabase/`, `.railway/`, `.docker/`, `.config/`, `.local/` |
| Model/runtime data | `.ollama/`, `.lmstudio/`, `.cache 4.26.43 AM/`, `.emo/`, `.emo-server.log`, `.emo-tests/`, `.emo_ai/` |
| Sibling projects | `Desktop/Emo-AI-Gateway/**` (incl. 14 modified tracked files), `B-Class/`, `Applications/` |
| Desktop/media strays | `Desktop/.DS_Store`, `Desktop/60540.webp`, `Desktop/ChatGPT Image Sep 26, 2026, 11_52_33 PM.png` |
| Home-dir state | `.CFUserTextEncoding`, `.DS_Store`, `.vscode/`, `.cline/`, `.agents/`, `.opencode/`, `.zsh_sessions/`, `.bash_sessions/` |
| In-project junk (also never) | `**/__pycache__/`, `**/*.pyc`, `**/.DS_Store`, `.venv/`, `dist/*.{whl,tar.gz}` |

Structural note: the long-term fix is to `git init` a standalone repo inside `Desktop/EMO-Cyber-Agent` (or move it out of a home-dir repo) and add a proper `.gitignore`. Until then, every git operation must use `Desktop/EMO-Cyber-Agent/`-scoped pathspecs from `/Users/emamabdullaziz`, and `git add .` / `git add -A` / `git commit -a` from the root are forbidden.

---

## Verdict: PASS

A safe scoped commit of the Progress + Recovery + reports work (23 explicit files, §3) is possible with the exact pathspec in §5. No BLOCKED condition: no renames/deletes to preserve, no required files ignored, no tags to move. Residual risks (missing `.gitignore`, home-dir root, wrong-remote `Tech-Makers`) are contained as long as the committer uses explicit paths and never runs a bare add.
