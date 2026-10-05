# POST-T019 Repo Recon — EMO-Cyber-Agent (READ-ONLY)

Date: 2026-10-05 (UTC)
Working dir: /Users/emamabdullaziz/Desktop/EMO-Cyber-Agent
Scope: RECON ONLY — no create/push/tag/remote/commit executed.

## 1. GitHub auth + account

Command: `gh auth status` (10s timeout)
```
github.com
  ✓ Logged in to github.com account emam2025 (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org', 'repo', 'workflow'
EXIT: 0
```
Account: `emam2025`
Scopes present: `gist, read:org, repo, workflow` — sufficient for repo create + push + Actions.

Command: `gh repo list --limit 20`
- Returned 12 repos including org repos under `SE-Emam/` (user is member/accessible).
- Notable hit: `SE-Emam/EMO-Cyber-Agent` — public, created `2026-10-05T16:03:55Z`.

## 2. Repo existence check

Obvious candidate (personal account):
Command: `gh repo view emam2025/EMO-Cyber-Agent`
```
GraphQL: Could not resolve to a Repository with the name 'emam2025/EMO-Cyber-Agent'. (repository)
EXIT: 1
```
Verdict personal: **NOT-FOUND** — `emam2025/EMO-Cyber-Agent` does not exist.

Org repo (found via single `repo list`, verified once):
Command: `gh repo view SE-Emam/EMO-Cyber-Agent --json name,owner,url,isPrivate,createdAt,updatedAt,defaultBranchRef`
```json
{"createdAt":"2026-10-05T16:03:54Z","defaultBranchRef":{"name":""},"isPrivate":false,"name":"EMO-Cyber-Agent","owner":{"id":"U_kgDOC6Atxw","login":"SE-Emam"},"updatedAt":"2026-10-05T16:03:55Z","url":"https://github.com/SE-Emam/EMO-Cyber-Agent"}
EXIT: 0
```
Verdict org: **EXISTS** — `SE-Emam/EMO-Cyber-Agent`, public, empty (`defaultBranchRef.name == ""`, no branches yet, created today).
No further broad-searches performed per instructions.

## 3. PyPI

Command: `curl -s -m 15 https://pypi.org/pypi/emo-cyber-agent/json -o /dev/null -w "%{http_code}"`
```
404
```
Verdict: **404 — name `emo-cyber-agent` free** (no body parsed).

## 4. Local git state

From `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`:
```
git remote -v:
origin  https://github.com/emam2025/Tech-Makers.git (fetch)
origin  https://github.com/emam2025/Tech-Makers.git (push)
branch: main
git-dir: /Users/emamabdullaziz/.git
toplevel: /Users/emamabdullaziz
```
From `/Users/emamabdullaziz`:
`git status --short -- Desktop/EMO-Cyber-Agent | head -15`:
```
~ Modified: 3 files
   Desktop/EMO-Cyber-Agent/release/SHA256SUMS
   Desktop/EMO-Cyber-Agent/release/effective_artifact_verification.json
   Desktop/EMO-Cyber-Agent/release/release-manifest.json
? Untracked: 12 files
   Desktop/EMO-Cyber-Agent/Alignment
   Desktop/EMO-Cyber-Agent/CONTRIBUTING.md
   Desktop/EMO-Cyber-Agent/LICENSE
   Desktop/EMO-Cyber-Agent/Makefile
   Desktop/EMO-Cyber-Agent/README.md
   Desktop/EMO-Cyber-Agent/SECURITY.md
   Desktop/EMO-Cyber-Agent/docs/
   Desktop/EMO-Cyber-Agent/examples/
   Desktop/EMO-Cyber-Agent/pyproject.toml
   Desktop/EMO-Cyber-Agent/release/CHANGELOG.md
   ... +2 more
```

- Project `.git`: `ls -d .../EMO-Cyber-Agent/.git` → `No such file or directory`. **Confirmed: project has no own .git** — nested subtree in parent monorepo (`/Users/emamabdullaziz/.git`, remote `Tech-Makers`).
- Project `.gitignore`: present at `Desktop/EMO-Cyber-Agent/.gitignore` (13 lines, scoped to subtree).
- Parent `.gitignore`: absent at `/Users/emamabdullaziz/.gitignore`.

## 5. Secrets scan + stray files

Command: `grep -rn -i -l "ghp_\|sk-live\|BEGIN PRIVATE KEY" src/emo_cyber_agent --include="*.py" | grep -v test | head`
Hits (7 files, content-verified — all scanner patterns/mocks, NOT real secrets):
- `src/emo_cyber_agent/core/repository.py:53` — `re.compile(r"(?i)(ghp_[A-Za-z0-9]+)")` (detection regex)
- `src/emo_cyber_agent/adapters/supabase.py:56` — string check for `"sb_secret_", "eyJ", "ghp_", "service_role:"` (redaction guard)
- `src/emo_cyber_agent/adapters/github.py:75` — string check for `"ghp_", "github_pat_", "gho_"` (redaction guard)
- `src/emo_cyber_agent/adapters/mock_scanners.py:31` — `"Token": "ghp_REALTOKEN123"` (mock fixture)
- `src/emo_cyber_agent/evaluation/oracle.py:61` — `re.compile(r"ghp_[0-9a-zA-Z]{20,}")` (detection regex)
- `src/emo_cyber_agent/evaluation/sut.py:531` — combined secret regex (detection)
- `src/emo_cyber_agent/subagent/result_firewall.py:147-148` — combined secret regex (detection)
Verdict: **No real secrets** — all hits are regex/placeholder logic. No `BEGIN PRIVATE KEY` hits.

Stray top-level entries that must NOT be committed (quick `ls -a`):
- `.venv/` — present, covered by `.gitignore` (`.venv/`, `venv/`)
- `dist/` — present, covered (`dist/`, `build/`)
- `.pytest_cache/`, `.ruff_cache/` — present, covered
- `.DS_Store` — present, covered
Do NOT commit these; `.gitignore` already excludes them.

## 6. Decision

OPTION (A) — New standalone repo via `gh repo create` (RECOMMENDED, needs user approval — NOT executed):
```bash
gh repo create emam2025/EMO-Cyber-Agent --public \
  --description "Portable, model-agnostic, governed cybersecurity subagent for code, applications, agents, prompts, MCP, and cloud security." \
  --source=/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent --remote=origin --push
```
Note: `SE-Emam/EMO-Cyber-Agent` already exists empty/public (created today). If org is intended owner, skip create and instead init/push to existing empty repo after user confirms owner + visibility — DO NOT push without approval since project currently has no own `.git` and parent remote is `Tech-Makers`.

OPTION (B) — Monorepo path (keep under `emam2025/Tech-Makers` / `/Users/emamabdullaziz`):
Fails independence: PyPI publish, standalone Actions, version tags, `pip install emo-cyber-agent`, and external contributors all assume repo root == package root (`pyproject.toml`, `src/`, `LICENSE`). Nested path breaks release automation, pollutes Tech-Makers history with agent releases, and couples access control to an unrelated private repo. Reject for POST-T019.

Recommendation: **OPTION A** — standalone repo. Prefer clarifying owner first: use existing empty `SE-Emam/EMO-Cyber-Agent` (if org ownership intended) OR create `emam2025/EMO-Cyber-Agent` (command above).

Prerequisites before create/push:
- [ ] User approval for owner/name + visibility (org `SE-Emam` vs personal `emam2025`)
- [ ] `gh` scopes: already have `repo, workflow, gist, read:org` — OK; need `admin:org` only if creating under org with restricted policy (verify on execute)
- [ ] PyPI account + trusted-publisher / API token for `emo-cyber-agent` (name free, 404)
- [ ] Actions: PyPI trusted publishing + provenance configured post-create
- [ ] Clean init: fresh `git init` in subtree copy (not in-place inside parent monorepo) to avoid pushing `.venv/dist/caches`; verify `.gitignore` respected

## Verdict

**READY-FOR-CREATE (needs user approval)** — auth OK, PyPI 404, no real secrets, .gitignore present, personal name free; org name already taken-empty. No write actions taken.
