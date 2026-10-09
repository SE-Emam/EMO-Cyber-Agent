# POST-T021 — Jan Native Integration (T21-C)

- Date (UTC): 2026-10-08T19:19:53Z
- Agent: T21-C — Jan Native Integration Agent
- Working directory: `/Users/emamabdullaziz/Desktop/EMO-Cyber-Agent`
- Constraints honored: wrote exactly this one file; did NOT modify `src/`/`tests/`/`docs/`/any other agent file; did NOT download any model; read-only inspection of Jan data/config (names/sizes/key-names only, no secret values); did NOT launch Jan Desktop app or any inference runtime; no credential bypass.

## Verdict: ENVIRONMENT-BLOCKED

**Reason (one line):** Jan CLI 0.8.4 works, but `jan models list` returns `[]` and both on-disk model dirs (`llamacpp/models/`, `mlx/models/`) are empty, so every inference path (`serve`/`launch`/`models load`) requires a GB-scale model download that is forbidden in this task — the EMO-stdio register/discover/delegate/result/failure/recovery/isolation/malformed-input matrix therefore could not be executed (no live inference round-trip).

---

## 1) `jan --version` + binary path + subcommands (verbatim, re-verified 2026-10-08)

### `which jan` + `jan --version`
```
which jan → /Users/emamabdullaziz/.local/bin/jan
jan 0.8.4
```
(exit 0 both)

### `jan --help` (verbatim, full)
```

       ██╗ █████╗ ███╗  ██╗
       ██║██╔══██╗████╗ ██║
       ██║███████║██╔██╗██║
  ██   ██║██╔══██║██║╚████║
  ╚█████╔╝██║  ██║██║ ╚███║
   ╚════╝ ╚═╝  ╚═╝╚═╝  ╚══╝

Jan runs local AI models (LlamaCPP / MLX) and exposes them via an
OpenAI-compatible API, then wires AI coding agent like Claude Code
directly to your own hardware — no cloud account, no usage fees, full privacy.

Models downloaded in the Jan desktop app are automatically available here.

Usage: jan <COMMAND>

Commands:
  serve    Load a local model and expose it at localhost:6767/v1 (auto-detects LlamaCPP or MLX)
  launch   Start a local model, then launch an AI agent with it pre-wired (env vars set automatically)
  threads  List and inspect conversation threads saved by the Jan app
  models   List and load models installed in the Jan data folder
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Examples:
  jan launch claude                                      # pick a model, then run Claude Code against it
  jan launch claude --model janhq/Jan-code-4b-gguf       # use a specific model
  jan launch openclaw --model janhq/Jan-code-4b-gguf     # wire openclaw to a local model
  jan serve janhq/Jan-code-4b-gguf                       # expose a model at localhost:6767/v1
  jan serve janhq/Jan-code-4b-gguf --fit                 # auto-fit context to available VRAM
  jan serve janhq/Jan-code-4b-gguf --detach              # run in the background
  jan models list                                        # show all installed models
```
(exit 0)

### `jan models --help` (verbatim)
```
List and load models installed in the Jan data folder

Usage: jan models <COMMAND>

Commands:
  list      Print all installed models as JSON (from the Jan data folder)
  load      Load a model and serve it — alias for the top-level `serve` command
  load-mlx  Load an MLX model directly (macOS / Apple Silicon only)
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```
(exit 0)

### `jan serve --help` (verbatim)
```
Load a local model and expose it at localhost:6767/v1 (auto-detects LlamaCPP or MLX)

Usage: jan serve [OPTIONS] [MODEL_ID]

Arguments:
  [MODEL_ID]  Model ID to load (omit to pick interactively from installed models)

Options:
      --model-path <MODEL_PATH>      Path to the GGUF file (auto-resolved from model.yml when omitted)
      --bin <BIN>                    Path to the inference binary (auto-discovered from Jan data folder when omitted)
      --port <PORT>                  Port the model server listens on (0 = pick a random free port) [default: 6767]
      --mmproj <MMPROJ>              mmproj path for vision-language models (auto-resolved from model.yml when omitted)
      --embedding                    Treat the model as an embedding model
      --timeout <TIMEOUT>            Seconds to wait for the model server to become ready [default: 120]
      --n-gpu-layers <N_GPU_LAYERS>  GPU layers to offload (-1 = all layers, 0 = CPU only) [default: -1]
      --ctx-size <CTX_SIZE>          Context window size in tokens (0 = model default) [default: 32768]
      --fit                          Auto-fit context to available VRAM, maximising the context window
      --threads <THREADS>            CPU threads for inference (0 = auto-detect) [default: 0]
      --api-key <API_KEY>            API key required by clients (sets LLAMA_API_KEY / MLX_API_KEY on the server) [default: ""]
  -d, --detach                       Run in the background (detach from terminal) and print the PID
      --log <LOG>                    Log file for background mode (default: <data-folder>/logs/serve.log)
  -v, --verbose                      Print full server logs (llama.cpp / mlx output) instead of the loading spinner
      --select                       When downloading a model, show quantization selection list
  -h, --help                         Print help
```
(exit 0)

### `jan launch --help` (verbatim)
```
Start a local model, then launch an AI agent with it pre-wired (env vars set automatically)

Usage: jan launch [OPTIONS] [PROGRAM] [PROGRAM_ARGS]...

Arguments:
  [PROGRAM]          Agent or program to run after the model is ready (e.g. claude, openclaw) Omit to pick interactively from: claude, openclaw
  [PROGRAM_ARGS]...  Arguments forwarded to the program

Options:
      --model <MODEL>                Model ID to load (omit to pick interactively)
      --bin <BIN>                    Path to the inference binary (auto-discovered from Jan data folder when omitted)
      --port <PORT>                  Port the model server listens on [default: 6767]
      --api-key <API_KEY>            API key for the model server (exported as OPENAI_API_KEY and ANTHROPIC_AUTH_TOKEN) [default: jan]
      --n-gpu-layers <N_GPU_LAYERS>  GPU layers to offload (-1 = all layers, 0 = CPU only) [default: -1]
      --ctx-size <CTX_SIZE>          Context window size in tokens (default: 4096; disables --fit when set explicitly)
      --fit <FIT>                    Auto-fit context to available VRAM (default: on when launching claude, unless --ctx-size is set) [possible values: true, false]
  -v, --verbose                      Print full server logs (llama.cpp / mlx output) instead of the loading spinner
      --select                       When downloading a model, show quantization selection list
  -h, --help                         Print help
```
(exit 0)

### `jan threads --help` (verbatim)
```
List and inspect conversation threads saved by the Jan app

Usage: jan threads <COMMAND>

Commands:
  list      Print all threads as JSON
  get       Print a single thread's metadata as JSON
  delete    Permanently delete a thread and all its messages
  messages  Print all messages in a thread as JSON

Options:
  -h, --help  Print help
```
(exit 0)

### `jan models load --help` (verbatim — alias of `serve`)
```
Load a model and serve it — alias for the top-level `serve` command

Usage: jan models load [OPTIONS] [MODEL_ID]

Arguments:
  [MODEL_ID]  Model ID to load (omit to pick interactively from installed models)

Options:
      --model-path <MODEL_PATH>      Path to the GGUF file (auto-resolved from model.yml when omitted)
      --bin <BIN>                    Path to the inference binary (auto-discovered from Jan data folder when omitted)
      --port <PORT>                  Port the model server listens on (0 = pick a random free port) [default: 6767]
      --mmproj <MMPROJ>              mmproj path for vision-language models (auto-resolved from model.yml when omitted)
      --embedding                    Treat the model as an embedding model
      --timeout <TIMEOUT>            Seconds to wait for the model server to become ready [default: 120]
      --n-gpu-layers <N_GPU_LAYERS>  GPU layers to offload (-1 = all layers, 0 = CPU only) [default: -1]
      --ctx-size <CTX_SIZE>          Context window size in tokens (0 = model default) [default: 32768]
      --fit                          Auto-fit context to available VRAM, maximising the context window
      --threads <THREADS>            CPU threads for inference (0 = auto-detect) [default: 0]
      --api-key <API_KEY>            API key required by clients (sets LLAMA_API_KEY / MLX_API_KEY on the server) [default: ""]
  -d, --detach                       Run in the background (detach from terminal) and print the PID
      --log <LOG>                    Log file for background mode (default: <data-folder>/logs/serve.log)
  -v, --verbose                      Print full server logs (llama.cpp / mlx output) instead of the loading spinner
      --select                       When downloading a model, show quantization selection list
  -h, --help                         Print help
```
(exit 0)

### MCP / agent subcommand search (verbatim negative results, re-verified 2026-10-08)
- `jan mcp --help` → verbatim: `error: unrecognized subcommand 'mcp'` + usage hint (exit 2).
- `jan agent --help` → verbatim: `error: unrecognized subcommand 'agent'` + usage hint (exit 2).
- **Finding: NO `jan mcp`, `jan agent`, or standalone `jan model` command in CLI 0.8.4.** Only model-adjacent surface is `jan models {list,load,load-mlx}` + inference gates `jan serve` / `jan launch` / `jan models load`, all requiring an installed model.

---

## 2) Existing models / config — re-verified 2026-10-08 (read-only, names/sizes/key-names only)

- `jan models list` → verbatim output `[]` (exit 0). **Re-verified today: still empty (unchanged from 2026-10-07).**
- `jan threads list` → verbatim output `[]` (exit 0). No saved threads.
- `~/.jan`: **absent** (`No such file or directory` — unchanged).
- `~/Library/Application Support/Jan/data/llamacpp/models/`: **EMPTY** (`total 0`, only `.`/`..`, dated Sep 24).
- `~/Library/Application Support/Jan/data/mlx/models/`: **EMPTY** (`total 0`, only `.`/`..`, dated Sep 24).
- `~/Library/Application Support/Jan/data/` listing (names only): `assistants/`, `db/`, `llamacpp/`, `logs/`, `mcp_config.json` (1375 bytes), `mlx/`, `settings.json` (31454 bytes), `store.json` (44 bytes), `threads/` — no model weights present.
- `~/Library/Application Support/Jan/settings.json`: top-level keys = `["data_folder"]` (value not read).
- `~/Library/Application Support/Jan` total footprint ≈ **18 MB** (runtimes/config/logs, zero model weights).
- `mcp_config.json` structure (key/server **names only**, no commands/args/env/values):
  - top-level keys: `['mcpServers', 'mcpSettings']`
  - server names (6): `Jan Browser MCP`, `browsermcp`, `fetch`, `filesystem`, `sequential-thinking`, `serper`
  - `mcpSettings` keys: `['backoffMultiplier', 'baseRestartDelayMs', 'enableSmartToolRouting', 'maxRestartDelayMs', 'routerModelId', 'routerModelProvider', 'toolCallTimeoutSeconds', 'useLightweightRouterModel']` (values not read)
- `Jan/data/settings.json` top-level keys (names only, values not read): `__settings_migrated_to_backend__`, `agent-mode`, `favorite-models`, `jan-model-prompt-dismissed`, `latest-jan-model`, `llama_cpp_backend_type`, `llamacpp-embedder-bootstrapped`, `llamacpp_fit_off_v1`, `llamacpp_model_yaml_backfill_v1`, `llamacpp_models_max_migrated_v1`, `model-provider`, `paused-downloads`, `productAnalytic`, `productAnalyticPrompt`, `setting-appearance`, `setting-hardware`, `setting-web-search`, `theme`.
- `/Applications/Jan.app` → **PRESENT**; bundle identity (from `Contents/Info.plist`, no launch): `CFBundleName=Jan`, `CFBundleShortVersionString=0.8.4`, `CFBundleVersion=0.8.4`, `CFBundleIdentifier=jan.ai.app` — matches CLI 0.8.4. App was **not launched**.

---

## 3) MCP path check — does Jan CLI 0.8.4 expose any MCP consumer?

**Answer: NO (CLI has no MCP consumer path).**

| Candidate | Result (2026-10-08) |
|---|---|
| `jan mcp ...` | does not exist (`unrecognized subcommand 'mcp'`, exit 2) |
| `jan agent ...` | does not exist (`unrecognized subcommand 'agent'`, exit 2) |
| `jan serve` without model | requires `[MODEL_ID]` or interactive picker over installed models; installed set is empty → would trigger download (forbidden) |
| `jan launch` without model | same: requires `--model` / interactive picker; only forwards to `claude`/`openclaw` after a model is serving |
| `jan models load` / `load-mlx` | aliases/wrappers of `serve`; same model requirement |
| `jan models list` / `jan threads list` | work model-free (both returned `[]`) but expose no MCP/agent delegation |

Desktop-side `mcp_config.json` proves Jan Desktop *has* an MCP surface (6 configured servers by name), but that surface is owned by the Electron app — no CLI flag in 0.8.4 drives it headlessly, and reading/executing the servers' commands would mean handling credentials and spawning third-party processes (explicitly excluded: "no credential bypass"). Config-existing alone is NEVER env PASS per task policy.

---

## 4) EMO contract-path matrix — NOT-EXECUTED (blocked, no fabrication)

Per policy, each row is PASS only with a live inference round-trip; otherwise NOT-EXECUTED with reason. No live inference was possible (zero installed models; serve/launch both gated on download).

| Step | Verdict | Evidence / reason |
|---|---|---|
| register (EMO stdio) | NOT-EXECUTED | no `jan mcp add/register` path in CLI 0.8.4; hand-editing Desktop `mcp_config.json` would bypass the app and risk credentials — refused |
| discover | NOT-EXECUTED | no model-free discovery endpoint in CLI |
| filter | NOT-EXECUTED | no tool surface reachable without serving model |
| delegate | NOT-EXECUTED | requires serving model; `jan models list` = `[]` |
| result | NOT-EXECUTED | no delegation ran, nothing to collect |
| failure | NOT-EXECUTED | no delegation ran, no error trace to record |
| recovery | NOT-EXECUTED | no failure induced, no recovery to measure |
| isolation | NOT-EXECUTED | `jan threads list` = `[]`; no threads to compare |
| malformed-input | NOT-EXECUTED | no serving endpoint to send malformed input to |

No PASS evidence exists. No PASS claimed.

---

## 5) ENVIRONMENT-BLOCKED + Reproduction Kit

### Block statement
`jan models list` → `[]`; `llamacpp/models/` and `mlx/models/` both empty; `jan serve`/`jan launch`/`jan models load` all resolve `MODEL_ID` from the installed set (or download on demand). Downloading even the smallest suggested model (`janhq/Jan-code-4b-gguf`, multi-GB GGUF) is explicitly forbidden for this task ("Do NOT download GB-scale models"). Hence end-to-end Jan-native inference + EMO delegation cannot be exercised in this environment.

### Reproduction instructions (exact retry steps after unblock)
Run these **only** in an environment where a model download is authorized (smallest viable first; allow several GB disk + minutes on first pull):

```bash
# 0. Sanity: CLI present and at expected version
jan --version            # expect: jan 0.8.4 (or newer; re-record --help if changed)
jan --help               # re-check for new mcp/agent/model subcommands

# 1. Install the smallest viable model (AUTHORIZED downloads only)
jan models list          # expect [] before pull
jan serve janhq/Jan-code-4b-gguf --select
# --select lets you pick the smallest quantization; note exact bytes + quantization chosen

# 2. Confirm inventory non-empty
jan models list          # expect JSON with >= 1 entry; save verbatim

# 3. Serve on a random port (avoids clashing with :6767)
jan serve janhq/Jan-code-4b-gguf --port 0 --detach
# record PID + actual port from output/logs; then:
curl -s http://localhost:<PORT>/v1/models | head -c 2000; echo
# expect OpenAI-compatible model list JSON

# 4. Register EMO as an MCP stdio server (PREFERRED: via Jan Desktop UI or documented CLI if a newer jan adds `jan mcp add`)
#    - Manual-edit fallback (only with owner consent, never with secrets in shell history):
#      cp ~/Library/Application\ Support/Jan/data/mcp_config.json /tmp/mcp_config.backup.json
#      add server entry: name e.g. "emo", command = EMO stdio entrypoint, args per EMO MCP README
#    - Record: exact entry added (redact secrets), method used (UI vs CLI vs file)

# 5. Discover + filter
#    - Via Desktop UI: open MCP/tools panel, screenshot/list tools surfaced for "emo"
#    - Via API (if model serving): POST /v1/chat/completions with tools passthrough; record tool list JSON
#    - Apply an allowlist filter (e.g. only EMO read-only tools first); record filter rule verbatim

# 6. Delegate + result (happy path)
#    - Prompt model with a minimal EMO task (e.g. version/echo probe scoped to fixture data)
#    - Save: full request JSON, full response JSON, tool-call trace, exit code, wall time

# 7. Failure + recovery
#    - Kill EMO stdio mid-call (kill <pid>) → record error surfaced by Jan (verbatim)
#    - Restart server (Desktop toggle or re-serve) → re-run probe → record recovery time + result

# 8. Session isolation
#    - Run two threads (jan threads list/get/messages to verify IDs), one with EMO tool use, one without
#    - Confirm via `jan threads messages <id>` that tool traces do not leak across threads

# 9. Malformed input
#    - Send malformed tool args / malformed MCP envelope; record verbatim rejection (no crash expected)

# 10. Cleanup
#    - Stop background server: kill <PID from --detach>; confirm port freed
#    - Restore mcp_config.json from /tmp backup if hand-edited; `diff` to prove restore
```

**Desktop-UI proof alternative** (if CLI never gains MCP commands): enable/configure the EMO server in Jan Desktop → Models → pull small model → chat with MCP tools enabled → export thread (`jan threads messages <id>`) as evidence. Attach screenshots + exported JSON.

**Expected artifact on retry:** update this report (or a `POST-T021-followup` file) with verbatim outputs for steps 2–9; only then can the verdict flip to PASS.

---

## Evidence log (commands run, all read-only except report write)

| # | Command | Result |
|---|---|---|
| 1 | `which jan; jan --version` | `/Users/emamabdullaziz/.local/bin/jan`, `jan 0.8.4`, exit 0 |
| 2 | `jan --help` | 4 subcommands: serve/launch/threads/models (+help); recorded verbatim §1 |
| 3 | `jan models --help; jan models list` | help exit 0; list → `[]`, exit 0 (re-verified 2026-10-08) |
| 4 | `jan serve --help; jan launch --help; jan threads --help; jan models load --help` | all exit 0; recorded verbatim §1 |
| 5 | `jan mcp --help` / `jan agent --help` | `error: unrecognized subcommand ...`, exit 2 each |
| 6 | `jan threads list` | `[]`, exit 0 |
| 7 | `ls` of `llamacpp/models`, `mlx/models` (both empty), `data/`, `~/.jan` (absent), `du` (18M) | listings in §2 |
| 8 | key-names-only parse of `mcp_config.json` / `settings.json` / `Jan/settings.json` | names in §2; no values read |
| 9 | `Info.plist` read for `/Applications/Jan.app` | 0.8.4, present, not launched |
| 10 | wrote this file | only file written: `reports/development/POST-T021-jan-native.md` |

## Constraints compliance
- Files written: exactly 1 (`reports/development/POST-T021-jan-native.md`). No `src/`/`tests/`/`docs/` modifications.
- No model downloaded; no `jan serve`/`jan launch` invocation (both would resolve/download a model).
- No secret values read or reproduced (only file names, sizes, key names, server names).
- No credentials bypassed; no config edited; Jan.app not launched.
