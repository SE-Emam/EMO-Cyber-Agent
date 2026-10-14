# 06 — CLI Interface Contract

## Entry point

`cyber-agent`

## Commands

```text
cyber-agent audit <target>
cyber-agent review <target-or-context>
cyber-agent verify <finding-id>
cyber-agent supabase-audit
cyber-agent dependency-audit <target>
cyber-agent secret-audit <target>
cyber-agent doctor
cyber-agent mcp
cyber-agent config show
```

## Common flags

```text
--mode quick|standard|deep
--permission read_only|verify|remediate
--format text|json|jsonl
--output <path>
--policy <path>
--include <pattern>
--exclude <pattern>
--focus <domain>
--no-model
--fail-on critical|high|medium|low
```

`--no-model` is useful for deterministic scanner-only workflows and should not silently imply a complete security audit.

The foundation `audit` command returns a JSON result with
`result.status = "partial"`, zero evaluated controls, and scanner-run/evidence
metadata from Gitleaks when the local binary is available. Secret values are
redacted before observations are returned. Semgrep is not invoked until its
offline configuration is verified, and scanner evidence is not classified
into EMO findings. This is not a completed security assessment. The top-level
CLI status `ok` indicates that the command serialized a response; it does not
mean the nested audit result is complete.

## Examples

```bash
cyber-agent audit . --mode standard
cyber-agent audit . --mode deep --format json --output audit.json
cyber-agent secret-audit . --format json
cyber-agent doctor
cyber-agent mcp
```

## Exit codes

- `0`: command completed; no failure condition requested.
- `1`: findings matched `--fail-on` threshold.
- `2`: invalid input/configuration.
- `3`: tool/runtime failure.
- `4`: authorization/policy denied.
- `5`: partial completion with unevaluated controls when configured as strict CI mode.
