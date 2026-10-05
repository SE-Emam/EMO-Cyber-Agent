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
