# 17 — Host Integration Guide

## Principle

Hosts integrate with EMO-Cyber-Agent through the public MCP surface or CLI. They should not import internal modules.

## MCP registration pattern

A host should register the installed executable as an MCP server using its native configuration format.

Conceptually:

```json
{
  "mcpServers": {
    "emo-cyber-agent": {
      "command": "cyber-agent",
      "args": ["mcp"]
    }
  }
}
```

The exact configuration file/location is host-specific and should live in host-specific documentation, not the core package.

## CLI delegation pattern

For hosts without suitable MCP support:

```bash
cyber-agent audit . --mode standard --format json
```

The host agent reads the result and continues its workflow.

## Environment

Configuration should be supplied via environment variables, user config, or secret managers. Never hard-code credentials in host configuration examples.

## GitHub

Prefer repository-scoped, least-privileged credentials and read-only access for audit mode.

## Supabase

Prefer project-scoped credentials and read-only inspection. Avoid connecting the security worker to production write paths by default.

## Future compatibility

A future host integration SHOULD be possible without modifying `core`, `domain`, or `security` modules.
