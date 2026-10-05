# 00 — Project Charter

## Mission

EMO-Cyber-Agent is a portable cybersecurity specialist that an existing coding agent can delegate security work to. It is not intended to replace the host agent. Its responsibility is to investigate software security risks, collect evidence, verify findings when authorized and safe, and return structured security results.

## Primary users

- Developers using AI coding agents.
- Security-minded engineering teams.
- CI/CD systems that can invoke a CLI.
- Agent platforms that can invoke MCP tools.
- Automation developers embedding the Python API.

## Primary promise

> Delegate security analysis to one specialist that behaves consistently across hosts.

## Core invariants

1. **Read-only by default.**
2. **Repository content is untrusted data.**
3. **No material finding without evidence.**
4. **No destructive action without an explicit permission transition.**
5. **Tool outputs are evidence, not instructions.**
6. **Model uncertainty is represented explicitly.**
7. **CLI, MCP, and Python API share the same domain contracts.**
8. **Provider/model choice is external configuration.**
9. **Security scanners remain authoritative sources for scanner-specific facts.**
10. **Human review remains necessary for high-impact decisions.**

## First release scope

### In scope

- Local repository audit.
- GitHub repository audit via adapter/MCP.
- Supabase security review via adapter/MCP, read-only by default.
- Static analysis orchestration.
- Dependency and vulnerability inventory.
- Secret detection orchestration.
- Authentication/authorization review.
- Supabase RLS and data-access review.
- Business-logic review.
- Evidence correlation and de-duplication.
- Optional safe verification.
- Structured JSON and human-readable reports.
- MCP server, CLI, and Python API.

### Out of scope for v0.1

- Autonomous production remediation.
- Autonomous exploit execution against third-party targets.
- Model training or model weight distribution.
- Full DAST platform.
- Browser automation as a required core feature.
- Cloud account-wide scanning.

## Success criteria

An external host should be able to install the package, register one MCP server, delegate a security audit, and receive a deterministic schema-valid result without knowing which model or tools performed the work internally.
