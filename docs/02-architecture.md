# 02 — Architecture

## Architectural style

EMO-Cyber-Agent follows a ports-and-adapters design with an internal security-agent orchestration layer.

```text
             External host / human / automation
                         │
                 ┌───────┼────────┐
                 ▼       ▼        ▼
                MCP      CLI   Python API
                 │       │        │
                 └───────┼────────┘
                         ▼
                 Application Facade
                         │
                  Agent Orchestrator
                         │
       ┌─────────────────┼──────────────────┐
       ▼                 ▼                  ▼
  Policy Engine     Evidence Store     Provider Port
       │                 │                  │
       └────────────┬────┴────────────┬─────┘
                    ▼                 ▼
             Tool Registry       Model Runtime
                    │             (external)
          ┌─────────┼─────────┬─────────┐
          ▼         ▼         ▼         ▼
       GitHub    Supabase   SAST      SCA/Secrets
```

## Core modules

### Application facade

Maps external requests to domain commands and domain results.

### Agent orchestrator

Owns the security investigation loop. It chooses the next permitted action based on scope, evidence collected, policy and task state.

### Policy engine

Determines which tools/actions are allowed in the current mode and permission profile.

### Tool registry

Provides typed discovery and invocation. It is not a shell passthrough.

### Evidence store

Stores normalized evidence objects, provenance, content hashes and relationships to findings.

### Provider port

Defines the contract for model calls and structured tool-calling without binding the core to any model vendor.

## Boundary rules

- MCP adapter MUST NOT contain security logic.
- CLI adapter MUST NOT duplicate audit logic.
- Tool adapters MUST normalize provider-specific output to domain evidence.
- Model provider MUST NOT receive credentials it does not need.
- Repository content MUST be separated from system/developer policy.
- Findings MUST be produced from the domain evidence model.

## Data flow

```text
AuditRequest
   ↓
Scope validation
   ↓
Policy evaluation
   ↓
Inventory / reconnaissance
   ↓
Tool execution
   ↓
Evidence normalization
   ↓
LLM-assisted security reasoning
   ↓
Cross-source correlation
   ↓
Verification (if allowed)
   ↓
Finding validation
   ↓
Report generation
   ↓
AuditResult
```

## Reliability principle

If the model is unavailable, deterministic scanners should still be callable through the CLI/API where useful. If a scanner fails, the report must state that the control was not evaluated rather than implying absence of risk.
