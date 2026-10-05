# 01 — Requirements

## Functional requirements

### FR-01 Portable installation

The project MUST be installable as a Python package. The canonical end-user executable is `cyber-agent`.

### FR-02 Multiple interfaces

The same core operations MUST be callable through:

- MCP over stdio first; HTTP transport may be added as an adapter.
- CLI.
- Python API.

### FR-03 Security audit operation

The system MUST expose a high-level `cyber_audit` operation that accepts a target, scope, mode, permission profile, and optional focus.

### FR-04 Specialist ownership

The host agent MUST NOT need to orchestrate low-level scanner steps. The cybersecurity sub-agent owns the security workflow.

### FR-05 Evidence

Every finding MUST support source references, tool evidence, reasoning summary, verification status, confidence, and remediation guidance.

### FR-06 Verification

The system MUST distinguish `suspected`, `supported`, and `confirmed` findings. Verification MUST be gated by policy.

### FR-07 Read-only default

All integrations MUST default to read-only operations. Any write-capable connector MUST declare explicit capability and policy requirements.

### FR-08 Untrusted content handling

Repository text, issue text, PR descriptions, database content, generated code and scanner output MUST be treated as untrusted input.

### FR-09 Stable schemas

MCP and CLI outputs MUST validate against versioned JSON Schemas in `docs/schemas/`.

### FR-10 Tool registry

Tools MUST declare capability, risk level, read/write behavior, required permissions, input schema, output schema, and provenance.

### FR-11 Provider abstraction

A model provider MUST be replaceable without modifying the audit domain logic.

### FR-12 Audit lifecycle

An audit MUST support states: `created`, `planning`, `collecting`, `analyzing`, `verifying`, `reporting`, `completed`, `failed`, `cancelled`.

## Non-functional requirements

### NFR-01 Reproducibility

The audit should preserve tool versions, policy version, provider identifier, model identifier, timestamps, and content hashes where feasible.

### NFR-02 Least privilege

Integrations MUST request only the permissions required for the current task.

### NFR-03 Isolation

Tool execution SHOULD occur in an isolated workspace when feasible.

### NFR-04 Observability

The system MUST emit structured audit events suitable for debugging and post-incident review.

### NFR-05 Fail-safe behavior

Ambiguous tool failures MUST NOT be silently interpreted as secure states.

### NFR-06 Extensibility

Adding a new scanner or repository provider MUST NOT require changes to MCP/CLI contracts.
