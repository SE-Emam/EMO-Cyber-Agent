# 18 — Architecture Decision Records

## ADR-001 — One package, three interfaces

**Decision:** MCP, CLI and Python API are adapters over one core.

**Reason:** prevents duplicated behavior and makes the worker portable.

## ADR-002 — Model-agnostic core

**Decision:** no model weights or provider-specific runtime in the core repository.

**Reason:** allows model upgrades and remote/local provider selection without architectural rewrites.

## ADR-003 — High-level MCP surface

**Decision:** expose security capabilities such as `cyber_audit`, not every low-level scanner command.

**Reason:** EMO should own specialist workflow and policy.

## ADR-004 — Read-only default

**Decision:** destructive and write-capable actions are disabled by default.

**Reason:** a security worker is commonly invoked inside powerful coding agents; least privilege is mandatory.

## ADR-005 — Evidence-first findings

**Decision:** findings must reference normalized evidence.

**Reason:** reduces unsupported model claims and enables auditing of the auditor.

## ADR-006 — Deterministic tools around probabilistic reasoning

**Decision:** integrate scanners as evidence providers rather than asking the model to replace them.

**Reason:** complementary strengths and better provenance.

## ADR-007 — Provider abstraction

**Decision:** model provider is a port with structured tool-call support.

**Reason:** model choice is expected to evolve.
