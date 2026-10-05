# 20 — Implementation Backlog

## Epic A — Core

- [ ] typed domain entities
- [ ] audit state machine
- [ ] service facade
- [ ] structured event stream

## Epic B — Security reasoning

- [ ] attack-surface inventory
- [ ] auth/authz analyzer
- [ ] dataflow analyzer
- [ ] business-logic analyzer
- [ ] Supabase/RLS correlator
- [ ] finding deduplication
- [ ] confidence/completeness calculator

## Epic C — Tools

- [ ] local git/filesystem adapter
- [ ] GitHub adapter
- [ ] Supabase adapter
- [ ] Semgrep adapter
- [ ] Trivy adapter
- [ ] OSV adapter
- [ ] Gitleaks adapter
- [ ] CodeQL optional adapter

## Epic D — Interfaces

- [ ] MCP stdio
- [ ] CLI
- [ ] JSON/JSONL output
- [ ] Python API
- [ ] optional HTTP transport

## Epic E — Safety

- [ ] policy engine
- [ ] capability checks
- [ ] redaction
- [ ] sandbox integration
- [ ] prompt-injection regression suite
- [ ] authorization scopes

## Epic F — Evaluation

- [ ] fixture corpus
- [ ] known finding labels
- [ ] MCP/CLI equivalence tests
- [ ] tool-failure tests
- [ ] high-severity review gate

## Epic G — Packaging

- [ ] package metadata
- [ ] wheel build
- [ ] pipx documentation
- [ ] changelog
- [ ] license
- [ ] signed/reproducible release strategy
