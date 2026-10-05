# 19 — Release Checklist

## Code

- [ ] Tests pass.
- [ ] Type checking passes.
- [ ] Lint/format checks pass.
- [ ] Public API documented.

## Security

- [ ] No credentials in repository.
- [ ] Secret-redaction tests pass.
- [ ] Prompt-injection tests pass.
- [ ] Tool authorization tests pass.
- [ ] Read-only default verified.
- [ ] Dependency vulnerabilities reviewed.

## Interfaces

- [ ] MCP schema validation passes.
- [ ] CLI JSON output schema validation passes.
- [ ] Python API smoke test passes.

## Documentation

- [ ] Installation instructions current.
- [ ] Host integration instructions current.
- [ ] Scope/permission semantics documented.
- [ ] Limitations documented.

## Distribution

- [ ] Version bumped.
- [ ] Changelog updated.
- [ ] Wheel/sdist built.
- [ ] Clean installation tested.
- [ ] License selected and included.
