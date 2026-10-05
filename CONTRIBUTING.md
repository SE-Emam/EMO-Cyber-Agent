# Contributing

## Principles

- Prefer small, typed changes.
- Preserve public schemas.
- Add tests for policy-sensitive behavior.
- Never add real secrets or production targets.
- Keep model-provider and host-specific code behind adapters.
- Document any capability that can write or mutate external state.

## Change categories

Changes to any of the following require explicit review:

- MCP tools;
- permission profiles;
- tool capabilities;
- report schemas;
- credential handling;
- external network access;
- verification behavior.
