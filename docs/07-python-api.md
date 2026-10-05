# 07 — Python API Contract

The Python API is the third stable interface over the same core service layer.

Conceptual usage:

```python
from emo_cyber_agent import SecurityAuditor

service = SecurityAuditor(config=...)
result = await service.audit(
    target=".",
    mode="standard",
    permission_profile="read_only",
)
```

## API principles

- Return domain objects, not MCP-specific or CLI-specific structures.
- Support async execution internally because tool adapters may be network-bound.
- Permit dependency injection for repositories, tools, evidence stores, policies, and model providers.
- Do not expose raw secret-bearing environment state.

## Required service methods

- `audit(request) -> AuditResult`
- `review(request) -> ReviewResult`
- `verify(request) -> VerificationResult`
- `doctor(request) -> DoctorResult`
