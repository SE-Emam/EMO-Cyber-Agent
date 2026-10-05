"""MCP high-level tool surface — ECA-T013.

Six specialist tools: five Core audit tools plus a read-only extension
catalog view. No internal registry, scanner, repository, or database
tool is exposed. Descriptions state the actual read-only contract —
never write/delete/execute capabilities.
"""

from __future__ import annotations

from typing import Any

MAX_STRING = 2000
MAX_ITEMS = 200


def _str(min_len: int = 0, max_len: int = MAX_STRING, enum: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "minLength": min_len, "maxLength": max_len}
    if enum is not None:
        schema["enum"] = enum
    return schema


TOOLS: list[dict[str, Any]] = [
    {
        "name": "cyber_audit",
        "description": "Perform a scoped, read-only security audit of an authorized software project and return an auditable audit result. Read-only; never modifies code, data, or infrastructure.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": _str(1, 512),
                "mode": _str(0, 20, ["quick", "standard", "deep"]),
                "focus": {"type": "array", "items": _str(0, 80), "maxItems": 10},
                "audit_id": _str(0, 120),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cyber_review",
        "description": "Run a focused, read-only security review of a specific asset or context and return findings with evidence references. Read-only.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": _str(1, 512),
                "focus": {"type": "array", "items": _str(0, 80), "maxItems": 10},
                "audit_id": _str(0, 120),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cyber_verify",
        "description": "Request verification of a specific finding candidate using only policy-approved, read-only methods. Returns a verification plan; input is never authorization.",
        "inputSchema": {
            "type": "object",
            "required": ["audit_id", "candidate", "method", "target", "rationale"],
            "properties": {
                "audit_id": _str(1, 120),
                "candidate": {"type": "object", "maxProperties": 40},
                "method": _str(1, 60, ["static_confirmation", "configuration_confirmation", "dataflow_confirmation", "dependency_confirmation", "policy_confirmation", "read_only_query"]),
                "target": {
                    "type": "object",
                    "required": ["kind", "locator"],
                    "properties": {"kind": _str(1, 40, ["repository", "file", "endpoint", "database_object", "dependency", "configuration"]), "locator": _str(1, 512)},
                    "additionalProperties": False,
                },
                "rationale": _str(1, 1000),
                "statement": _str(0, MAX_STRING),
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cyber_report",
        "description": "Project Core findings into a JSON, JSONL, or Markdown report with provenance intact. Projection only; never reinterprets security results.",
        "inputSchema": {
            "type": "object",
            "required": ["audit_id", "findings", "format"],
            "properties": {
                "audit_id": _str(1, 120),
                "findings": {"type": "array", "maxItems": MAX_ITEMS},
                "format": _str(1, 20, ["json", "jsonl", "markdown"]),
                "include_non_reportable": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cyber_status",
        "description": "Return read-only runtime status: version, capabilities, and policy posture. Exposes no credentials, no other audits, no internals.",
        "inputSchema": {
            "type": "object",
            "properties": {"audit_id": _str(0, 120)},
            "additionalProperties": False,
        },
    },
    {
        "name": "cyber_extensions",
        "description": "Inspect the extension catalog as data: list, describe, resolve, or check extension metadata. Read-only metadata view; never installs, loads, trusts, or runs extension code.",
        "inputSchema": {
            "type": "object",
            "required": ["action"],
            "properties": {
                "action": _str(1, 20, ["list", "describe", "resolve", "check"]),
                "extension_id": _str(0, 80),
                "provide": _str(0, 120),
            },
            "additionalProperties": False,
        },
    },
]

TOOL_NAMES = tuple(t["name"] for t in TOOLS)

# Key TOKENS that must never appear in tool inputs: permission/capability/
# policy escalation, commands, credentials, or model configuration.
# Matched per token (split on _/non-word) so legitimate keys like
# "description" never false-positive.
FORBIDDEN_TOKENS = frozenset({
    "permission", "permissions", "capability", "capabilities", "policy",
    "command", "shell", "script", "token", "tokens", "credential",
    "credentials", "secret", "secrets", "api", "apikey", "model", "role",
    "roles", "sudo", "admin", "password", "private", "exec", "system",
    "eval", "cmd",
})


class InvalidInput(Exception):
    pass


def validate_arguments(tool_name: str, arguments: Any) -> dict[str, Any]:
    """Interface-shape validation only (types/required/sizes/forbidden keys).
    All security decisions stay in Core."""
    spec = next((t for t in TOOLS if t["name"] == tool_name), None)
    if spec is None:
        raise InvalidInput(f"unknown tool: {tool_name}")
    if not isinstance(arguments, dict):
        raise InvalidInput("arguments must be an object")
    schema = spec["inputSchema"]
    _check_object(arguments, schema, path="$")
    _check_forbidden(arguments)
    return arguments


def _check_forbidden(value: Any, depth: int = 0) -> None:
    import re as _re

    if depth > 6:
        raise InvalidInput("arguments nested too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            tokens = set(_re.split(r"[\W_]+", str(key).lower())) - {""}
            if tokens & FORBIDDEN_TOKENS:
                raise InvalidInput(f"forbidden input key: {key}")
            if isinstance(item, str) and len(item) > 8000:
                raise InvalidInput(f"input value too large: {key}")
            _check_forbidden(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise InvalidInput("input array too large")
        for item in value:
            _check_forbidden(item, depth + 1)


def _check_object(value: Any, schema: dict[str, Any], *, path: str) -> None:
    if not isinstance(value, dict):
        raise InvalidInput(f"{path} must be an object")
    for req in schema.get("required", []):
        if req not in value:
            raise InvalidInput(f"{path} missing required field: {req}")
    props = schema.get("properties", {})
    for key, item in value.items():
        subschema = props.get(key)
        if subschema is None:
            if schema.get("additionalProperties") is False:
                raise InvalidInput(f"{path} has unknown field: {key}")
            continue
        _check_value(item, subschema, path=f"{path}.{key}")


def _check_value(value: Any, schema: dict[str, Any], *, path: str) -> None:
    kind = schema.get("type")
    if kind == "string":
        if not isinstance(value, str):
            raise InvalidInput(f"{path} must be a string")
        if len(value) < schema.get("minLength", 0):
            raise InvalidInput(f"{path} too short")
        if len(value) > schema.get("maxLength", MAX_STRING):
            raise InvalidInput(f"{path} too long")
        if "enum" in schema and value and value not in schema["enum"]:
            raise InvalidInput(f"{path} has unsupported value")
    elif kind == "array":
        if not isinstance(value, list):
            raise InvalidInput(f"{path} must be an array")
        if len(value) > schema.get("maxItems", MAX_ITEMS):
            raise InvalidInput(f"{path} array too large")
        for i, item in enumerate(value):
            _check_value(item, schema.get("items", {}), path=f"{path}[{i}]")
    elif kind == "boolean":
        if not isinstance(value, bool):
            raise InvalidInput(f"{path} must be a boolean")
    elif kind == "object":
        _check_object(value, schema, path=path)
