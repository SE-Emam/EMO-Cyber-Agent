"""MCP wire layer — ECA-T013.

Minimal JSON-RPC 2.0 stdio subset implementing the MCP lifecycle every
host needs: initialize → notifications/initialized → tools/list →
tools/call (+ ping). One JSON object per line; logs go to stderr only.

No security logic here: this module frames bytes. All decisions happen in
delegate.py → Core. Unknown methods get METHOD_NOT_FOUND (protocol-correct);
protocol-specific code stays inside this adapter package, never in Core.
"""

from __future__ import annotations

import json
from typing import Any

SERVER_NAME = "emo-cyber-agent"
SERVER_VERSION = "0.2.0"

SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]

MAX_MESSAGE_BYTES = 1024 * 1024  # 1 MiB per line; larger → dropped, logged


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602

# Domain failures ride INSIDE tools/call results (isError:true) with these
# stable string codes, mapped from Core errors in delegate.py.
DOMAIN_PERMISSION_DENIED = "PERMISSION_DENIED"
DOMAIN_SECURITY_BLOCKED = "SECURITY_BLOCKED"
DOMAIN_NOT_FOUND = "NOT_FOUND"
DOMAIN_INVALID = "INVALID_REQUEST"
DOMAIN_TIMEOUT = "TIMEOUT"
DOMAIN_UNAVAILABLE = "SERVICE_UNAVAILABLE"


def negotiate_version(requested: Any) -> str:
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return LATEST_PROTOCOL_VERSION


def error_envelope(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message[:300]}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def result_envelope(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def parse_line(line: str) -> Any:
    if len(line.encode("utf-8", errors="replace")) > MAX_MESSAGE_BYTES:
        raise JsonRpcError(PARSE_ERROR, "message too large")
    try:
        return json.loads(line)
    except ValueError as e:
        raise JsonRpcError(PARSE_ERROR, f"invalid JSON: {e}") from e


def initialize_result(requested_version: Any) -> dict[str, Any]:
    return {
        "protocolVersion": negotiate_version(requested_version),
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }
