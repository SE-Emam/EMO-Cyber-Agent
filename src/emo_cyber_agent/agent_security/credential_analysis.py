"""Credential flow analysis — POST-RC-010.

Reuses existing secret handling: raw material never becomes
evidence. Flows carry digest/locator references only; every
emitted summary is redacted and every flow must stay inside its
credential boundary.
"""

from __future__ import annotations

from typing import Any


def analyze_credential_flows(
    flows: tuple[Any, ...],
    *,
    boundaries: tuple[Any, ...] = (),
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    boundary_consumers: dict[str, set[str]] = {}
    for boundary in boundaries:
        for consumer in getattr(boundary, "consumers", ()):
            boundary_consumers.setdefault(consumer, set()).add(getattr(boundary, "boundary_id", ""))
    for flow in sorted(flows, key=lambda f: getattr(f, "flow_id", "")):
        flow_id = getattr(flow, "flow_id", "unknown-flow")
        if not getattr(flow, "redacted", True):
            signals.append({"signal": "CREDENTIAL_EXPOSURE", "flow_id": flow_id, "detail": "credential flow not marked redacted; exposure hypothesis pending verification"})
        consumer = getattr(flow, "consumer_id", "")
        declared = set(boundary_consumers.get(consumer, ()))
        stated = getattr(flow, "boundary_id", "")
        if stated and stated not in declared and declared:
            signals.append({"signal": "CROSS_BOUNDARY_DATA_FLOW", "flow_id": flow_id, "detail": f"flow boundary {stated} outside declared consumer boundaries"})
        if "log" in consumer.lower():
            signals.append({"signal": "CREDENTIAL_IN_LOG_PATH", "flow_id": flow_id, "detail": "credential reaches a log-like consumer; verify redaction downstream"})
        if "model" in consumer.lower() or "context" in consumer.lower():
            signals.append({"signal": "CREDENTIAL_IN_CONTEXT", "flow_id": flow_id, "detail": "credential reaches model context; verify scoping downstream"})
    return signals


def redact_summary(text: str) -> str:
    from emo_cyber_agent.core.repository import redact_credentials

    return redact_credentials(text)
