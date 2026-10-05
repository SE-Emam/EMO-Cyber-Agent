"""Pack executor — POST-RC-007.

Declarative definition ONLY. No new execution mechanism: every run
goes through the existing ToolExecutor (Registry → StrictPolicy →
argv → port → invocation). The pack contributes input validation,
binding checks, argv assembly from fixed adapter logic, and
normalized evidence mapping.
"""

from __future__ import annotations

from typing import Any

from emo_cyber_agent.tools.packs.errors import ToolPackError, ToolPackErrorCode
from emo_cyber_agent.tools.packs.provenance import build_tool_provenance, digest_text
from emo_cyber_agent.tools.packs.spec import NormalizedToolResult, ResolvedTool


def validate_inputs(definition: Any, inputs: dict[str, Any]) -> dict[str, Any]:
    """Typed validation per ToolInputContract. Unknown/missing/invalid → INPUT_REJECTED."""
    from emo_cyber_agent.core.repository import normalize_path

    declared = {field.name: field for field in definition.inputs.fields}
    unknown = sorted(set(inputs) - set(declared))
    if unknown:
        raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"undeclared inputs: {unknown}")
    cleaned: dict[str, Any] = {}
    for name, field in declared.items():
        if name not in inputs:
            if field.required:
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"missing required input: {name}")
            continue
        value = inputs[name]
        if field.type == "string":
            if not isinstance(value, str):
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"input not a string: {name}")
            cleaned[name] = value[: field.max_length]
        elif field.type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"input not an integer: {name}")
            if (field.min_value is not None and value < field.min_value) or (field.max_value is not None and value > field.max_value):
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"input out of range: {name}")
            cleaned[name] = value
        elif field.type == "boolean":
            if not isinstance(value, bool):
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"input not a boolean: {name}")
            cleaned[name] = value
        elif field.type == "enum":
            if value not in field.allowed_values:
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"input not allowlisted: {name}")
            cleaned[name] = value
        elif field.type in ("path", "ref", "snapshot_id"):
            if not isinstance(value, str) or not value.strip():
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"input must be a non-empty string: {name}")
            if field.type == "path":
                try:
                    cleaned[name] = normalize_path(value.strip())
                except Exception as e:
                    raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"path rejected: {name}: {e}") from e
            else:
                cleaned[name] = value.strip()[: field.max_length]
        else:
            raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, f"unknown input type: {field.type}")
    return cleaned


class PackExecutor:
    """Pack-aware front door to the existing ToolExecutor."""

    def __init__(self, *, tool_registry: Any, policy: Any, port: Any, audit_root: str, pack_registry: Any, adapters: dict[str, Any]):
        from emo_cyber_agent.core.execution import ToolExecutor as _ToolExecutor

        self._executor = _ToolExecutor(registry=tool_registry, policy=policy, port=port, audit_root=audit_root)
        self._policy = policy
        self._packs = pack_registry
        self._adapters = dict(adapters)

    def _definition(self, resolved: ResolvedTool) -> tuple[Any, Any]:
        pack = self._packs.get(resolved.pack_id, resolved.pack_version or None)
        for definition in pack.definitions:
            if definition.definition_id == resolved.definition_id:
                return pack, definition
        raise ToolPackError(ToolPackErrorCode.NOT_FOUND, f"definition not registered: {resolved.definition_id}")

    def build_argv(self, resolved: ResolvedTool, *, confined_target: str, inputs: dict[str, Any] | None = None) -> tuple[str, ...]:
        """argv = [binary, *fixed_args, *adapter_tail, *flag_values].

        Shell-safe by construction: fixed args validated at pack
        validation; values validated per input contract; the port
        always runs shell=False. No caller can inject raw argv.
        """
        pack, definition = self._definition(resolved)
        adapter = self._adapters.get(definition.adapter)
        if adapter is None:
            raise ToolPackError(ToolPackErrorCode.TOOL_UNAVAILABLE, f"no adapter registered: {definition.adapter}")
        cleaned = validate_inputs(definition, inputs or {})
        base = list(adapter_argv(adapter, resolved, confined_target))
        argv: list[str] = [base[0], *list(definition.fixed_args), *base[1:]]
        declared = {field.name: field for field in definition.inputs.fields}
        for flag in definition.value_flags:
            ref = flag[2:].replace("-", "_")
            if ref not in cleaned:
                continue
            value = cleaned[ref]
            if declared[ref].type == "boolean":
                if value:
                    argv.append(flag)
            else:
                argv.extend([flag, str(value)])
        for part in argv:
            if not isinstance(part, str) or "\x00" in part:
                raise ToolPackError(ToolPackErrorCode.INPUT_REJECTED, "argv part rejected")
        return tuple(argv)

    def execute(
        self,
        resolved: ResolvedTool,
        *,
        audit_id: str,
        project_id: str,
        snapshot_id: str,
        target: str,
        inputs: dict[str, Any] | None = None,
        profile: str = "read_only",
        policy_decision_id: str | None = None,
        timeout_s: int = 120,
    ) -> tuple[NormalizedToolResult, list[dict[str, Any]], Any, Any]:
        from emo_cyber_agent.core.repository import redact_credentials

        pack, definition = self._definition(resolved)
        cleaned = validate_inputs(definition, inputs or {})
        # binding checks: snapshot/audit/project supplied by the caller win;
        # conflicting declared values fail closed.
        if definition.snapshot_binding:
            declared_snapshot = cleaned.get("snapshot_id", "")
            if declared_snapshot and declared_snapshot != snapshot_id:
                raise ToolPackError(ToolPackErrorCode.STALE_SNAPSHOT, "snapshot binding mismatch")
        for key, expected in (("audit_id", audit_id), ("project_id", project_id)):
            if key in cleaned and cleaned[key] != expected:
                raise ToolPackError(ToolPackErrorCode.BINDING_MISMATCH, f"{key} binding mismatch")
        adapter = self._adapters.get(definition.adapter)
        if adapter is None:
            raise ToolPackError(ToolPackErrorCode.TOOL_UNAVAILABLE, f"no adapter registered: {definition.adapter}")
        tool_capability = definition.tool_capability
        if policy_decision_id is None:
            decision = self._policy.issue_decision(audit_id, definition.tool_id, target, profile, [tool_capability])
            if not decision.allowed:
                raise ToolPackError(ToolPackErrorCode.POLICY_DENIED, f"policy denied: {decision.reason_codes}")
            policy_decision_id = decision.decision_id
        final_argv = self.build_argv(resolved, confined_target="__confined__", inputs=inputs)
        _ = final_argv  # validated shape; ToolExecutor re-derives with the real confined target below
        parsed, invocation, result = self._executor.execute(
            audit_id=audit_id, tool_id=definition.tool_id, target=target, capability=tool_capability,
            profile=profile, policy_decision_id=policy_decision_id,
            argv_builder=lambda spec, confined: list(self.build_argv(resolved, confined_target=confined, inputs=inputs)),
            parse=adapter.parse, timeout_s=timeout_s,
        )
        observations = list((parsed or {}).get("observations", []) or [])
        raw_stdout = result.stdout or ""
        raw_digest = digest_text(raw_stdout)
        limitations = list(pack.limitations)
        if result.stdout_truncated or result.stderr_truncated:
            limitations.append("output-truncated: re-run scoped on failure output")
        provenance = build_tool_provenance(
            tool_id=definition.tool_id, tool_version=invocation.tool_version, adapter=definition.adapter,
            pack_id=pack.pack_id, pack_version=pack.version, invocation_id=invocation.invocation_id,
            audit_id=audit_id, project_id=project_id, snapshot_id=snapshot_id, argv_digest=result.argv_digest,
            raw_digest=raw_digest, policy_version=self._policy_decision_policy_version(policy_decision_id or ""),
            network=definition.network.value, coverage="complete", limitations=tuple(limitations),
        )
        if definition.outputs.retains_raw and definition.outputs.redaction:
            provenance["raw_preview"] = redact_credentials(raw_stdout[: definition.outputs.raw_limit])
        normalized = NormalizedToolResult(
            tool_id=definition.tool_id, tool_version=invocation.tool_version,
            invocation_id=invocation.invocation_id, audit_id=audit_id, project_id=project_id,
            snapshot_id=snapshot_id, status="completed", raw_digest=raw_digest,
            normalized_records=tuple(o.model_dump(mode="json") if hasattr(o, "model_dump") else dict(o) for o in observations),
            limitations=tuple(limitations), coverage="complete", provenance=provenance,
        )
        evidence_fields = self.map_evidence(observations, audit_id=audit_id, project_id=project_id, invocation_id=normalized.invocation_id, target=target)
        return normalized, evidence_fields, invocation, result

    def map_evidence(self, observations: list[Any], *, audit_id: str, project_id: str, invocation_id: str, target: str) -> list[dict[str, Any]]:
        """Observation → EvidenceItem fields via the existing Core mapping.
        Tool labels (HIGH/CRITICAL/VULNERABLE/…) stay inside untrusted
        message data; they never become EMO severity or confirmation."""
        from emo_cyber_agent.core.scanners import observation_to_evidence_fields

        return [observation_to_evidence_fields(obs, audit_id=audit_id, asset_id=project_id, invocation_id=invocation_id, target=target) for obs in observations]

    def _policy_decision_policy_version(self, policy_decision_id: str) -> str:
        try:
            decision = self._policy.get_decision(policy_decision_id)
            return str(decision.policy_version) if decision else ""
        except Exception:
            return ""


def adapter_argv(adapter: Any, resolved: ResolvedTool, confined_target: str) -> list[str]:
    from emo_cyber_agent.tools.packs.errors import ToolPackError as _E
    from emo_cyber_agent.tools.packs.errors import ToolPackErrorCode as _C

    try:
        return list(adapter.argv(None, confined_target))
    except Exception as e:
        raise _E(_C.TOOL_UNAVAILABLE, f"adapter argv failed: {e}") from e
