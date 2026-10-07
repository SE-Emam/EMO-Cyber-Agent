"""Official security review checklist catalog — POST-T020.

Seven deterministic, versioned, scope-bound checklists. Each item is
evidence-aware (``expected_evidence`` names the artifact to cite),
verification-aware (``verification_requirement`` names how to confirm),
and result-bias-free (``acceptance_condition`` states an observable
condition without prejudging pass/fail or assigning levels).

Checklists GRANT NOTHING: no capability, policy, or severity fields,
no verdicts, no execution. Accessors return the same frozen objects on
every call.
"""

from __future__ import annotations

from emo_cyber_agent.checklists.spec import Checklist, ChecklistItem

__all__ = [
    "OFFICIAL_CHECKLIST_IDS",
    "SCOPE_TO_ID",
    "get_by_scope",
    "get_checklist",
    "list_checklists",
]


def _item(
    id: str,
    check: str,
    expected_evidence: str,
    verification_requirement: str,
    acceptance_condition: str,
) -> ChecklistItem:
    return ChecklistItem(
        id=id,
        check=check,
        expected_evidence=expected_evidence,
        verification_requirement=verification_requirement,
        acceptance_condition=acceptance_condition,
    )


def _secure_code_review() -> Checklist:
    prefix = "secure-code-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="source-code-change",
        items=(
            _item(
                f"{prefix}-input-handling",
                "Review how untrusted input is handled at each entry point in the change.",
                "File path and line references for each entry point plus the handling code cited in the review note.",
                "Re-read the cited lines and confirm the described handling matches the source.",
                "Each entry point in the change is listed with its handling described and lines cited.",
            ),
            _item(
                f"{prefix}-output-encoding",
                "Review output encoding for contexts where change data is rendered or stored.",
                "Rendering or storage locations cited with the encoding used at each location.",
                "Inspect the cited locations and confirm the recorded encoding is present in the source.",
                "Every rendering or storage location in the change has its encoding recorded with a citation.",
            ),
            _item(
                f"{prefix}-secret-handling",
                "Review that no secret material is introduced in code, comments, tests, or fixtures.",
                "Search output and file citations showing where secret patterns were looked for and what was found.",
                "Repeat the recorded search on the cited paths and confirm the recorded outcome.",
                "The locations searched and the material found, if any, are recorded with citations.",
            ),
            _item(
                f"{prefix}-dependency-use",
                "Review new or changed dependency uses for documented purpose and version reference.",
                "Manifest or import citations with the purpose of each added dependency noted.",
                "Open the cited manifest or import lines and confirm the recorded purpose matches usage.",
                "Each added dependency is listed with its version reference and purpose noted.",
            ),
            _item(
                f"{prefix}-error-paths",
                "Review error paths in the change for information included in messages and logs.",
                "Error-path locations cited with the message or logged content quoted in the review note.",
                "Read the cited error paths and confirm the quoted content matches the source.",
                "Each error path in the change is listed with its emitted content quoted and cited.",
            ),
        ),
    )


def _agent_security_review() -> Checklist:
    prefix = "agent-security-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="agent-system",
        items=(
            _item(
                f"{prefix}-tool-surface",
                "Review the set of tools the agent can reach in this scope.",
                "List of reachable tools with configuration references cited in the review note.",
                "Read the cited configuration and confirm the listed tools match what is configured.",
                "The reachable tools are listed with configuration references cited.",
            ),
            _item(
                f"{prefix}-instruction-sources",
                "Review the sources of instructions the agent accepts within this scope.",
                "Each instruction source cited with its origin location recorded in the review note.",
                "Inspect the cited origins and confirm the recorded sources are present.",
                "Each instruction source is listed with its origin location recorded.",
            ),
            _item(
                f"{prefix}-data-boundaries",
                "Review boundaries between trusted and untrusted data in the agent workflow.",
                "Workflow steps cited with the data classification noted at each step.",
                "Walk the cited steps and confirm the recorded classification matches the data flow.",
                "Each workflow step is listed with its data classification noted and cited.",
            ),
            _item(
                f"{prefix}-action-records",
                "Review that agent actions leave records sufficient for later inspection.",
                "Record locations cited with the fields captured at each location described.",
                "Open the cited record locations and confirm the described fields are captured.",
                "Each agent action location has its captured record fields described with citations.",
            ),
            _item(
                f"{prefix}-human-checkpoints",
                "Review where human checkpoints occur before consequential actions.",
                "Consequential actions listed with the checkpoint location for each cited.",
                "Read the cited checkpoints and confirm the recorded placement matches the workflow.",
                "Each consequential action is listed with its checkpoint location recorded.",
            ),
        ),
    )


def _prompt_injection_review() -> Checklist:
    prefix = "prompt-injection-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="untrusted-input-handling",
        items=(
            _item(
                f"{prefix}-content-origins",
                "Review the origins of content placed near instructions.",
                "Each content block cited with its origin and trust note recorded.",
                "Inspect the cited blocks and confirm the recorded origin matches the source.",
                "Each content block near instructions is listed with its origin recorded.",
            ),
            _item(
                f"{prefix}-delimiter-use",
                "Review delimiters or markers separating instructions from data.",
                "Delimiter locations cited with the marker text quoted in the review note.",
                "Read the cited locations and confirm the quoted markers are present.",
                "Each instruction-data boundary has its marker quoted and cited.",
            ),
            _item(
                f"{prefix}-quoted-instructions",
                "Review quoted or pasted instruction-like text inside untrusted content.",
                "Instances cited with the surrounding context quoted in the review note.",
                "Read the cited instances and confirm the quoted context matches the source.",
                "Each instruction-like instance in untrusted content is cited with context quoted.",
            ),
            _item(
                f"{prefix}-output-grounding",
                "Review that generated output is grounded in cited evidence rather than embedded directives.",
                "Output sections cited with the evidence references supporting each section.",
                "Compare the cited outputs against the cited evidence and confirm the references exist.",
                "Each output section has its supporting evidence references recorded.",
            ),
            _item(
                f"{prefix}-refusal-records",
                "Review that refused or redirected requests are recorded with the reason noted.",
                "Refusal instances cited with the recorded reason quoted in the review note.",
                "Read the cited instances and confirm the recorded reason matches the entry.",
                "Each refusal instance is listed with its recorded reason quoted.",
            ),
        ),
    )


def _mcp_security_review() -> Checklist:
    prefix = "mcp-security-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="mcp-tool-surface",
        items=(
            _item(
                f"{prefix}-exposed-tools",
                "Review the tools exposed over the MCP surface in this scope.",
                "Tool list with server configuration references cited in the review note.",
                "Read the cited configuration and confirm the listed tools match the exposure.",
                "The exposed tools are listed with server configuration references cited.",
            ),
            _item(
                f"{prefix}-input-schemas",
                "Review input schemas of exposed tools for bounds and documented fields.",
                "Schema locations cited with field lists recorded in the review note.",
                "Open the cited schemas and confirm the recorded fields match the definitions.",
                "Each exposed tool has its schema fields recorded with locations cited.",
            ),
            _item(
                f"{prefix}-transport-setting",
                "Review the transport setting carrying MCP traffic in this scope.",
                "Configuration entries cited with the transport value quoted in the review note.",
                "Read the cited entries and confirm the quoted transport value is present.",
                "The transport setting is recorded with its configuration entry cited.",
            ),
            _item(
                f"{prefix}-logging-coverage",
                "Review logging coverage for tool invocations on this surface.",
                "Invocation paths cited with the logged fields described for each path.",
                "Inspect the cited paths and confirm the described logged fields exist.",
                "Each invocation path has its logged fields described with citations.",
            ),
            _item(
                f"{prefix}-error-responses",
                "Review error responses from tools for information included.",
                "Error response locations cited with the response content quoted.",
                "Read the cited locations and confirm the quoted content matches the source.",
                "Each error response is listed with its content quoted and cited.",
            ),
        ),
    )


def _cloud_security_review() -> Checklist:
    prefix = "cloud-security-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="cloud-deployment",
        items=(
            _item(
                f"{prefix}-public-exposure",
                "Review network exposure of each workload in the deployment scope.",
                "Resource entries cited with the exposure setting recorded for each.",
                "Read the cited resource entries and confirm the recorded exposure matches configuration.",
                "Each workload has its exposure setting recorded with a citation.",
            ),
            _item(
                f"{prefix}-identity-attachments",
                "Review identities attached to workloads in the deployment scope.",
                "Attachment entries cited with the identity reference recorded for each workload.",
                "Read the cited entries and confirm the recorded identity matches configuration.",
                "Each workload has its attached identity recorded with a citation.",
            ),
            _item(
                f"{prefix}-stored-data",
                "Review stored data locations and their recorded protection settings.",
                "Storage entries cited with the protection setting recorded for each location.",
                "Read the cited entries and confirm the recorded setting is present.",
                "Each storage location has its protection setting recorded with a citation.",
            ),
            _item(
                f"{prefix}-change-records",
                "Review that configuration changes in scope leave traceable records.",
                "Change history locations cited with the recorded entries described.",
                "Open the cited history and confirm the described entries are present.",
                "Each configuration area has its change history location cited and described.",
            ),
            _item(
                f"{prefix}-backup-state",
                "Review recorded backup state for data stores in the deployment scope.",
                "Data store entries cited with the backup setting recorded for each.",
                "Read the cited entries and confirm the recorded backup setting is present.",
                "Each data store has its backup setting recorded with a citation.",
            ),
        ),
    )


def _change_security_review() -> Checklist:
    prefix = "change-security-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="proposed-change",
        items=(
            _item(
                f"{prefix}-change-description",
                "Review that the proposed change describes affected components and behavior differences.",
                "Change description location cited with the affected components listed.",
                "Read the cited description and confirm the listed components match the diff.",
                "The affected components are listed with the description location cited.",
            ),
            _item(
                f"{prefix}-test-evidence",
                "Review test evidence attached to the proposed change.",
                "Test reports or run references cited with the covered areas noted.",
                "Open the cited reports and confirm the noted coverage matches the contents.",
                "Each test report is cited with its covered areas noted.",
            ),
            _item(
                f"{prefix}-rollback-note",
                "Review that the change records how it is reversed.",
                "Reversal instructions cited with their location recorded in the review note.",
                "Read the cited instructions and confirm the recorded location is present.",
                "The reversal instructions are recorded with their location cited.",
            ),
            _item(
                f"{prefix}-reviewer-notes",
                "Review that reviewer observations on the change are recorded.",
                "Review threads cited with each observation summarized in the review note.",
                "Open the cited threads and confirm the summaries match the entries.",
                "Each review thread is cited with its observations summarized.",
            ),
            _item(
                f"{prefix}-migration-steps",
                "Review migration or data steps included in the proposed change.",
                "Migration files cited with each step described in the review note.",
                "Read the cited files and confirm the described steps match the contents.",
                "Each migration step is described with its file cited.",
            ),
        ),
    )


def _release_security_review() -> Checklist:
    prefix = "release-security-review"
    return Checklist(
        id=prefix,
        version="1.0.0",
        scope="release-candidate",
        items=(
            _item(
                f"{prefix}-artifact-list",
                "Review the artifact list included in the release candidate.",
                "Artifact manifest cited with each included artifact recorded.",
                "Read the cited manifest and confirm the recorded artifacts match the entries.",
                "Each included artifact is recorded with the manifest cited.",
            ),
            _item(
                f"{prefix}-version-notes",
                "Review version notes describing differences from the previous release.",
                "Notes location cited with the described differences summarized.",
                "Read the cited notes and confirm the summary matches the contents.",
                "The version differences are summarized with the notes location cited.",
            ),
            _item(
                f"{prefix}-verification-runs",
                "Review verification runs recorded against the release candidate.",
                "Run reports cited with the exercised areas noted for each run.",
                "Open the cited reports and confirm the noted areas match the contents.",
                "Each verification run is cited with its exercised areas noted.",
            ),
            _item(
                f"{prefix}-outstanding-items",
                "Review outstanding items deferred past this release candidate.",
                "Deferred item entries cited with the recorded reason for deferral quoted.",
                "Read the cited entries and confirm the quoted reasons match the source.",
                "Each deferred item is listed with its recorded reason quoted.",
            ),
            _item(
                f"{prefix}-signoff-record",
                "Review that reviewer signoff entries for the release candidate are recorded.",
                "Signoff entries cited with the reviewer reference and timestamp noted.",
                "Open the cited entries and confirm the recorded references are present.",
                "Each signoff entry is listed with its reviewer reference and timestamp noted.",
            ),
        ),
    )


_BUILDERS = {
    "secure-code-review": _secure_code_review,
    "agent-security-review": _agent_security_review,
    "prompt-injection-review": _prompt_injection_review,
    "mcp-security-review": _mcp_security_review,
    "cloud-security-review": _cloud_security_review,
    "change-security-review": _change_security_review,
    "release-security-review": _release_security_review,
}

OFFICIAL_CHECKLIST_IDS: tuple[str, ...] = (
    "secure-code-review",
    "agent-security-review",
    "prompt-injection-review",
    "mcp-security-review",
    "cloud-security-review",
    "change-security-review",
    "release-security-review",
)

SCOPE_TO_ID: dict[str, str] = {
    "source-code-change": "secure-code-review",
    "agent-system": "agent-security-review",
    "untrusted-input-handling": "prompt-injection-review",
    "mcp-tool-surface": "mcp-security-review",
    "cloud-deployment": "cloud-security-review",
    "proposed-change": "change-security-review",
    "release-candidate": "release-security-review",
}


def get_checklist(checklist_id: str) -> Checklist:
    """Return the official checklist for ``checklist_id``.

    Pure and deterministic: repeated calls with the same id return equal
    frozen objects. Unknown ids raise ``KeyError``.
    """
    try:
        builder = _BUILDERS[checklist_id]
    except KeyError:
        raise KeyError(f"unknown checklist: {checklist_id}") from None
    return builder()


def get_by_scope(scope: str) -> Checklist:
    """Return the official checklist bound to ``scope``.

    Each scope maps to exactly one checklist; unknown scopes raise
    ``KeyError``.
    """
    try:
        checklist_id = SCOPE_TO_ID[scope]
    except KeyError:
        raise KeyError(f"unknown checklist scope: {scope}") from None
    return get_checklist(checklist_id)


def list_checklists() -> tuple[Checklist, ...]:
    """Return all official checklists in catalog order (deterministic)."""
    return tuple(get_checklist(checklist_id) for checklist_id in OFFICIAL_CHECKLIST_IDS)
