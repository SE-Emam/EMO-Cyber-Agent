"""Security review checklist tests — POST-T020 (checklist owner scope only)."""

import ast
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from emo_cyber_agent.checklists.catalog import (
    OFFICIAL_CHECKLIST_IDS,
    SCOPE_TO_ID,
    get_by_scope,
    get_checklist,
    list_checklists,
)
from emo_cyber_agent.checklists.spec import Checklist, ChecklistItem

EXPECTED_IDS = (
    "secure-code-review",
    "agent-security-review",
    "prompt-injection-review",
    "mcp-security-review",
    "cloud-security-review",
    "change-security-review",
    "release-security-review",
)

EXPECTED_SCOPE = {
    "secure-code-review": "source-code-change",
    "agent-security-review": "agent-system",
    "prompt-injection-review": "untrusted-input-handling",
    "mcp-security-review": "mcp-tool-surface",
    "cloud-security-review": "cloud-deployment",
    "change-security-review": "proposed-change",
    "release-security-review": "release-candidate",
}

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
KEBAB_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,78}[a-z0-9]$")

FORBIDDEN_FIELDS = {
    "capability",
    "capabilities",
    "policy",
    "policies",
    "severity",
    "severities",
    "permission",
    "permissions",
    "verdict",
    "grant",
    "authority",
}

FORBIDDEN_IDENTIFIERS = FORBIDDEN_FIELDS | {"authorize", "approve", "deny"}

# Verdict verbs that would make an acceptance condition result-biased.
BIASED_WORDS = (
    "pass",
    "fail",
    "approve",
    "reject",
    "grant",
    "deny",
    "severity",
    "verdict",
)
BIASED_RE = re.compile(r"\b(" + "|".join(BIASED_WORDS) + r")\b", re.IGNORECASE)

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "emo_cyber_agent" / "checklists"


def _good_item_kwargs(item_id="x-item-one"):
    return {
        "id": item_id,
        "check": "Review described behavior.",
        "expected_evidence": "Cited lines recorded in the review note.",
        "verification_requirement": "Re-read the cited lines and confirm the note matches.",
        "acceptance_condition": "The behavior is described with lines cited in the review note.",
    }


# --- catalog completeness --- #


def test_official_ids_complete():
    assert OFFICIAL_CHECKLIST_IDS == EXPECTED_IDS
    assert [c.id for c in list_checklists()] == list(EXPECTED_IDS)


def test_each_official_checklist_retrievable():
    for checklist_id in EXPECTED_IDS:
        checklist = get_checklist(checklist_id)
        assert isinstance(checklist, Checklist)
        assert checklist.id == checklist_id


def test_unknown_checklist_raises():
    with pytest.raises(KeyError):
        get_checklist("not-a-checklist")
    with pytest.raises(KeyError):
        get_by_scope("not-a-scope")


def test_scope_map_covers_all_ids():
    assert set(SCOPE_TO_ID.values()) == set(EXPECTED_IDS)
    assert len(set(SCOPE_TO_ID)) == len(EXPECTED_IDS)


# --- schema validity --- #


def test_checklist_schema_valid():
    for checklist in list_checklists():
        assert isinstance(checklist.id, str) and checklist.id.strip()
        assert isinstance(checklist.version, str) and checklist.version.strip()
        assert isinstance(checklist.scope, str) and checklist.scope.strip()
        assert isinstance(checklist.items, tuple) and len(checklist.items) >= 1
        for item in checklist.items:
            assert isinstance(item, ChecklistItem)
            for field_name in (
                "check",
                "expected_evidence",
                "verification_requirement",
                "acceptance_condition",
            ):
                value = getattr(item, field_name)
                assert isinstance(value, str) and value.strip()
                assert len(value) >= 10


def test_models_are_frozen():
    item = ChecklistItem(**_good_item_kwargs())
    with pytest.raises(Exception):
        item.check = "mutated"  # type: ignore[misc]
    checklist = get_checklist("secure-code-review")
    with pytest.raises(Exception):
        checklist.version = "9.9.9"  # type: ignore[misc]


def test_extra_fields_forbidden():
    with pytest.raises(Exception):
        ChecklistItem(**{**_good_item_kwargs(), "severity": "high"})
    with pytest.raises(Exception):
        Checklist(
            id="secure-code-review",
            version="1.0.0",
            scope="source-code-change",
            items=(ChecklistItem(**_good_item_kwargs()),),
            capability="anything",
        )


def test_bad_ids_versions_scopes_rejected():
    with pytest.raises(Exception):
        ChecklistItem(**{**_good_item_kwargs(item_id="UPPER")})
    with pytest.raises(Exception):
        Checklist(
            id="BAD",
            version="1.0.0",
            scope="source-code-change",
            items=(ChecklistItem(**_good_item_kwargs()),),
        )
    with pytest.raises(Exception):
        Checklist(
            id="secure-code-review",
            version="not-semver",
            scope="source-code-change",
            items=(ChecklistItem(**_good_item_kwargs()),),
        )
    with pytest.raises(Exception):
        Checklist(
            id="secure-code-review",
            version="1.0.0",
            scope="Has Space",
            items=(ChecklistItem(**_good_item_kwargs()),),
        )
    with pytest.raises(Exception):
        ChecklistItem(**{**_good_item_kwargs(), "check": "   "})


def test_duplicate_item_ids_rejected():
    with pytest.raises(Exception):
        Checklist(
            id="secure-code-review",
            version="1.0.0",
            scope="source-code-change",
            items=(
                ChecklistItem(**_good_item_kwargs(item_id="dup-item")),
                ChecklistItem(**_good_item_kwargs(item_id="dup-item")),
            ),
        )


def test_blank_item_fields_rejected():
    for field_name in (
        "check",
        "expected_evidence",
        "verification_requirement",
        "acceptance_condition",
    ):
        kwargs = _good_item_kwargs()
        kwargs[field_name] = "  "
        with pytest.raises(Exception):
            ChecklistItem(**kwargs)


# --- determinism / roundtrip --- #


def test_item_roundtrip():
    for checklist in list_checklists():
        for item in checklist.items:
            assert ChecklistItem.from_dict(item.to_dict()) == item
            assert ChecklistItem.from_dict(json.loads(item.to_canonical_json())) == item


def test_checklist_roundtrip_and_canonical_json():
    for checklist in list_checklists():
        assert Checklist.from_dict(checklist.to_dict()) == checklist
        assert Checklist.from_dict(json.loads(checklist.to_canonical_json())) == checklist
        first = checklist.to_canonical_json()
        assert checklist.to_canonical_json() == first


def test_catalog_deterministic():
    first = list_checklists()
    for _ in range(5):
        again = list_checklists()
        assert again == first
        assert [c.to_canonical_json() for c in again] == [c.to_canonical_json() for c in first]
    for checklist_id in EXPECTED_IDS:
        assert get_checklist(checklist_id) == get_checklist(checklist_id)


def test_item_order_preserved():
    for checklist in list_checklists():
        ids_once = [item.id for item in get_checklist(checklist.id).items]
        ids_again = [item.id for item in get_checklist(checklist.id).items]
        assert ids_once == ids_again == [item.id for item in checklist.items]
        assert len(set(ids_once)) == len(ids_once)


# --- scope binding --- #


def test_scope_binding():
    seen_scopes = set()
    for checklist in list_checklists():
        assert checklist.scope == EXPECTED_SCOPE[checklist.id]
        assert KEBAB_RE.match(checklist.scope)
        seen_scopes.add(checklist.scope)
        for item in checklist.items:
            assert item.id.startswith(checklist.id + "-"), (
                f"item {item.id} not bound to checklist {checklist.id}"
            )
    assert len(seen_scopes) == len(EXPECTED_IDS)


def test_get_by_scope_roundtrip():
    for checklist in list_checklists():
        assert get_by_scope(checklist.scope) == checklist
        assert get_by_scope(checklist.scope).id == checklist.id


# --- version format --- #


def test_version_format():
    for checklist in list_checklists():
        assert SEMVER_RE.match(checklist.version), (
            f"{checklist.id} version not semver: {checklist.version}"
        )


# --- evidence / verification / result-bias --- #


def test_items_evidence_and_verification_aware():
    for checklist in list_checklists():
        for item in checklist.items:
            assert item.expected_evidence.strip()
            assert item.verification_requirement.strip()
            assert item.acceptance_condition.strip()


def test_acceptance_conditions_result_bias_free():
    for checklist in list_checklists():
        for item in checklist.items:
            assert not BIASED_RE.search(item.acceptance_condition), (
                f"{item.id} acceptance_condition is result-biased: {item.acceptance_condition!r}"
            )


# --- no-authority guard: checklists grant nothing --- #


def test_no_authority_fields():
    for model in (Checklist, ChecklistItem):
        fields = set(model.model_fields)
        overlap = {f.lower() for f in fields} & FORBIDDEN_FIELDS
        assert not overlap, f"{model.__name__} grants authority via fields: {overlap}"
    for checklist in list_checklists():
        dumped = checklist.to_dict()
        overlap = {k.lower() for k in dumped} & FORBIDDEN_FIELDS
        assert not overlap, f"{checklist.id} serialized authority keys: {overlap}"
        for item in checklist.items:
            overlap = {k.lower() for k in item.to_dict()} & FORBIDDEN_FIELDS
            assert not overlap, f"{item.id} serialized authority keys: {overlap}"


def _identifiers_in_source(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            found.add(node.attr.lower())
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name.lower())
        elif isinstance(node, ast.arg):
            found.add(node.arg.lower())
    return found


def test_no_authority_identifiers_in_source():
    for filename in ("spec.py", "catalog.py"):
        path = SRC_ROOT / filename
        assert path.exists(), f"missing {filename}"
        overlap = _identifiers_in_source(path) & FORBIDDEN_IDENTIFIERS
        assert not overlap, f"{filename} grants authority via identifiers: {overlap}"
