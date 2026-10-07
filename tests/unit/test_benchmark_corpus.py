"""POST-T020 G9-B corpus validation — blind rules, schema, and coverage gates.

Validates every JSON document under tests/fixtures/evaluation/post_t020/
against PostT020Case (spec-owned schema, reused — nothing redefined here).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from emo_cyber_agent.evaluation.post_t020_benchmark import (
    PostT020Case,
    PostT020CaseKind,
    PostT020Category,
    post_t020_blind,
)
from emo_cyber_agent.evaluation.spec import SECURITY_GROUND_TRUTH_KINDS

CORPUS_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "evaluation" / "post_t020"

GAP_CATEGORIES = (
    PostT020Category.CLOUD,
    PostT020Category.CONTAMINATION,
    PostT020Category.DELEGATION,
    PostT020Category.RECOVERY,
    PostT020Category.THREAT_MODEL,
)

ALL_KINDS = {k.value for k in PostT020CaseKind}

FORBIDDEN_KEYS = {"ground_truth", "expected", "expected_signal", "must_not", "label", "verdict"}

SECRET_MARKERS = ("AKIA", "-----BEGIN", "aws_secret", "xoxb-", "ghp_")


def _load_documents() -> list[tuple[Path, dict]]:
    files = sorted(CORPUS_DIR.glob("*.json"))
    assert files, f"no corpus files in {CORPUS_DIR}"
    documents = []
    for path in files:
        with path.open() as handle:
            documents.append((path, json.load(handle)))
    return documents


def _input_keys_recursive(node) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.append(key)
            found.extend(_input_keys_recursive(value))
    elif isinstance(node, (list, tuple)):
        for item in node:
            found.extend(_input_keys_recursive(item))
    return found


@pytest.fixture(scope="module")
def cases() -> list[PostT020Case]:
    parsed = []
    for path, raw in _load_documents():
        parsed.append(PostT020Case.model_validate(raw))
    return parsed


def test_corpus_files_parse_against_schema(cases: list[PostT020Case]) -> None:
    assert len(cases) >= 30, f"expected 30+ cases, found {len(cases)}"


def test_gap_categories_have_minimum_coverage(cases: list[PostT020Case]) -> None:
    counts = Counter(case.category for case in cases)
    for category in GAP_CATEGORIES:
        assert counts[category] >= 6, f"{category.value}: {counts[category]} < 6"


def test_each_gap_category_spans_all_kinds(cases: list[PostT020Case]) -> None:
    by_category: dict[str, set[str]] = {}
    for case in cases:
        by_category.setdefault(case.category.value, set()).add(case.kind.value)
    for category in GAP_CATEGORIES:
        missing = ALL_KINDS - by_category.get(category.value, set())
        assert not missing, f"{category.value} missing kinds: {sorted(missing)}"


def test_case_ids_unique(cases: list[PostT020Case]) -> None:
    ids = [case.case_id for case in cases]
    assert len(set(ids)) == len(ids), "duplicate case_id values"


def test_categories_and_kinds_closed(cases: list[PostT020Case]) -> None:
    valid_categories = {c.value for c in PostT020Category}
    valid_kinds = {k.value for k in PostT020CaseKind}
    for case in cases:
        assert case.category.value in valid_categories
        assert case.kind.value in valid_kinds
        for secondary in case.secondary_categories:
            assert secondary.value in valid_categories


def test_blind_projection_holds(cases: list[PostT020Case]) -> None:
    for case in cases:
        blind = post_t020_blind(case)
        assert set(blind) == {
            "case_id",
            "title",
            "category",
            "secondary_categories",
            "kind",
            "input",
        }, f"{case.case_id}: blind shape mismatch"
        leaked = FORBIDDEN_KEYS & set(blind)
        assert not leaked, f"{case.case_id}: blind leak {sorted(leaked)}"
        nested = FORBIDDEN_KEYS & set(_input_keys_recursive(case.input))
        assert not nested, f"{case.case_id}: input carries {sorted(nested)}"
        with pytest.raises(Exception):
            post_t020_blind(case.model_dump())


def test_must_not_present_where_required(cases: list[PostT020Case]) -> None:
    for case in cases:
        if case.kind in (PostT020CaseKind.ADVERSARIAL, PostT020CaseKind.CROSS_SCOPE):
            assert case.must_not, f"{case.case_id}: {case.kind.value} needs must_not"
            for record in case.must_not:
                assert record.kind.value in SECURITY_GROUND_TRUTH_KINDS, (
                    f"{case.case_id}: must_not kind {record.kind.value} not security-relevant"
                )


def test_cross_scope_secondary_rules(cases: list[PostT020Case]) -> None:
    for case in cases:
        if case.kind is PostT020CaseKind.CROSS_SCOPE:
            assert case.secondary_categories, f"{case.case_id}: cross_scope needs secondary"
        else:
            assert not case.secondary_categories, (
                f"{case.case_id}: secondaries only for cross_scope"
            )


def test_regression_stage_signal(cases: list[PostT020Case]) -> None:
    regressions = [c for c in cases if c.kind is PostT020CaseKind.REGRESSION]
    assert regressions, "no regression cases"
    for case in regressions:
        assert any(r.stage == "regression" for r in case.expected_signal), (
            f"{case.case_id}: regression needs a regression-stage signal"
        )


def test_sources_non_production_and_no_secrets(cases: list[PostT020Case]) -> None:
    for case in cases:
        assert not case.source.production, f"{case.case_id}: production source refused"
        blob = json.dumps(case.input)
        for marker in SECRET_MARKERS:
            assert marker not in blob, f"{case.case_id}: secret marker {marker!r}"


# --- POST-T020 G11 M3: nested ground-truth-shaped keys must not leak ---


def _valid_signal() -> dict:
    return {"kind": "evidence", "subject": "x", "stage": "report", "value": "y"}


def _valid_kwargs(**over) -> dict:
    base = {
        "case_id": "g11.m3-case",
        "title": "G11 M3",
        "category": "code",
        "kind": "positive",
        "input": {"prompt": "benign"},
        "expected_signal": [_valid_signal()],
    }
    base.update(over)
    return base


def test_g11_m3_nested_ground_truth_refused_at_construction() -> None:
    for nested_input in (
        {"context": {"ground_truth": "SECRET"}},
        {"a": {"b": {"expected_signal": ["x"]}}},
        {"items": [{"label": "leak"}]},
        {"deep": {"deeper": {"verdict": "pass"}}},
    ):
        with pytest.raises(Exception):
            PostT020Case.model_validate(_valid_kwargs(input=nested_input))


def test_g11_m3_blind_projection_refuses_nested_mapping_and_deep_copies() -> None:
    from emo_cyber_agent.evaluation.errors import EvaluationError

    case = PostT020Case.model_validate(_valid_kwargs(input={"nested": {"list": [1, 2]}}))
    blind = post_t020_blind(case)
    assert blind["input"] == {"nested": {"list": [1, 2]}}
    # Deep copy: mutating the projection must not alias the case.
    blind["input"]["nested"]["list"].append(3)
    assert case.input == {"nested": {"list": [1, 2]}}
    # Raw-mapping path with a poisoned nested fixture is refused.
    poisoned = {
        "case_id": "g11.m3-poison",
        "title": "P",
        "category": "code",
        "kind": "positive",
        "input": {"context": {"ground_truth": "SECRET"}},
    }
    with pytest.raises(EvaluationError):
        post_t020_blind(poisoned)
