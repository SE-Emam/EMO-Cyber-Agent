"""POST-RC-013 — datasets, blind delivery, contamination control.

Loads the real fixture corpus, checks manifest/selection integrity, gates
ground-truth release behind execution, and proves the contamination scan
both fires on a product identifier and stays clean on the shipped corpus.
"""

from pathlib import Path

import pytest

from emo_cyber_agent.evaluation import (
    ALL_METRIC_NAMES,
    BlindDatasetProvider,
    DatasetManifest,
    EvaluationDataset,
    build_dataset,
    collect_forbidden_identifiers,
    contamination_scan,
    load_dataset,
    normalize_case,
)
from emo_cyber_agent.evaluation.errors import EvaluationError, EvaluationErrorCode

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "fixtures" / "evaluation"
FIXTURE_ROOTS = tuple(
    str(path) for path in sorted((ROOT / "tests" / "fixtures").iterdir())
    if path.is_dir() and path.name != "evaluation"
)


def _manifest(**overrides):
    payload = {"dataset_id": "t-unit", "name": "unit", "case_count": 1}
    payload.update(overrides)
    return payload


def _case(case_id="t-01-case", **overrides):
    payload = {
        "case_id": case_id,
        "title": "Unit case",
        "track": "detection",
        "taxonomy": "secrets",
        "stage": "detection",
        "scenario": {"kind": "detect", "payload": {}},
        "ground_truth": [{"kind": "state", "subject": "ok", "value": True, "match": "true"}],
    }
    payload.update(overrides)
    return normalize_case(payload)


# ------------------------------------------------------------- shipped corpus


def test_shipped_corpus_loads_with_expected_shape():
    dataset = load_dataset(CORPUS)
    assert len(dataset.cases) == dataset.manifest.case_count == 104
    assert dataset.sections == tuple(sorted(path.name for path in CORPUS.iterdir() if path.is_dir()))
    assert len(dataset.sections) == 11
    assert set(dataset.sections) == set(dataset.manifest.sections)
    assert dataset.fingerprint == load_dataset(CORPUS).fingerprint
    assert len(dataset.fingerprint) >= 8
    counts = dataset.counts()
    assert counts["cases"] == 104
    assert counts["split:development"] == 104


def test_shipped_manifest_thresholds_and_requirements_are_registry_bound():
    manifest = load_dataset(CORPUS).manifest
    assert manifest.thresholds
    assert set(manifest.thresholds) <= set(ALL_METRIC_NAMES)
    assert all(0.0 <= value <= 1.0 for value in manifest.thresholds.values())
    assert set(manifest.required_metrics) <= set(ALL_METRIC_NAMES)
    assert manifest.required_gates == ("security_gate", "correctness_gate", "regression_gate")
    assert manifest.baseline
    assert set(manifest.baseline) <= set(ALL_METRIC_NAMES)
    assert manifest.production is False


def test_selection_filters_narrow_the_dataset():
    dataset = load_dataset(CORPUS)
    parity = dataset.select(tracks=["parity"])
    assert parity and all(case.track.value == "parity" for case in parity)
    scripted = dataset.select(tracks=sorted({c.track.value for c in dataset.cases} - {"parity"}))
    assert len(scripted) == len(dataset.cases) - len(parity)
    section = dataset.select(sections=["hostile_input"])
    assert section and all(case.section == "hostile_input" for case in section)
    single = dataset.select(case_ids=[dataset.cases[0].case_id])
    assert len(single) == 1
    stages = dataset.select(stages=["parity"])
    assert stages and all(case.stage.value == "parity" for case in stages)
    splits = dataset.select(split="development")
    assert len(splits) == len(dataset.cases)


def test_unknown_case_id_is_reported():
    dataset = load_dataset(CORPUS)
    with pytest.raises(EvaluationError) as missing:
        dataset.case("does-not-exist")
    assert missing.value.code is EvaluationErrorCode.CASE_NOT_FOUND


# ---------------------------------------------------------- construction rules


def test_duplicate_and_production_cases_are_refused():
    with pytest.raises(EvaluationError) as duplicate:
        build_dataset(_manifest(), [_case("t-01-case"), _case("t-01-case")])
    assert duplicate.value.code is EvaluationErrorCode.INVALID_DATASET

    with pytest.raises(EvaluationError) as production:
        build_dataset(
            _manifest(),
            [_case(source={"system": "production", "fixture": "", "production": True})],
        )
    assert production.value.code is EvaluationErrorCode.INVALID_DATASET

    with pytest.raises(EvaluationError) as empty:
        build_dataset(_manifest(case_count=0), [])
    assert empty.value.code is EvaluationErrorCode.DATASET_EMPTY


def test_split_visibility_rule_is_enforced_on_holdout_cases():
    with pytest.raises(EvaluationError) as holdout:
        _case(split="holdout", visibility="public")
    assert holdout.value.code is EvaluationErrorCode.INVALID_CASE

    dataset = build_dataset(_manifest(), [_case()])
    assert isinstance(dataset, EvaluationDataset)
    assert dataset.manifest.dataset_id == "t-unit"
    assert len(dataset.fingerprint) >= 8

    blinded = build_dataset(_manifest(split="holdout"), [_case(split="holdout", visibility="holdout")])
    assert blinded.split.value == "holdout"


def test_manifest_threshold_validators():
    with pytest.raises(Exception):
        DatasetManifest(dataset_id="t", name="n", thresholds={"lowercase": 0.5})
    with pytest.raises(Exception):
        DatasetManifest(dataset_id="t", name="n", thresholds={"SCORE": 1.5})
    with pytest.raises(Exception):
        DatasetManifest(dataset_id="t", name="n", baseline={"BASE": -0.1})
    manifest = DatasetManifest(dataset_id="t", name="n", thresholds={"SCORE": 0.5})
    assert manifest.thresholds == {"SCORE": 0.5}


def test_load_dataset_reports_missing_and_incomplete_manifests(tmp_path):
    with pytest.raises(EvaluationError) as missing:
        load_dataset(tmp_path)
    assert missing.value.code is EvaluationErrorCode.DATASET_NOT_FOUND

    (tmp_path / "dataset.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(EvaluationError) as broken:
        load_dataset(tmp_path)
    assert broken.value.code is EvaluationErrorCode.INVALID_DATASET


# -------------------------------------------------------------- blind delivery


def test_ground_truth_is_gated_behind_execution():
    dataset = load_dataset(CORPUS)
    provider = BlindDatasetProvider(dataset)
    case_id = dataset.cases[0].case_id

    blind = provider.blind_case(case_id)
    assert not hasattr(blind, "ground_truth")
    assert provider.executed(case_id) is False
    assert provider.executed_count() == 0

    with pytest.raises(EvaluationError) as gated:
        provider.ground_time_for(case_id)
    assert gated.value.code is EvaluationErrorCode.BLIND_ACCESS_DENIED

    provider.mark_executed(case_id)
    assert provider.executed(case_id) is True
    records = provider.ground_time_for(case_id)
    assert records == dataset.case(case_id).ground_truth
    assert provider.executed_count() == 1

    with pytest.raises(EvaluationError) as unknown:
        provider.mark_executed("nope-not-here")
    assert unknown.value.code is EvaluationErrorCode.CASE_NOT_FOUND
    assert provider.dataset is dataset
    assert provider.case_ids() == tuple(case.case_id for case in dataset.cases)


# ----------------------------------------------------------- contamination scan


def test_forbidden_identifier_collection(tmp_path):
    pack = tmp_path / "packs"
    pack.mkdir()
    (pack / "skill-pack.json").write_text(
        '{"id": "skill-alpha", "ids": ["task-beta", "xy"], "playbook_id": "playbook-gamma"}',
        encoding="utf-8",
    )
    (pack / "notes.md").write_text("# prose", encoding="utf-8")
    (pack / "template.yaml").write_text("id: playbook-gamma", encoding="utf-8")
    tokens = collect_forbidden_identifiers([tmp_path])
    assert "skill-pack" in tokens
    assert "skill-alpha" in tokens
    assert "task-beta" in tokens
    assert "template" in tokens  # file stem of the yaml fixture
    assert "playbook-gamma" in tokens  # declared playbook id inside a json fixture
    assert "notes" in tokens  # file stem of the markdown fixture
    assert "xy" not in tokens  # below min_length
    assert collect_forbidden_identifiers([tmp_path / "missing"]) == ()


def test_contamination_scan_flags_structural_fields_only():
    dataset = build_dataset(
        _manifest(),
        [_case(case_id="t-09-flagged", title="Uses skill-alpha surface", scenario={"kind": "detect", "payload": {"id": "skill-alpha"}})],
    )
    report = contamination_scan(dataset, ["skill-alpha", "detectx"])
    assert report.clean is False
    assert report.scanned_cases == 1
    assert report.forbidden_tokens == 2
    hit = report.hits[0]
    assert hit.case_id == "t-09-flagged"
    assert hit.field == "title"
    assert hit.token == "skill-alpha"
    assert contamination_scan(dataset, ["absent-token"]).clean is True


def test_shipped_corpus_is_clean_against_other_fixture_roots():
    assert FIXTURE_ROOTS, "expected sibling fixture roots"
    dataset = load_dataset(CORPUS)
    forbidden = collect_forbidden_identifiers(FIXTURE_ROOTS)
    assert len(forbidden) >= 20
    report = contamination_scan(dataset, forbidden)
    assert report.clean is True, report.hits[:10]
    assert report.scanned_cases == len(dataset.cases)
