"""Independent synthetic catalog joins using in-source fixtures."""
import pytest

from evaluation import fixture_loader


def _payload(label):
    return {"cases": [{
        "caseId": "synthetic-shared-id",
        "kind": "NORMAL",
        "input": {"items": [{"label": label}]},
        "expected": {"decision": label, "checks": [label]},
    }]}


def test_same_case_id_is_scoped_to_catalog_and_never_joins_another_catalog(monkeypatch):
    monkeypatch.setattr(fixture_loader, "_REGISTRY", {})
    left = _payload("LEFT_SYNTHETIC")
    right = _payload("RIGHT_SYNTHETIC")
    right["cases"].append({"caseId": "synthetic-right-only", "kind": "ATTACK"})
    left_hash = fixture_loader.register_fixture_set("synthetic-catalog-left", left)
    right_hash = fixture_loader.register_fixture_set("synthetic-catalog-right", right)
    assert left_hash != right_hash
    for catalog, marker, digest in (
        ("synthetic-catalog-left", "LEFT_SYNTHETIC", left_hash),
        ("synthetic-catalog-right", "RIGHT_SYNTHETIC", right_hash),
    ):
        selected = fixture_loader.load_fixture_set(catalog, ["synthetic-shared-id"])
        assert selected["fixtureSetId"] == catalog
        assert selected["fixtureHash"] == digest
        assert selected["cases"] == [{
            "caseId": "synthetic-shared-id", "kind": "NORMAL",
            "input": {"items": [{"label": marker}]},
            "expected": {"decision": marker, "checks": [marker]},
        }]
    with pytest.raises(ValueError, match="^case is not registered$") as failure:
        fixture_loader.load_fixture_set("synthetic-catalog-left", ["synthetic-right-only"])
    assert failure.value.__cause__ is None
    assert fixture_loader.load_fixture_set("synthetic-catalog-left")["cases"] == left["cases"]


def test_nested_source_and_selected_mutation_cannot_rebind_input_to_other_expected(monkeypatch):
    monkeypatch.setattr(fixture_loader, "_REGISTRY", {})
    source = _payload("ORIGINAL_SYNTHETIC")
    digest = fixture_loader.register_fixture_set("synthetic-nested-catalog", source)
    source["cases"][0]["input"]["items"][0]["label"] = "CALLER_INPUT_CHANGE"
    source["cases"][0]["expected"]["checks"].append("CALLER_EXPECTED_CHANGE")
    first = fixture_loader.load_fixture_set("synthetic-nested-catalog", ["synthetic-shared-id"])
    assert first["cases"][0]["input"] == {"items": [{"label": "ORIGINAL_SYNTHETIC"}]}
    assert first["cases"][0]["expected"] == {"decision": "ORIGINAL_SYNTHETIC", "checks": ["ORIGINAL_SYNTHETIC"]}
    first["cases"][0]["input"]["items"].clear()
    first["cases"][0]["expected"]["decision"] = "SELECTED_RESULT_CHANGE"
    again = fixture_loader.load_fixture_set("synthetic-nested-catalog", ["synthetic-shared-id"])
    assert again["cases"] == _payload("ORIGINAL_SYNTHETIC")["cases"]
    assert again["fixtureHash"] == digest


def test_valid_conflicting_reregistration_preserves_original_catalog_and_hash(monkeypatch):
    monkeypatch.setattr(fixture_loader, "_REGISTRY", {})
    identifier = "synthetic-conflicting-catalog"
    digest = fixture_loader.register_fixture_set(identifier, _payload("PINNED_SYNTHETIC"))
    before = fixture_loader.load_fixture_set(identifier)
    assert fixture_loader.register_fixture_set(identifier, _payload("PINNED_SYNTHETIC")) == digest
    for field in ("input", "expected"):
        changed = _payload("PINNED_SYNTHETIC")
        changed["cases"][0][field] = {"changed": "OTHER_SYNTHETIC"}
        with pytest.raises(ValueError, match="^fixture registration is already pinned$") as failure:
            fixture_loader.register_fixture_set(identifier, changed)
        assert failure.value.__cause__ is None
        assert fixture_loader.load_fixture_set(identifier) == before
        assert fixture_loader.load_fixture_set(identifier)["fixtureHash"] == digest


def test_duplicate_ids_never_register_or_poison_an_existing_pin(monkeypatch):
    monkeypatch.setattr(fixture_loader, "_REGISTRY", {})
    existing = "synthetic-existing-duplicate-guard"
    fresh = "synthetic-new-duplicate-guard"
    fixture_loader.register_fixture_set(existing, _payload("ORIGINAL_SYNTHETIC"))
    before = fixture_loader.load_fixture_set(existing)
    duplicates = _payload("FIRST_SYNTHETIC")
    duplicates["cases"].append(_payload("SECOND_SYNTHETIC")["cases"][0])
    for identifier in (fresh, existing):
        with pytest.raises(ValueError, match="^duplicate fixture cases$") as failure:
            fixture_loader.register_fixture_set(identifier, duplicates)
        assert failure.value.__cause__ is None
    with pytest.raises(ValueError, match="^fixture set is not registered$"):
        fixture_loader.load_fixture_set(fresh)
    assert fixture_loader.load_fixture_set(existing) == before
