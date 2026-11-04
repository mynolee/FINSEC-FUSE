"""Synthetic registry lookup inputs must not run caller-defined callbacks."""
import pytest

from evaluation import fixture_loader


def test_custom_fixture_identifier_is_rejected_before_registry_hash_or_string_callbacks():
    class Identifier(str):
        def __hash__(self):
            raise AssertionError("Custom lookup hash must not execute")

        def strip(self):
            raise AssertionError("Custom lookup strip must not execute")

    with pytest.raises(ValueError, match="^fixture identifier is required$"):
        fixture_loader.load_fixture_set(Identifier("synthetic-lookup"))


@pytest.mark.parametrize("identifier", [None, [], {}, True, b"synthetic", "", " \t"])
def test_wrong_identifier_types_and_blank_values_are_fixed_errors(identifier):
    with pytest.raises(ValueError, match="^fixture identifier is required$") as failure:
        fixture_loader.load_fixture_set(identifier)
    assert failure.value.__cause__ is None


def test_custom_selection_containers_and_elements_are_rejected_without_callbacks():
    class Selection(list):
        def __iter__(self):
            raise AssertionError("Custom selection iteration must not execute")

    class CaseIdentifier(str):
        def __hash__(self):
            raise AssertionError("Custom selected ID hash must not execute")

    for selection in (Selection(), [CaseIdentifier("synthetic-case")]):
        with pytest.raises(ValueError, match="^invalid case selection$"):
            fixture_loader.load_fixture_set("synthetic-lookup-unregistered", selection)


def test_bad_selection_is_rejected_before_registry_lock_or_copy(monkeypatch):
    class Lock:
        def __enter__(self):
            raise AssertionError("Invalid lookup must not reach the registry lock")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(fixture_loader, "_LOCK", Lock())
    with pytest.raises(ValueError, match="^invalid case selection$"):
        fixture_loader.load_fixture_set("synthetic-lookup", [False])
    with pytest.raises(ValueError, match="^duplicate selected cases$"):
        fixture_loader.load_fixture_set("synthetic-lookup", ["synthetic-case", "synthetic-case"])


def test_builtin_unicode_selection_preserves_order_hash_and_detached_results():
    identifier = "synthetic-lookup-한글"
    payload = {"cases": [
        {"caseId": "synthetic-가", "kind": "NORMAL"},
        {"caseId": "synthetic-나", "kind": "ATTACK"},
    ]}
    digest = fixture_loader.register_fixture_set(identifier, payload)
    selected = fixture_loader.load_fixture_set(identifier, ["synthetic-나", "synthetic-가"])
    assert selected["fixtureHash"] == digest
    assert [case["caseId"] for case in selected["cases"]] == ["synthetic-나", "synthetic-가"]
    assert selected["registeredPlannedCaseCount"] == 2
    assert selected["registeredSplitCaseCounts"] == {"DEV": 1, "TUNE": 0, "FINAL": 0, "NORMAL": 1}
    selected["cases"][0]["caseId"] = "synthetic-caller-change"
    assert fixture_loader.load_fixture_set(identifier)["cases"] == payload["cases"]
    empty = fixture_loader.load_fixture_set(identifier, [])
    assert empty["cases"] == []
    assert empty["fixtureHash"] == digest
    assert empty["registeredPlannedCaseCount"] == 2


def test_caller_selection_change_after_validation_cannot_change_the_lookup(monkeypatch):
    identifier = "synthetic-lookup-detached-selection"
    fixture_loader.register_fixture_set(identifier, {"cases": [
        {"caseId": "synthetic-first", "kind": "NORMAL"},
        {"caseId": "synthetic-second", "kind": "NORMAL"},
    ]})
    selection = ["synthetic-first"]
    original_lock = fixture_loader._LOCK

    class MutatingLock:
        def __enter__(self):
            original_lock.__enter__()
            selection[:] = ["synthetic-second"]

        def __exit__(self, *args):
            return original_lock.__exit__(*args)

    monkeypatch.setattr(fixture_loader, "_LOCK", MutatingLock())
    selected = fixture_loader.load_fixture_set(identifier, selection)
    assert selection == ["synthetic-second"]
    assert [case["caseId"] for case in selected["cases"]] == ["synthetic-first"]
