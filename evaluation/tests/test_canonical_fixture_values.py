"""Synthetic JSON value-algebra boundaries; no original fixture data is used."""
import hashlib

import pytest

from evaluation.fixture_loader import canonical_bytes, fingerprint, load_fixture_set, register_fixture_set


def test_builtin_json_numbers_unicode_and_shared_acyclic_values_keep_canonical_bytes():
    shared = [True, None, -0.0]
    source = {"unicode": "한글😀", "integer": 7, "float": 1.5, "array": shared}
    expected = '{"array":[true,null,-0.0],"float":1.5,"integer":7,"unicode":"한글😀"}'.encode("utf-8")
    assert canonical_bytes(source) == expected
    assert fingerprint(source) == hashlib.sha256(expected).hexdigest()
    assert canonical_bytes([shared, shared]) == b"[[true,null,-0.0],[true,null,-0.0]]"
    assert source["array"] is shared
    assert fingerprint(True) != fingerprint(1)
    assert canonical_bytes([1, 2]) == b"[1,2]"


@pytest.mark.parametrize("key", [1, True, None, 1.5])
def test_nonstring_keys_cannot_alias_valid_string_json_keys(key):
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        canonical_bytes({key: "synthetic-value"})
    assert canonical_bytes({"1": "synthetic-value"}) == b'{"1":"synthetic-value"}'


def test_mixed_numeric_and_string_keys_are_rejected_without_exposing_values():
    with pytest.raises(ValueError) as failure:
        canonical_bytes({1: "SYNTHETIC_MARKER", "1": "other"})
    assert str(failure.value) == "Invalid fixture JSON value"
    assert failure.value.__cause__ is None


@pytest.mark.parametrize("value", [(1, 2), {1, 2}, b"synthetic", float("inf"), float("nan")])
def test_non_json_values_and_nonfinite_numbers_are_rejected(value):
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        fingerprint({"nested": value})


def test_custom_container_and_numeric_callbacks_are_never_invoked():
    class CustomDict(dict):
        def items(self):
            raise AssertionError("Custom items callback must not execute")

        def __deepcopy__(self, memo):
            raise AssertionError("Custom deepcopy callback must not execute")

    class CustomNumber(int):
        def __deepcopy__(self, memo):
            raise AssertionError("Custom numeric deepcopy callback must not execute")

        def __str__(self):
            raise AssertionError("Custom numeric string callback must not execute")

    class CustomList(list):
        def __iter__(self):
            raise AssertionError("Custom list iteration must not execute")

    class CustomText(str):
        def __str__(self):
            raise AssertionError("Custom text callback must not execute")

    for value in (CustomDict(), CustomNumber(1), CustomList(), CustomText("synthetic")):
        with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
            canonical_bytes({"nested": value})
        with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
            register_fixture_set("synthetic-hostile-json", {
                "cases": [{"caseId": "synthetic-case", "kind": "NORMAL"}], "nested": value,
            })
    with pytest.raises(ValueError, match="not registered"):
        load_fixture_set("synthetic-hostile-json")
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        register_fixture_set("synthetic-hostile-root", CustomDict())


def test_unsupported_payload_cannot_change_an_existing_registration():
    identifier = "synthetic-pinned-json-algebra"
    register_fixture_set(identifier, {"cases": [{"caseId": "synthetic-case", "kind": "NORMAL"}]})
    before = load_fixture_set(identifier)
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        register_fixture_set(identifier, {
            "cases": [{"caseId": "synthetic-case", "kind": "NORMAL"}], "nonJson": (1, 2),
        })
    assert load_fixture_set(identifier) == before


def test_cycles_are_fixed_failures_and_never_partially_register():
    value = []
    value.append(value)
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        canonical_bytes(value)
    payload = {"cases": [{"caseId": "synthetic-case", "kind": "NORMAL"}]}
    payload["cycle"] = payload
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        register_fixture_set("synthetic-cycle-json", payload)
    with pytest.raises(ValueError, match="not registered"):
        load_fixture_set("synthetic-cycle-json")


def test_invalid_unicode_encoding_is_a_fixed_error_before_registration():
    payload = {"cases": [{"caseId": "synthetic-case", "kind": "NORMAL"}], "text": "\ud800"}
    with pytest.raises(ValueError, match="^Invalid fixture JSON value$"):
        register_fixture_set("synthetic-surrogate-json", payload)
    with pytest.raises(ValueError, match="not registered"):
        load_fixture_set("synthetic-surrogate-json")
