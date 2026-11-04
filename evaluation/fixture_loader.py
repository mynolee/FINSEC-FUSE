"""Explicit fixture registration; no private datasets are bundled or discovered."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from threading import RLock
from typing import Any

_REGISTRY: dict[str, dict] = {}
_LOCK = RLock()


_INVALID_JSON = "Invalid fixture JSON value"


def _copy_json(value: Any, active: set[int]) -> Any:
    kind = type(value)
    if value is None or kind in (str, bool, int):
        return value
    if kind is float:
        if not math.isfinite(value):
            raise ValueError(_INVALID_JSON)
        return value
    if kind not in (dict, list):
        raise ValueError(_INVALID_JSON)
    identity = id(value)
    if identity in active:
        raise ValueError(_INVALID_JSON)
    active.add(identity)
    try:
        if kind is list:
            return [_copy_json(item, active) for item in value]
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError(_INVALID_JSON)
            result[key] = _copy_json(item, active)
        return result
    finally:
        active.remove(identity)


def _json_copy(value: Any) -> Any:
    try:
        return _copy_json(value, set())
    except (ValueError, TypeError, RuntimeError):
        raise ValueError(_INVALID_JSON) from None


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(_json_copy(value), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RuntimeError, OverflowError):
        raise ValueError(_INVALID_JSON) from None


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _case_split(case: dict) -> str:
    value = case.get("split", "NORMAL" if case["kind"] == "NORMAL" else "DEV")
    value = "DEV" if value == "DEVELOPMENT" else value
    if value not in ("DEV", "TUNE", "FINAL", "NORMAL"):
        raise ValueError("unsupported split")
    return value


def register_fixture_set(fixture_set_id: str, payload: dict) -> str:
    """Pin caller-supplied, approved data; return its canonical full-plan hash."""
    if type(fixture_set_id) is not str or not fixture_set_id.strip():
        raise ValueError("fixture identifier is required")
    if type(payload) is not dict:
        raise ValueError(_INVALID_JSON)
    source = _json_copy(payload)
    if source.get("fixtureSetId", fixture_set_id) != fixture_set_id:
        raise ValueError("fixture identifier does not match")
    source["fixtureSetId"] = fixture_set_id
    declared_hash = source.pop("fixtureHash", None)
    cases = source.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("fixture cases are required")
    identifiers = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("caseId"), str) or not case["caseId"]:
            raise ValueError("invalid fixture case")
        if case.get("kind") not in ("ATTACK", "NORMAL"):
            raise ValueError("invalid fixture case kind")
        _case_split(case)
        identifiers.append(case["caseId"])
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("duplicate fixture cases")
    digest = fingerprint(source)
    if declared_hash is not None and declared_hash != digest:
        raise ValueError("fixture hash does not match")
    source["fixtureHash"] = digest
    with _LOCK:
        existing = _REGISTRY.get(fixture_set_id)
        if existing is not None and existing != source:
            raise ValueError("fixture registration is already pinned")
        _REGISTRY[fixture_set_id] = source
    return digest


def load_fixture_set(fixture_set_id: str, case_ids: list[str] | None = None) -> dict:
    # Reject caller-owned callback types before hashing under the registry lock.
    if type(fixture_set_id) is not str or not fixture_set_id.strip():
        raise ValueError("fixture identifier is required")
    if case_ids is not None:
        if type(case_ids) is not list:
            raise ValueError("invalid case selection")
        case_ids = case_ids.copy()
        if any(type(value) is not str for value in case_ids):
            raise ValueError("invalid case selection")
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("duplicate selected cases")
    with _LOCK:
        if fixture_set_id not in _REGISTRY:
            raise ValueError("fixture set is not registered")
        result = deepcopy(_REGISTRY[fixture_set_id])
    full_cases = result["cases"]
    result["registeredPlannedCaseCount"] = len(full_cases)
    result["registeredSplitCaseCounts"] = {
        split: sum(_case_split(c) == split for c in full_cases)
        for split in ("DEV", "TUNE", "FINAL", "NORMAL")
    }
    if case_ids is not None:
        lookup = {case["caseId"]: case for case in full_cases}
        if any(case_id not in lookup for case_id in case_ids):
            raise ValueError("case is not registered")
        result["cases"] = [lookup[case_id] for case_id in case_ids]
    return result
