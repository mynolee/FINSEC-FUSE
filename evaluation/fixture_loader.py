"""Strict immutable registry loader and reproducible fixture fingerprints."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any

from agent.dto import KycProposal, strict_json_loads

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures"
REGISTERED_SETS = {"mvp-security-v1", "security-evaluation-v1"}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode()


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_fixture_set(fixture_set_id: str, case_ids: list[str] | None = None) -> dict:
    if fixture_set_id not in REGISTERED_SETS:
        raise ValueError("unregistered fixture set")
    manifest = strict_json_loads((FIXTURE_DIRECTORY / f"{fixture_set_id}.json").read_bytes())
    if manifest["fixtureSetId"] != fixture_set_id:
        raise ValueError("fixture set binding mismatch")
    cases = manifest["cases"]
    ids = [row["caseId"] for row in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate fixture IDs")
    for row in cases:
        KycProposal.model_validate(row["modelOutput"])
        if row["kind"] not in {"ATTACK", "NORMAL"} or row["amountKrw"] <= 0:
            raise ValueError("invalid fixture")
        if row["injection"]["source"] not in {"TEST_HARNESS", "UNTRUSTED_RAG", "REGISTERED_FIXTURE"}:
            raise ValueError("unlabeled injection source")
    if case_ids:
        if len(set(case_ids)) != len(case_ids) or set(case_ids) - set(ids):
            raise ValueError("duplicate or unregistered case ID")
        selected = [next(row for row in cases if row["caseId"] == case_id) for case_id in case_ids]
    else:
        selected = cases
    return {**manifest, "fixtureHash": fingerprint(manifest), "cases": selected}
