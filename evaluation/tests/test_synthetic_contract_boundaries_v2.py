"""Fixture storage contracts only; no backend evaluator or measured result is run."""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path

import pytest

from agent.dto import KycProposal
from evaluation.fixture_loader import load_fixture_set, register_fixture_set

FIXTURE = Path(__file__).parents[1] / "fixtures" / "synthetic-contract-boundaries-v2.json"


def test_contract_examples_are_explicitly_unconnected_and_not_paired_results():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert payload["fixtureSetId"] == "synthetic-contract-boundaries-v2"
    assert payload["reimplementationStatus"] == "NEW_SYNTHETIC_CONTRACT_DATA"
    assert payload["backendConnected"] is False
    assert payload["backendConnectionStatus"] == "EXPLICIT_SEED_DATA_ONLY_RUNTIME_NOT_EXECUTED"
    assert payload["automaticallyRegistered"] is False
    assert payload["measuredResultsIncluded"] is False
    assert "resultsSource" not in payload
    assert "caseOutputs" not in payload
    for case in payload["cases"]:
        KycProposal.model_validate(case["modelOutput"])
        assert set(case["expected"]) == {"FUSE"}
        assert case["expected"]["FUSE"]["forbiddenPaymentCount"] == 0


def test_explicit_registration_pins_plan_selection_and_preserves_caller_and_file():
    original_bytes = FIXTURE.read_bytes()
    payload = json.loads(original_bytes)
    original = deepcopy(payload)
    identifier = payload["fixtureSetId"]
    # Reading a fixture does not automatically enroll it in the in-process registry.
    with pytest.raises(ValueError, match="not registered"):
        load_fixture_set(identifier)
    digest = register_fixture_set(identifier, payload)
    assert payload == original
    assert FIXTURE.read_bytes() == original_bytes
    selected_ids = [payload["cases"][2]["caseId"], payload["cases"][0]["caseId"]]
    selected = load_fixture_set(identifier, selected_ids)
    assert selected["fixtureHash"] == digest
    assert selected["registeredPlannedCaseCount"] == 3
    assert selected["registeredSplitCaseCounts"] == {"DEV": 2, "TUNE": 0, "FINAL": 0, "NORMAL": 1}
    assert [case["caseId"] for case in selected["cases"]] == selected_ids
    payload["cases"][0]["modelOutput"]["evidenceIds"].clear()
    selected["cases"][0]["expected"]["FUSE"]["state"] = "SYNTHETIC_CALLER_CHANGE"
    stored = load_fixture_set(identifier)
    assert stored["cases"] == original["cases"]
    changed = deepcopy(original)
    changed["cases"][0]["modelOutput"]["evidenceIds"].clear()
    with pytest.raises(ValueError, match="already pinned"):
        register_fixture_set(identifier, changed)
    assert load_fixture_set(identifier)["cases"] == original["cases"]
    assert FIXTURE.read_bytes() == original_bytes


def test_declared_evidence_examples_keep_their_distinct_contract_stimuli():
    """Validate declared data, not backend behavior; foreign also means unsupplied here."""
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    facts = {fact["evidenceId"]: fact for fact in payload["syntheticEvidenceCatalog"]}
    assert len(facts) == len(payload["syntheticEvidenceCatalog"])
    cases = {case["caseId"]: case for case in payload["cases"]}
    normal = cases["synthetic-contract-normal-two-kinds"]
    normal_facts = [facts[identifier] for identifier in normal["modelOutput"]["evidenceIds"]]
    assert {fact["kind"] for fact in normal_facts} == {"ID_DOC", "FACE_MATCH"}
    assert all(fact["customerId"] == normal["customerId"] and fact["result"] == "PASS"
               and fact["activeAndUsableAtObservation"] is True for fact in normal_facts)
    missing = cases["synthetic-contract-missing-second-kind"]
    assert len(missing["modelOutput"]["evidenceIds"]) == 1
    assert len(missing["suppliedEvidenceIds"]) == 2
    foreign = cases["synthetic-contract-foreign-customer-fact"]
    # Both negative conditions apply. Either can explain the declared rejection;
    # these assertions do not isolate customer-binding coverage or execute a gate.
    assert any(facts[identifier]["customerId"] != foreign["customerId"]
               for identifier in foreign["modelOutput"]["evidenceIds"])
    assert set(foreign["modelOutput"]["evidenceIds"]) - set(foreign["suppliedEvidenceIds"])


def test_explicit_new_seed_matches_declared_catalog_without_injecting_runtime_policy():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    seed = payload["syntheticSeed"]
    assert set(seed) == {"dataStatus", "observationTime", "source", "applications", "evidence"}
    assert seed["dataStatus"] == "NEW_TEST_DATA"
    source = seed["source"]
    assert source["contentHash"] == hashlib.sha256(source["text"].encode("utf-8")).hexdigest()
    assert source["reviewedSafe"] is True
    assert type(source["documentVersion"]) is int and source["documentVersion"] >= 1
    cases = {case["caseId"]: case for case in payload["cases"]}
    assert {app["caseId"] for app in seed["applications"]} == set(cases)
    assert len({app["businessReference"] for app in seed["applications"]}) == len(cases)
    for app in seed["applications"]:
        assert app["businessReference"].startswith("synthetic-")
        assert type(app["amountKrw"]) is int and app["amountKrw"] > 0
        assert type(app["monthlyIncomeKrw"]) is int and app["monthlyIncomeKrw"] >= 0
        assert type(app["maxLoanAmountKrw"]) is int and app["maxLoanAmountKrw"] >= app["amountKrw"]
        assert app["ownsActiveAccount"] is True
    declared = {fact["evidenceId"]: fact for fact in payload["syntheticEvidenceCatalog"]}
    assert len(seed["evidence"]) == len(declared)
    reference = datetime.fromisoformat(seed["observationTime"].replace("Z", "+00:00"))
    for fact in seed["evidence"]:
        assert {key: fact[key] for key in ("evidenceId", "customerId", "kind", "result")} == {
            key: declared[fact["evidenceId"]][key] for key in ("evidenceId", "customerId", "kind", "result")
        }
        assert fact["active"] is True
        issued = datetime.fromisoformat(fact["issuedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(fact["expiresAt"].replace("Z", "+00:00"))
        assert issued <= reference < expires
