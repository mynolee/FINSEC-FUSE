"""New synthetic public contracts; no original fixtures or private reports are loaded."""
from copy import deepcopy
import csv
import io
import json
from pathlib import Path

import pytest

from evaluation import export as public_export
from evaluation import export_cli, export_provider
from evaluation.fixture_loader import fingerprint, load_fixture_set, register_fixture_set
from evaluation.report import CaseOutput, EvaluationReport
from evaluation.trace_sanitizer import sanitize_trace

HASH = "a" * 64
MARKER = "SYNTHETIC_UNTRUSTED_MARKER_MUST_NOT_EXPORT"


def fixture_plan(case_id="SYNTHETIC_NORMAL"):
    return {"fixtureSetId": "synthetic-public-v1", "fixtureHash": HASH, "cases": [{
        "caseId": case_id, "kind": "NORMAL", "split": "NORMAL", "family": "SYNTHETIC",
        "expected": {env: {"state": "WAIT_APPROVAL", "decision": "WAIT_APPROVAL"}
                     for env in ("BASELINE", "FUSE")},
    }]}


def report_for(plan=None, *, row_overrides=None):
    plan = fixture_plan() if plan is None else plan
    outputs = []
    for environment in ("BASELINE", "FUSE"):
        fields = dict(
            caseId=plan["cases"][0]["caseId"], environment=environment, repeat=1,
            status="COMPLETED", state="WAIT_APPROVAL", decision="WAIT_APPROVAL",
            reasonCodes=[], attackInduced=False, policyBlocked=False,
            forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0, actualDownstreamDepth=0,
            normalExpectedReached=True, unrelatedNormalExpected=0, unrelatedNormalCompleted=0,
            exclusionReason=None, fixtureHash=HASH, pairedInputVersion="FUSE-PAIRED-INPUT-1",
            pairedInputHash=HASH, inputSnapshotHash=HASH, responseByteHash=HASH,
            modelOutputHash=HASH, model="replay", promptVersion="KYC-PROMPT-1",
            policyVersion="FUSE-MVP-2", mockReviewerVersion="MOCK-REVIEWER-1",
            trace={"traceId": "11111111-1111-4111-8111-111111111111",
                   "request": {"authorization": MARKER}, "documents": [{"text": MARKER}],
                   "documentText": MARKER, "authorization": MARKER},
        )
        fields.update(row_overrides or {})
        outputs.append(CaseOutput(**fields))
    return EvaluationReport(
        experimentId="synthetic-public-export", fixtureSetId=plan["fixtureSetId"], fixtureHash=HASH,
        status="COMPLETED", modelMode="REPLAY", resultsSource="JAVA_POSTGRES_EXECUTION",
        syntheticModelOutputs=True, liveRobustnessMeasured=False,
        plannedCaseIds=[plan["cases"][0]["caseId"]], repeatCount=1, caseOutputs=outputs,
        metrics={}, limitations=["Synthetic only: no Java, database or real model execution."],
    )


def test_synthetic_bundle_is_deterministic_and_has_no_raw_trace(tmp_path):
    report, plan = report_for(), fixture_plan()
    folder = export_provider.export_evidence_bundle(report, plan, tmp_path)
    assert {p.name for p in folder.iterdir()} == {
        "manifest.json", "case_results.json", "case_results.csv", "metrics.json"}
    first = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert json.loads(first["manifest.json"])["bundleVersion"] == "FUSE-EVIDENCE-BUNDLE-2"
    assert MARKER.encode() not in b"".join(first.values())
    rows = json.loads(first["case_results.json"])
    assert [r["environment"] for r in rows] == ["BASELINE", "FUSE"]
    assert all(r["includedInCommonDenominator"] for r in rows)
    csv_rows = list(csv.DictReader(io.StringIO(first["case_results.csv"].decode())))
    assert json.loads(csv_rows[0]["actualReasonCodes"]) == rows[0]["actualReasonCodes"]
    assert json.loads(csv_rows[0]["securityCheckDurationMs"]) is None
    assert export_provider.export_evidence_bundle(report, plan, tmp_path) == folder
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == first


@pytest.mark.parametrize("field", ["exclusionReason", "model", "pairedInputVersion"])
def test_free_metadata_never_appears_in_any_artifact(tmp_path, field):
    report = report_for(row_overrides={field: MARKER})
    folder = export_provider.export_evidence_bundle(report, fixture_plan(), tmp_path)
    assert all(MARKER.encode() not in p.read_bytes() for p in folder.iterdir())


def test_excluded_case_identifier_is_removed_from_metrics_too(tmp_path):
    plan = fixture_plan(MARKER)
    report = report_for(plan, row_overrides={"exclusionReason": "ENVIRONMENT_ERROR"})
    folder = export_provider.export_evidence_bundle(report, plan, tmp_path)
    assert all(MARKER.encode() not in p.read_bytes() for p in folder.iterdir())
    rows = json.loads((folder / "case_results.json").read_text())
    assert all(row["includedInCommonDenominator"] is False for row in rows)
    assert all(row["commonExclusionReason"] == "ENVIRONMENT_ERROR" for row in rows)


@pytest.mark.parametrize("field,value", [
    ("inputReportVersion", MARKER),
    ("registeredPlannedCaseCount", {"private": MARKER}),
    ("registeredPlannedCaseCount", MARKER),
    ("registeredPlannedCaseCount", True),
    ("registeredSplitCaseCounts", {"DEV": MARKER}),
    ("registeredSplitCaseCounts", {"DEV": 0, "TUNE": 0, "FINAL": 0, "NORMAL": True}),
])
def test_unsupported_versions_and_non_numeric_count_metadata_are_rejected(tmp_path, field, value):
    report, plan = report_for(), fixture_plan()
    if field == "inputReportVersion":
        report = report.model_copy(update={field: value})
    else:
        plan[field] = value
    output = tmp_path / "not-created"
    with pytest.raises(ValueError):
        export_provider.export_evidence_bundle(report, plan, output)
    assert not output.exists()


def test_missing_arm_is_not_a_successful_zero(tmp_path):
    report = report_for()
    report = report.model_copy(update={"caseOutputs": report.caseOutputs[:1]})
    folder = export_provider.export_evidence_bundle(report, fixture_plan(), tmp_path)
    rows = json.loads((folder / "case_results.json").read_text())
    assert rows[1]["observationStatus"] == "NOT_RUN"
    assert rows[1]["sanitizedResultHash"] is None
    assert all(not row["includedInCommonDenominator"] for row in rows)
    assert all(row["commonExclusionReason"] == "INCOMPLETE_PAIR" for row in rows)


def test_modified_existing_bundle_is_preserved(tmp_path):
    report, plan = report_for(), fixture_plan()
    folder = export_provider.export_evidence_bundle(report, plan, tmp_path)
    marker = folder / "case_results.json"
    marker.write_text("synthetic preexisting altered bytes")
    with pytest.raises(ValueError):
        export_provider.export_evidence_bundle(report, plan, tmp_path)
    assert marker.read_text() == "synthetic preexisting altered bytes"


def test_registered_full_plan_hash_is_unchanged_by_selection():
    payload = {"fixtureSetId": "synthetic-registry-contract", "cases": [
        {"caseId": "SYNTHETIC_NORMAL", "kind": "NORMAL", "split": "NORMAL"},
        {"caseId": "SYNTHETIC_ATTACK", "kind": "ATTACK", "split": "DEV"},
    ]}
    digest = register_fixture_set(payload["fixtureSetId"], payload)
    selected = load_fixture_set(payload["fixtureSetId"], ["SYNTHETIC_ATTACK"])
    assert selected["fixtureHash"] == digest
    assert selected["registeredPlannedCaseCount"] == 2
    assert [c["caseId"] for c in selected["cases"]] == ["SYNTHETIC_ATTACK"]
    selected["cases"][0]["caseId"] = "mutated-caller-copy"
    assert load_fixture_set(payload["fixtureSetId"])["cases"][1]["caseId"] == "SYNTHETIC_ATTACK"
    with pytest.raises(ValueError):
        load_fixture_set(payload["fixtureSetId"], ["SYNTHETIC_ATTACK", "SYNTHETIC_ATTACK"])
    with pytest.raises(ValueError):
        load_fixture_set(payload["fixtureSetId"], ["not-registered"])
    changed = deepcopy(payload)
    changed["cases"].pop()
    with pytest.raises(ValueError):
        register_fixture_set(payload["fixtureSetId"], changed)


def test_cli_explicitly_pins_provider_and_preserves_validation_status(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(public_export, "_provider", None)
    monkeypatch.setattr(public_export, "_cli", None)
    assert export_cli.configure_public_exporter() is export_provider
    assert public_export.export_evidence_bundle is export_provider.export_evidence_bundle
    assert export_cli.main(["--unknown", MARKER]) == 2
    captured = capsys.readouterr()
    assert MARKER not in captured.out + captured.err
    assert captured.out == ""


def test_cli_success_writes_bundle_via_the_same_callback(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(public_export, "_provider", None)
    monkeypatch.setattr(public_export, "_cli", None)
    report_path, manifest_path = tmp_path / "report.json", tmp_path / "plan.json"
    report_path.write_text(report_for().model_dump_json())
    manifest_path.write_text(json.dumps(fixture_plan()))
    assert export_cli.main(["--report", str(report_path), "--manifest", str(manifest_path),
                            "--output", str(tmp_path / "bundles")]) == 0
    assert (tmp_path / "bundles/synthetic-public-export/manifest.json").is_file()
    assert capsys.readouterr().out == ""


def test_local_json_loader_rejects_duplicate_keys_without_agent_http_setup(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"value":1,"value":2}')
    with pytest.raises(ValueError):
        export_provider._strict_json(path)


def test_sanitizer_preserves_only_known_metadata():
    source = {"request": {"body": MARKER}, "authorization": MARKER, "documentText": MARKER,
              "armBindings": {"responseByteHash": HASH, "bindingVerified": True, "requestBytes": MARKER},
              "modelCapture": {"sanitizedCandidate": {"status": "VERIFIED",
                                                       "evidenceIds": ["11111111-1111-4111-8111-111111111111"],
                                                       "explanation": MARKER}},
              "quarantineMeasurement": {"elapsedNanos": 12, "leaseToken": MARKER}}
    value = sanitize_trace(source)
    assert MARKER not in json.dumps(value)
    assert "sourceTraceHash" not in value
    assert value["sanitizedTraceHash"] == fingerprint({
        key: item for key, item in value.items() if key != "sanitizedTraceHash"
    })
    assert value["armBindings"]["responseByteHash"] == HASH
    assert value["quarantineMeasurement"]["elapsedNanos"] == 12


def test_excluded_original_content_does_not_affect_public_fingerprints(tmp_path):
    plan = fixture_plan()
    report = report_for(plan)
    changed_plan = deepcopy(plan)
    changed_plan["cases"][0]["unexportedText"] = "synthetic-omitted-plan-text"
    changed_report = report.model_copy(update={
        "limitations": ["synthetic-omitted-report-text"],
        "metrics": {"unexportedText": "synthetic-omitted-metric-text"},
        "caseOutputs": [row.model_copy(update={"trace": {
            **row.trace, "request": {"body": "synthetic-omitted-request-text"},
        }}) for row in report.caseOutputs],
    })
    original = export_provider.export_evidence_bundle(report, plan, tmp_path / "first")
    changed = export_provider.export_evidence_bundle(changed_report, changed_plan, tmp_path / "second")
    assert {p.name: p.read_bytes() for p in original.iterdir()} == {
        p.name: p.read_bytes() for p in changed.iterdir()
    }
    manifest = json.loads((original / "manifest.json").read_text())
    assert "sourceReportHash" not in manifest
    assert "selectedFixturePlanHash" not in manifest
    assert "sanitizedReportHash" in manifest
    assert "sanitizedFixturePlanHash" in manifest
    rows = json.loads((original / "case_results.json").read_text())
    metrics = json.loads((original / "metrics.json").read_text())
    assert manifest["sanitizedReportHash"] == fingerprint({
        "manifest": {key: value for key, value in manifest.items() if key != "sanitizedReportHash"},
        "caseResults": rows, "metrics": metrics,
    })
    plan_fields = ("caseId", "kind", "split", "family", "environment",
                   "expectedEndState", "expectedDecision", "expectedReasonCode",
                   "expectedReasonEvidenceType")
    assert manifest["sanitizedFixturePlanHash"] == fingerprint([
        {key: row[key] for key in plan_fields} for row in rows if row["repeat"] == 1
    ])
    assert all("sourceResultHash" not in row for row in rows)
    for row in rows:
        assert row["sanitizedResultHash"] == fingerprint({
            key: value for key, value in row.items() if key != "sanitizedResultHash"
        })


def test_unknown_cases_keep_unique_public_identities_and_exclusion_mapping(tmp_path):
    plan = fixture_plan()
    unknown_ids = ["synthetic-omitted-case-alpha", "synthetic-omitted-case-beta"]
    for case_id in unknown_ids:
        case = deepcopy(plan["cases"][0])
        case.update(caseId=case_id, split="DEV", family="synthetic-omitted-family")
        plan["cases"].append(case)
    report = report_for()
    outputs = list(report.caseOutputs)
    outputs.extend(row.model_copy(update={
        "caseId": unknown_ids[0], "status": "ERROR", "decision": "ERROR",
    }) for row in report.caseOutputs)
    outputs.append(report.caseOutputs[0].model_copy(update={"caseId": unknown_ids[1]}))
    report = report.model_copy(update={
        "plannedCaseIds": [case["caseId"] for case in plan["cases"]], "caseOutputs": outputs,
    })
    folder = export_provider.export_evidence_bundle(report, plan, tmp_path / "first")
    rows = json.loads((folder / "case_results.json").read_text())
    assert [row["caseId"] for row in rows] == [
        "SYNTHETIC_NORMAL", "SYNTHETIC_NORMAL", "PUBLIC_CASE_1", "PUBLIC_CASE_1",
        "PUBLIC_CASE_2", "PUBLIC_CASE_2",
    ]
    metrics = json.loads((folder / "metrics.json").read_text())
    expected_exclusions = [
        {"caseId": "PUBLIC_CASE_1", "repeat": 1, "reason": "ENVIRONMENT_ERROR"},
        {"caseId": "PUBLIC_CASE_2", "repeat": 1, "reason": "INCOMPLETE_PAIR"},
    ]
    assert metrics["overall"]["exclusions"] == expected_exclusions
    assert metrics["bySplit"]["DEV"]["exclusions"] == expected_exclusions
    assert metrics["overall"]["plannedNormals"] == 3
    assert metrics["overall"]["commonEligibleNormalPairs"] == 1
    assert metrics["overall"]["excludedPairCount"] == 2
    assert all(row["family"] is None for row in rows[2:])

    renamed_plan = deepcopy(plan)
    replacements = dict(zip(unknown_ids, ["synthetic-other-omitted-one", "synthetic-other-omitted-two"]))
    for case in renamed_plan["cases"]:
        case["caseId"] = replacements.get(case["caseId"], case["caseId"])
    renamed_report = report.model_copy(update={
        "plannedCaseIds": [case["caseId"] for case in renamed_plan["cases"]],
        "caseOutputs": [row.model_copy(update={"caseId": replacements.get(row.caseId, row.caseId)})
                        for row in report.caseOutputs],
    })
    renamed = export_provider.export_evidence_bundle(renamed_report, renamed_plan, tmp_path / "second")
    original_bytes = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert original_bytes == {p.name: p.read_bytes() for p in renamed.iterdir()}
    for identifier in unknown_ids:
        assert identifier.encode() not in b"".join(original_bytes.values())
        assert fingerprint(identifier).encode() not in b"".join(original_bytes.values())


def test_exported_outcome_projection_does_not_mutate_source_report(tmp_path):
    identifier = "11111111-1111-4111-8111-111111111111"
    trace = {
        "workflowId": identifier, "traceId": identifier, "generation": 1,
        "auditEvents": [{"id": "10000000-0000-4000-8000-00000000000A",
                         "actionId": identifier, "runId": identifier,
                         "eventType": "LATE_RESULT_DISCARDED", "reasonCode": "WORKFLOW_CHANGED"}],
        "runs": [{"runId": identifier, "generation": 1, "role": "KYC",
                  "status": "BLOCKED", "inputSnapshotHash": HASH}],
        "payments": [], "results": [], "riskEvents": [],
        "armBindings": [{"workflowId": identifier, "runId": identifier,
                         "requestId": identifier, "generation": 1,
                         "bindingVerified": True, "inputSnapshotHash": HASH}],
    }
    report = report_for(row_overrides={"state": "BLOCKED", "decision": "DENY", "trace": trace})
    before = deepcopy(report.model_dump())
    folder = export_provider.export_evidence_bundle(report, fixture_plan(), tmp_path)
    rows = json.loads((folder / "case_results.json").read_text())
    assert all(len(row["actualOutcomeEvents"]) == 1 for row in rows)
    assert all(row["actualOutcomeEvents"][0]["eventId"] is None for row in rows)
    assert report.model_dump() == before
