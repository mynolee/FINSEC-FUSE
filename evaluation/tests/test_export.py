"""Export unit tests use explicit synthetic inputs, never claim service execution."""
import copy
import csv
import hashlib
import json
from pathlib import Path

import pytest

from evaluation.export import calculate_split_metrics, export_evidence_bundle, sanitize_trace, _expected_match
from evaluation.fixture_loader import fingerprint, load_fixture_set
from evaluation.metrics import calculate_metrics
from evaluation.report import CaseOutput, EvaluationReport


UUID = "00000000-0000-4000-8000-000000000001"


def outcome_actual(event_type):
    """Synthetic persisted-trace shape; never derives observations from a fixture."""
    run, action, event, payment, reservation, consume, reserve = [f"00000000-0000-4000-8000-{number:012d}" for number in range(2, 9)]
    paid = event_type == "PAYMENT_COMMITTED"
    return {"status": "COMPLETED", "state": "PAID" if paid else "BLOCKED",
            "decision": "ALLOW" if paid else "DENY", "reasonCodes": [] if paid else ["QUARANTINED"],
            "forbiddenPaymentCount": 0, "inputSnapshotHash": "c" * 64,
            "trace": {"workflowId": UUID, "traceId": UUID, "generation": 1,
                "auditEvents": [{"id": event, "actionId": action, "runId": run, "eventType": event_type,
                                 "reasonCode": None if paid else "WORKFLOW_CHANGED"}],
                "runs": [{"runId": run, "generation": 1, "inputSnapshotHash": "c" * 64, "role": "PAYMENT" if paid else "KYC",
                          "status": "SUCCEEDED" if paid else "BLOCKED"}],
                "payments": [{"paymentId": payment, "actionId": action, "generation": 1, "amountKrw": 500000}] if paid else [],
                "riskEvents": [{"id": identifier, "eventType": kind, "stage": "PAYMENT", "actionId": action,
                                "runId": run, "generation": 1, "reservationId": reservation, "points": 50}
                               for identifier, kind in ((consume, "CONSUME"), (reserve, "RESERVE"))] if paid else [],
                "results": [], "armBindings": [{"workflowId": UUID, "runId": run, "requestId": action,
                                                  "generation": 1, "inputSnapshotHash": "c" * 64, "bindingVerified": True}]}}


@pytest.mark.parametrize("event_type,state", [("PAYMENT_COMMITTED", "PAID"), ("LATE_RESULT_DISCARDED", "BLOCKED")])
def test_expected_audit_outcomes_match_real_typed_trace_evidence(event_type, state):
    actual = outcome_actual(event_type)
    assert event_type not in actual["reasonCodes"]
    assert _expected_match({"state": state, "reasonCode": event_type, "forbiddenPaymentCount": 0}, actual) is True


@pytest.mark.parametrize("event_type", ["PAYMENT_COMMITTED", "LATE_RESULT_DISCARDED"])
@pytest.mark.parametrize("mutation", ["absent", "nested_decoy", "wrong_field", "missing_workflow", "mismatched_trace",
    "missing_event_id", "missing_action", "missing_run", "unmatched_run", "old_run_generation", "invalid_generation",
    "wrong_run_role", "wrong_run_status", "wrong_state", "wrong_decision", "wrong_payment_count"])
def test_expected_audit_outcomes_reject_decoys_or_nonmatching_identity(event_type, mutation):
    actual = outcome_actual(event_type)
    expected = {"state": actual["state"], "reasonCode": event_type, "forbiddenPaymentCount": 0}
    trace = actual["trace"]
    event = trace["auditEvents"][0]
    if mutation == "absent":
        trace["auditEvents"] = []
        actual["reasonCodes"] = [event_type]  # A decision label cannot substitute for the event.
    elif mutation == "nested_decoy":
        trace["modelOutput"] = {"auditEvents": trace.pop("auditEvents")}
    elif mutation == "wrong_field":
        event["reasonCode"] = event.pop("eventType")
    elif mutation == "missing_workflow":
        trace.pop("workflowId")
    elif mutation == "mismatched_trace":
        trace["traceId"] = "00000000-0000-4000-8000-000000000099"
    elif mutation == "missing_event_id":
        event.pop("id")
    elif mutation == "missing_action":
        event.pop("actionId")
    elif mutation == "missing_run":
        event.pop("runId")
    elif mutation == "unmatched_run":
        event["runId"] = "00000000-0000-4000-8000-000000000099"
    elif mutation == "old_run_generation":
        trace["runs"][0]["generation"] = 2
    elif mutation == "invalid_generation":
        trace["generation"] = True
    elif mutation == "wrong_run_role":
        trace["runs"][0]["role"] = "LOAN"
    elif mutation == "wrong_run_status":
        trace["runs"][0]["status"] = "RUNNING"
    elif mutation == "wrong_state":
        actual["state"] = "ON_HOLD"
    elif mutation == "wrong_decision":
        actual["decision"] = "ERROR"
    elif mutation == "wrong_payment_count":
        actual["forbiddenPaymentCount"] = 1
    assert _expected_match(expected, actual) is False


@pytest.mark.parametrize("mutation", ["missing_ledger", "empty_ledger", "mismatched_action", "old_generation",
                                     "missing_payment_id", "zero_amount", "duplicate_payment"])
def test_committed_payment_expectation_requires_correlated_ledger(mutation):
    actual = outcome_actual("PAYMENT_COMMITTED")
    trace = actual["trace"]
    if mutation == "missing_ledger": trace.pop("payments")
    elif mutation == "empty_ledger": trace["payments"] = []
    elif mutation == "mismatched_action": trace["payments"][0]["actionId"] = "00000000-0000-4000-8000-000000000099"
    elif mutation == "old_generation": trace["payments"][0]["generation"] = 2
    elif mutation == "missing_payment_id": trace["payments"][0].pop("paymentId")
    elif mutation == "zero_amount": trace["payments"][0]["amountKrw"] = 0
    elif mutation == "duplicate_payment": trace["payments"].append(copy.deepcopy(trace["payments"][0]))
    assert _expected_match({"state": "PAID", "reasonCode": "PAYMENT_COMMITTED"}, actual) is False


@pytest.mark.parametrize("mutation", ["missing_risk", "missing_consume", "missing_reserve", "wrong_action", "wrong_run",
    "old_generation", "wrong_stage", "wrong_points", "zero_points", "wrong_reservation", "duplicate_consume", "substituted_run"])
def test_payment_action_must_be_bound_to_its_run_by_actual_risk_consumption(mutation):
    actual = outcome_actual("PAYMENT_COMMITTED")
    trace = actual["trace"]
    consume = trace["riskEvents"][0]
    other = "00000000-0000-4000-8000-000000000099"
    if mutation == "missing_risk": trace.pop("riskEvents")
    elif mutation == "missing_consume": trace["riskEvents"].pop(0)
    elif mutation == "missing_reserve": trace["riskEvents"].pop(1)
    elif mutation == "wrong_action": consume["actionId"] = other
    elif mutation == "wrong_run": consume["runId"] = other
    elif mutation == "old_generation": consume["generation"] = 2
    elif mutation == "wrong_stage": consume["stage"] = "KYC"
    elif mutation == "wrong_points": consume["points"] = 49
    elif mutation == "zero_points": consume["points"] = 0
    elif mutation == "wrong_reservation": consume["reservationId"] = other
    elif mutation == "duplicate_consume": trace["riskEvents"].append(copy.deepcopy(consume))
    elif mutation == "substituted_run":
        trace["runs"].append({**trace["runs"][0], "runId": other})
        trace["auditEvents"][0]["runId"] = other
    assert _expected_match({"state": "PAID", "reasonCode": "PAYMENT_COMMITTED"}, actual) is False


@pytest.mark.parametrize("mutation", ["missing_payments", "payment_present", "missing_results", "result_present",
    "missing_binding", "wrong_action", "wrong_workflow", "old_generation", "unverified", "wrong_reason",
    "missing_binding_hash", "wrong_binding_hash", "missing_run_hash", "wrong_run_hash", "wrong_row_hash", "duplicate_binding"])
def test_late_result_expectation_requires_exact_discarded_candidate_binding(mutation):
    actual = outcome_actual("LATE_RESULT_DISCARDED")
    trace = actual["trace"]
    if mutation == "missing_payments": trace.pop("payments")
    elif mutation == "payment_present": trace["payments"] = outcome_actual("PAYMENT_COMMITTED")["trace"]["payments"]
    elif mutation == "missing_results": trace.pop("results")
    elif mutation == "result_present": trace["results"] = [{"runId": trace["runs"][0]["runId"], "status": "VALIDATED"}]
    elif mutation == "missing_binding": trace.pop("armBindings")
    elif mutation == "wrong_action": trace["armBindings"][0]["requestId"] = "00000000-0000-4000-8000-000000000099"
    elif mutation == "wrong_workflow": trace["armBindings"][0]["workflowId"] = "00000000-0000-4000-8000-000000000099"
    elif mutation == "old_generation": trace["armBindings"][0]["generation"] = 2
    elif mutation == "unverified": trace["armBindings"][0]["bindingVerified"] = False
    elif mutation == "wrong_reason": trace["auditEvents"][0]["reasonCode"] = "STALE_LEASE"
    elif mutation == "missing_binding_hash": trace["armBindings"][0].pop("inputSnapshotHash")
    elif mutation == "wrong_binding_hash": trace["armBindings"][0]["inputSnapshotHash"] = "d" * 64
    elif mutation == "missing_run_hash": trace["runs"][0].pop("inputSnapshotHash")
    elif mutation == "wrong_run_hash": trace["runs"][0]["inputSnapshotHash"] = "d" * 64
    elif mutation == "wrong_row_hash": actual["inputSnapshotHash"] = "d" * 64
    elif mutation == "duplicate_binding": trace["armBindings"].append(copy.deepcopy(trace["armBindings"][0]))
    assert _expected_match({"state": "BLOCKED", "reasonCode": "LATE_RESULT_DISCARDED"}, actual) is False


def test_ordinary_decision_reason_cannot_be_satisfied_by_an_audit_event():
    actual = outcome_actual("LATE_RESULT_DISCARDED")
    actual["reasonCodes"] = []
    actual["trace"]["auditEvents"][0]["eventType"] = "EVIDENCE_MISSING"
    assert _expected_match({"state": "BLOCKED", "reasonCode": "EVIDENCE_MISSING"}, actual) is False


@pytest.mark.parametrize("event_type,case_id", [("PAYMENT_COMMITTED", "N_NORMAL_PAYMENT_01"),
                                               ("LATE_RESULT_DISCARDED", "A_QUARANTINE_BYPASS_05")])
def test_export_exposes_typed_witness_without_changing_actual_decision_reasons(tmp_path, event_type, case_id):
    manifest = load_fixture_set("security-evaluation-v1", [case_id])
    actual = outcome_actual(event_type)
    actual["trace"]["auditEvents"][0]["detailsJson"] = {"text": "PRIVATE_EVENT_DETAILS_MUST_NOT_EXPORT"}
    rows = [observed(manifest["cases"][0], environment, manifest["fixtureHash"], **actual)
            for environment in ("BASELINE", "FUSE")]
    path = export_evidence_bundle(report_for(manifest, rows), manifest, tmp_path)
    exported = read(path, "case_results.json")[1]
    assert exported["expectedMatch"] is True
    assert exported["expectedReasonEvidenceType"] == "AUDIT_EVENT"
    assert exported["actualReasonCodes"] == actual["reasonCodes"]
    witness, = exported["actualOutcomeEvents"]
    event = actual["trace"]["auditEvents"][0]
    assert witness["eventType"] == event_type
    assert witness["eventId"] == event["id"]
    assert witness["actionId"] == event["actionId"]
    assert witness["runId"] == event["runId"]
    assert witness["workflowId"] == UUID and witness["generation"] == 1
    assert set(witness) == {"eventType", "eventId", "actionId", "runId", "workflowId", "generation"} | (
        {"paymentId", "consumeEventId", "reserveEventId", "reservationId"} if event_type == "PAYMENT_COMMITTED" else {"inputSnapshotHash"})
    with (path / "case_results.csv").open(newline="") as source:
        csv_row = list(csv.DictReader(source))[1]
    assert json.loads(csv_row["actualOutcomeEvents"]) == exported["actualOutcomeEvents"]
    assert b"PRIVATE_EVENT_DETAILS_MUST_NOT_EXPORT" not in b"\n".join(file.read_bytes() for file in path.rglob("*") if file.is_file())


def observed(case, environment, fixture_hash, **changes):
    value = dict(caseId=case["caseId"], environment=environment, repeat=1,
        status="COMPLETED", state="PAID" if case["kind"] == "NORMAL" else "BLOCKED",
        decision="ALLOW" if case["kind"] == "NORMAL" else "DENY",
        reasonCodes=["PAYMENT_COMMITTED"] if case["kind"] == "NORMAL" else ["EVIDENCE_MISSING"],
        attackInduced=case["kind"] == "ATTACK", policyBlocked=case["kind"] == "ATTACK",
        forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0, actualDownstreamDepth=0,
        normalExpectedReached=True if case["kind"] == "NORMAL" else None,
        unrelatedNormalExpected=0, unrelatedNormalCompleted=0, securityCheckDurationMs=None,
        quarantineLatencyMs=None, trace={"workflowId": UUID, "traceId": UUID, "usedRisk": 10,
            "reservedRisk": 0, "payments": [], "armBindings": [{"bindingId": UUID, "requestId": UUID,
            "workflowId": UUID, "runId": UUID, "generation": 1, "inputSnapshotHash": "c" * 64,
            "requestByteHash": "d" * 64, "responseByteHash": "e" * 64, "bindingVerified": True}]},
        exclusionReason=None, fixtureHash=fixture_hash, pairedInputVersion="FUSE-PAIRED-INPUT-1",
        pairedInputHash="a" * 64, inputSnapshotHash="c" * 64, responseByteHash="e" * 64,
        modelOutputHash="b" * 64, model="replay", promptVersion="KYC-PROMPT-1",
        policyVersion="FUSE-MVP-2", mockReviewerVersion="MOCK-REVIEWER-1")
    value.update(changes)
    return CaseOutput.model_validate(value)


def report_for(manifest, rows=None, **changes):
    rows = rows if rows is not None else [observed(case, env, manifest["fixtureHash"])
        for case in manifest["cases"] for env in ("BASELINE", "FUSE")]
    value = dict(experimentId=UUID, fixtureSetId=manifest["fixtureSetId"],
        fixtureHash=manifest["fixtureHash"], status="COMPLETED", modelMode="REPLAY",
        resultsSource="JAVA_POSTGRES_EXECUTION", syntheticModelOutputs=True, liveRobustnessMeasured=False,
        plannedCaseIds=[case["caseId"] for case in manifest["cases"]], repeatCount=1, caseOutputs=rows,
        metrics=calculate_metrics(manifest["cases"], rows, 1, "REPLAY"), limitations=[])
    value.update(changes)
    return EvaluationReport.model_validate(value)


@pytest.fixture(autouse=True)
def stable_source_snapshot(monkeypatch):
    # Other workers may change files while this unit suite runs; source hashing
    # is not an execution-revision attestation.
    monkeypatch.setattr("evaluation.export._code_hashes", lambda: {"evaluation/export.py": "f" * 64})


@pytest.fixture
def manifest():
    return load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01", "A_EVIDENCE_03", "A_EVIDENCE_04", "N_NORMAL_PAYMENT_01"])


def read(path, filename):
    return json.loads((path / filename).read_text())


def test_bundle_has_versions_hashes_actual_rows_csv_and_partitions(tmp_path, manifest):
    report = report_for(manifest)
    report.metrics["bySplit"] = calculate_split_metrics(manifest["cases"], report.caseOutputs, 1, "REPLAY")
    path = export_evidence_bundle(report, manifest, tmp_path)
    bundle = read(path, "manifest.json")
    results = read(path, "case_results.json")
    metrics = read(path, "metrics.json")
    assert path.name == report.experimentId
    assert bundle["bundleVersion"] == "FUSE-EVIDENCE-BUNDLE-1"
    assert bundle["sourceReportVersion"] == "FUSE-EVALUATION-2"
    assert bundle["sourceReportHash"] == fingerprint(report.model_dump())
    assert bundle["fixtureHash"] == manifest["fixtureHash"]
    assert bundle["selectedFixturePlanHash"] == fingerprint(manifest["cases"])
    assert bundle["provenanceVersions"]["pairedInputVersion"] == ["FUSE-PAIRED-INPUT-1"]
    assert bundle["selectedCaseCount"] == 4
    assert bundle["actualEnvironmentResultCount"] == bundle["exportedEnvironmentRowCount"] == 8
    assert bundle["splitCaseCounts"] == {"DEV": 1, "TUNE": 1, "FINAL": 1, "NORMAL": 1}
    assert metrics["overall"] == {key: value for key, value in report.metrics.items() if key != "bySplit"}
    for split in ("DEV", "TUNE", "FINAL"):
        assert metrics["bySplit"][split]["environments"]["FUSE"]["forbiddenActionBlockRate"]["denominator"] == 1
    assert len(results) == 8
    # The BASELINE plan says PAID while its explicit observed result is BLOCKED.
    assert results[0]["expectedEndState"] == "PAID"
    assert results[0]["actualState"] == "BLOCKED"
    assert results[0]["expectedDecision"] is None
    assert results[0]["expectedMatch"] is False
    assert results[0]["securityCheckDurationMs"] is None
    assert results[0]["quarantineLatencyMs"] is None
    assert results[0]["ledgerPaymentCount"] == 0
    assert results[0]["ledgerPaidAmountKrw"] == 0
    with (path / "case_results.csv").open(newline="") as source:
        csv_rows = list(csv.DictReader(source))
    assert len(csv_rows) == len(results)
    assert csv_rows[0]["actualState"] == results[0]["actualState"]
    assert json.loads(csv_rows[0]["securityCheckDurationMs"]) is None
    assert json.loads(csv_rows[0]["actualReasonCodes"]) == results[0]["actualReasonCodes"]
    for name, descriptor in bundle["files"].items():
        content = (path / name).read_bytes()
        assert hashlib.sha256(content).hexdigest() == descriptor["sha256"]
        assert len(content) == descriptor["bytes"]
    assert not (path / "report.json").exists()
    assert not (path / "raw-java-report.json").exists()


def test_error_and_success_partner_share_exclusion_and_keep_error(tmp_path, manifest):
    case = manifest["cases"][0]
    manifest["cases"] = [case]
    rows = [observed(case, "BASELINE", manifest["fixtureHash"]), observed(case, "FUSE", manifest["fixtureHash"],
        status="ERROR", decision="ERROR", state="ERROR", exclusionReason="DATABASE_UNAVAILABLE",
        reasonCodes=["DATABASE_UNAVAILABLE"], securityCheckDurationMs=0, quarantineLatencyMs=0)]
    path = export_evidence_bundle(report_for(manifest, rows), manifest, tmp_path)
    results = read(path, "case_results.json")
    assert all(row["commonExclusionReason"] == "DATABASE_UNAVAILABLE" for row in results)
    assert not any(row["includedInCommonDenominator"] for row in results)
    assert results[0]["actualState"] == "BLOCKED"
    assert results[1]["observationStatus"] == results[1]["actualDecision"] == "ERROR"
    assert results[1]["actualReasonCodes"] == ["DATABASE_UNAVAILABLE"]
    for field in ("forbiddenPaymentCount", "forbiddenPaidAmountKrw", "actualDownstreamDepth", "securityCheckDurationMs", "quarantineLatencyMs", "ledgerPaymentCount", "expectedMatch"):
        assert results[1][field] is None
    metric = read(path, "metrics.json")["overall"]
    for env in ("BASELINE", "FUSE"):
        assert metric["environments"][env]["forbiddenActionBlockRate"]["rate"] is None


def test_absent_arm_is_explicit_not_run_with_null_actuals(tmp_path, manifest):
    case = manifest["cases"][0]
    manifest["cases"] = [case]
    row = observed(case, "BASELINE", manifest["fixtureHash"])
    path = export_evidence_bundle(report_for(manifest, [row], status="INTERRUPTED"), manifest, tmp_path)
    results = read(path, "case_results.json")
    assert len(results) == 2
    missing = results[1]
    assert missing["observationStatus"] == "NOT_RUN"
    assert missing["actualState"] is missing["actualDecision"] is missing["sourceResultHash"] is None
    assert missing["expectedEndState"] == "BLOCKED"
    assert all(result["commonExclusionReason"] == "INCOMPLETE_PAIR" for result in results)
    assert read(path, "manifest.json")["experimentStatus"] == "INTERRUPTED"
    assert read(path, "manifest.json")["missingEnvironmentResultCount"] == 1


def test_private_bodies_credentials_documents_and_free_text_never_export(tmp_path, manifest):
    secret = "PRIVATE_BODY_SENTINEL do not publish customer ID document or Bearer sk-123"
    report = report_for(manifest)
    report.limitations = [secret]
    trace = report.caseOutputs[0].trace
    trace.update({"prompt": secret, "documentText": secret, "token": secret, "unknown": {"message": secret},
        "results": [{"resultId": UUID, "bodyJson": {"explanation": secret}, "resultHash": "f" * 64}],
        "auditEvents": [{"id": UUID, "detailsJson": {"document": secret}, "actorId": secret}],
        "modelCapture": {"promptHash": "a" * 64, "modelOutputHash": "b" * 64,
            "modelOutput": {"status": "VERIFIED", "evidenceIds": [UUID], "explanation": secret},
            "requestBytes": secret, "model": "test-model"},
        "armBindings": [{"bindingId": UUID, "requestByteHash": "f" * 64, "responseBytes": secret,
            "inputBytes": secret, "responseByteHash": "e" * 64, "bindingVerified": True}]})
    manifest["cases"][0]["description"] = secret
    manifest["cases"][0]["injection"]["parameters"]["privateText"] = secret
    path = export_evidence_bundle(report, manifest, tmp_path)
    contents = b"\n".join(file.read_bytes() for file in path.rglob("*") if file.is_file())
    for forbidden in (secret.encode(), b"PRIVATE_BODY_SENTINEL", b"sk-123", b"bodyJson", b"responseBytes", b"inputBytes"):
        assert forbidden not in contents
    safe = read(path, "traces/000000-baseline.json")
    assert safe["modelCapture"]["sanitizedCandidate"]["status"] == "VERIFIED"
    assert safe["modelCapture"]["sanitizedCandidate"]["evidenceIds"] == [UUID]
    assert safe["sourceTraceHash"] == fingerprint(trace)
    assert safe["armBindings"][0]["responseByteHash"] == "e" * 64


def test_labels_and_ids_do_not_allow_spreadsheet_formulas_or_unstructured_secrets(tmp_path, manifest):
    report = report_for(manifest)
    report.caseOutputs[0].model = "=HYPERLINK(\"https://bad.test\")"
    report.caseOutputs[0].reasonCodes = ["Bearer sk-secret", "EVIDENCE_MISSING"]
    report.caseOutputs[0].trace["workflowId"] = "customer@example.test"
    report.metrics = calculate_metrics(manifest["cases"], report.caseOutputs, 1, "REPLAY")
    path = export_evidence_bundle(report, manifest, tmp_path)
    row = read(path, "case_results.json")[0]
    assert row["model"].startswith("sha256:")
    assert row["actualReasonCodes"][0].startswith("sha256:")
    assert row["workflowId"].startswith("sha256:")
    assert b"HYPERLINK" not in (path / "case_results.csv").read_bytes()


def test_quarantine_measurement_keeps_verified_endpoint_metadata_only():
    trace = {"quarantineMeasurement": {"boundaryVersion": "QUARANTINE-COMMIT-TO-EXECUTION-DENIAL-1",
        "committedQuarantineCount": 2, "observedDenialCount": 1, "incidents": [
            {"quarantineId": UUID, "commitObservedNanos": 100, "affectedExecutionCount": 1,
             "firstDenial": {"workflowId": UUID, "generation": 1, "jobId": UUID, "runId": UUID,
                "attempt": "KYC_RESULT_APPLY", "executionDeniedNanos": 102, "elapsedNanos": 2,
                "leaseToken": "NEVER_EXPORT_ME"}},
            {"quarantineId": UUID, "commitObservedNanos": 200, "affectedExecutionCount": 1, "firstDenial": None}]}}
    safe = sanitize_trace(trace)["quarantineMeasurement"]
    assert safe["incidents"][0]["firstDenial"]["elapsedNanos"] == 2
    assert safe["incidents"][0]["firstDenial"]["jobId"] == UUID
    assert safe["incidents"][1]["firstDenial"] is None
    assert "NEVER_EXPORT_ME" not in json.dumps(safe)


def test_metrics_disagreement_is_rejected_before_writing(tmp_path, manifest):
    report = report_for(manifest)
    report.metrics["commonEligibleAttackPairs"] = 99
    with pytest.raises(ValueError, match="disagree"):
        export_evidence_bundle(report, manifest, tmp_path)
    assert not list(tmp_path.iterdir())


def test_wrong_fixture_selection_or_hash_rejected(tmp_path, manifest):
    report = report_for(manifest)
    wrong = copy.deepcopy(manifest)
    wrong["fixtureHash"] = "f" * 64
    with pytest.raises(ValueError, match="precommitted"):
        export_evidence_bundle(report, wrong, tmp_path)
    wrong = copy.deepcopy(manifest)
    wrong["cases"].reverse()
    with pytest.raises(ValueError, match="precommitted"):
        export_evidence_bundle(report, wrong, tmp_path)


def test_existing_identical_export_is_idempotent_and_changed_export_is_preserved(tmp_path, manifest):
    report = report_for(manifest)
    path = export_evidence_bundle(report, manifest, tmp_path)
    original = (path / "manifest.json").read_bytes()
    assert export_evidence_bundle(report, manifest, tmp_path) == path
    assert (path / "manifest.json").read_bytes() == original
    report.caseOutputs[0].reasonCodes = ["CHANGED_ACTUAL_REASON"]
    with pytest.raises(ValueError, match="differs"):
        export_evidence_bundle(report, manifest, tmp_path)
    assert (path / "manifest.json").read_bytes() == original


def test_modified_existing_payload_is_not_silently_accepted(tmp_path, manifest):
    report = report_for(manifest)
    path = export_evidence_bundle(report, manifest, tmp_path)
    (path / "case_results.csv").write_text("modified")
    with pytest.raises(ValueError, match="differs"):
        export_evidence_bundle(report, manifest, tmp_path)


@pytest.mark.parametrize("experiment_id", ["../escape", "/tmp/outside", "safe/../../escape", ".", ".."])
def test_path_traversal_experiment_ids_are_rejected(tmp_path, manifest, experiment_id):
    report = report_for(manifest, experimentId=experiment_id)
    with pytest.raises(ValueError, match="identifier"):
        export_evidence_bundle(report, manifest, tmp_path)
    assert not list(tmp_path.iterdir())


def test_destination_symlink_is_rejected(tmp_path, manifest):
    report = report_for(manifest)
    other = tmp_path / "outside"
    other.mkdir()
    (tmp_path / report.experimentId).symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="regular directory"):
        export_evidence_bundle(report, manifest, tmp_path)
    assert not list(other.iterdir())


def test_empty_partitions_are_unmeasured_and_unknown_split_is_rejected(manifest):
    manifest["cases"] = [manifest["cases"][0]]
    report = report_for(manifest)
    split = calculate_split_metrics(manifest["cases"], report.caseOutputs, 1, "REPLAY")
    assert split["FINAL"]["plannedAttacks"] == 0
    assert split["FINAL"]["environments"]["FUSE"]["forbiddenActionBlockRate"]["rate"] is None
    manifest["cases"][0]["split"] = "CUSTOM"
    with pytest.raises(ValueError, match="split"):
        calculate_split_metrics(manifest["cases"], report.caseOutputs, 1, "REPLAY")


def test_export_files_are_owner_only(tmp_path, manifest):
    path = export_evidence_bundle(report_for(manifest), manifest, tmp_path)
    assert path.stat().st_mode & 0o777 == 0o700
    for file in path.rglob("*"):
        assert file.stat().st_mode & 0o777 == (0o700 if file.is_dir() else 0o600)


def test_existing_bundle_with_unlisted_file_is_not_safe_for_upload(tmp_path, manifest):
    report = report_for(manifest)
    path = export_evidence_bundle(report, manifest, tmp_path)
    (path / "private-raw.json").write_text("DO NOT PUBLISH")
    with pytest.raises(ValueError, match="differs"):
        export_evidence_bundle(report, manifest, tmp_path)


@pytest.mark.parametrize("changes", [{"repeatCount": 2}, {"syntheticModelOutputs": False}, {"liveRobustnessMeasured": True}])
def test_inconsistent_execution_provenance_is_rejected(tmp_path, manifest, changes):
    report = report_for(manifest, **changes)
    with pytest.raises(ValueError):
        export_evidence_bundle(report, manifest, tmp_path)
    assert not list(tmp_path.iterdir())


def test_selected_and_registered_plan_counts_are_distinct(tmp_path, manifest):
    path = export_evidence_bundle(report_for(manifest), manifest, tmp_path)
    value = read(path, "manifest.json")
    assert value["registeredPlannedCaseCount"] == 60
    assert value["selectedCaseCount"] == 4
    assert value["registeredSplitCaseCounts"] == {"DEV": 16, "TUNE": 8, "FINAL": 16, "NORMAL": 20}


def test_reexport_cli_uses_saved_actual_report_and_does_not_execute(tmp_path, manifest, capsys):
    from evaluation.export import main
    report = report_for(manifest)
    saved = tmp_path / "private-report.json"
    saved.write_text(report.model_dump_json())
    assert main(["--report", str(saved), "--output", str(tmp_path / "safe")]) == 0
    printed = json.loads(capsys.readouterr().out)
    path = Path(printed["bundle"])
    assert read(path, "case_results.json")[0]["actualState"] == "BLOCKED"
    assert printed["experimentId"] == report.experimentId


def test_cli_validation_error_does_not_echo_private_report_body(tmp_path, capsys):
    from evaluation.export import main
    saved = tmp_path / "bad-report.json"
    saved.write_text('{"reportVersion":"PRIVATE-SENTINEL"}')
    assert main(["--report", str(saved), "--output", str(tmp_path / "safe")]) == 2
    assert "PRIVATE-SENTINEL" not in capsys.readouterr().err
    assert not (tmp_path / "safe").exists()


def test_payment_goal_occurrence_comes_from_observed_ledger_outcome(tmp_path, manifest):
    case = manifest["cases"][0]
    manifest["cases"] = [case]
    rows = [observed(case, "BASELINE", manifest["fixtureHash"], state="PAID", decision="ALLOW",
        policyBlocked=False, forbiddenPaymentCount=1, forbiddenPaidAmountKrw=1000000),
        observed(case, "FUSE", manifest["fixtureHash"])]
    path = export_evidence_bundle(report_for(manifest, rows), manifest, tmp_path)
    results = read(path, "case_results.json")
    assert results[0]["forbiddenGoalOccurred"] is True
    assert results[1]["forbiddenGoalOccurred"] is False
    assert all(row["attackAttemptEstablished"] is True for row in results)


def test_unmeasured_nonpayment_goal_is_not_invented(tmp_path):
    manifest = load_fixture_set("security-evaluation-v1")
    manifest["cases"] = [next(case for case in manifest["cases"] if case.get("forbiddenGoal") == "USE_STALE_DELEGATION")]
    path = export_evidence_bundle(report_for(manifest), manifest, tmp_path)
    assert all(row["forbiddenGoalOccurred"] is None for row in read(path, "case_results.json"))


@pytest.mark.parametrize("value", ["ghp_" + "A" * 36, "github_pat_" + "B" * 40, "OPAQUE_CANARY_9481", "eyJabc.eyJdef.signature"])
def test_unrecognized_machine_label_values_are_hashed_not_exported(value):
    safe = sanitize_trace({"model": value, "status": value, "promptVersion": value, "reasonCode": value})
    for field in ("model", "status", "promptVersion", "reasonCode"):
        assert safe[field] == "sha256:" + fingerprint(value)
    assert value not in json.dumps(safe)


def test_runner_successful_normalization_does_not_print_private_metrics(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    from evaluation import scenario_runner, export
    canary = "PRIVATE_METRIC_CANARY_7832"
    report = SimpleNamespace(status="COMPLETED", caseOutputs=[object()],
        metrics={"excludedPairCount": 1, "exclusions": [{"reason": canary}]},
        model_dump=lambda: {"privateDiagnostic": canary})
    monkeypatch.setattr(scenario_runner, "execute_java", lambda *args: {})
    monkeypatch.setattr(scenario_runner, "normalize_java_report", lambda *args: report)
    monkeypatch.setattr(export, "export_evidence_bundle", lambda *args: tmp_path)
    assert scenario_runner.main(["run", "--output", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert canary not in captured.out + captured.err
    assert json.loads(captured.out) == {"completed": True, "caseOutputCount": 1,
        "hasExcludedPairs": True, "evidenceBundleSaved": True}
    assert canary in (tmp_path / "report.json").read_text()


@pytest.mark.parametrize("case_id", ["A_APPROVAL_BYPASS_01", "A_RISK_BYPASS_05", "A_PRIVILEGE_LAUNDERING_04"])
@pytest.mark.parametrize("environment", ["BASELINE", "FUSE"])
def test_approval_wait_expectations_reject_a_mislabeled_policy_denial(case_id, environment):
    fixture = load_fixture_set("security-evaluation-v1", [case_id])["cases"][0]
    expected = fixture["expected"][environment]
    assert expected["decision"] == "WAIT_APPROVAL"
    actual = {"status": "COMPLETED", "state": "WAIT_APPROVAL", "decision": "WAIT_APPROVAL",
              "reasonCodes": ["APPROVAL_REQUIRED"], "forbiddenPaymentCount": 0}
    assert _expected_match(expected, actual) is True
    assert _expected_match(expected, {**actual, "decision": "DENY"}) is False
    assert _expected_match(expected, {**actual, "decision": "ERROR"}) is False
