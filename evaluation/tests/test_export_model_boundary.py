"""Wholly synthetic in-process export model regressions; not executed here."""
from copy import deepcopy
import json
from unittest.mock import Mock
import warnings

import pytest

from evaluation import export_provider
from evaluation.report import CaseOutput, EvaluationReport


def row():
    return CaseOutput(
        caseId="synthetic-export-row", environment="FUSE", repeat=1,
        status="COMPLETED", state="WAIT_APPROVAL", decision="WAIT_APPROVAL",
        reasonCodes=[], attackInduced=False, policyBlocked=False,
        forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0, actualDownstreamDepth=0,
        normalExpectedReached=True, unrelatedNormalExpected=0, unrelatedNormalCompleted=0,
        trace={}, exclusionReason=None, fixtureHash="a" * 64, modelOutputHash="b" * 64,
        model="synthetic-replay", promptVersion="SYNTHETIC-PROMPT-1",
        policyVersion="SYNTHETIC-POLICY-1", mockReviewerVersion="SYNTHETIC-REVIEWER-1",
    )


def report():
    return EvaluationReport(
        experimentId="synthetic-export-model", fixtureSetId="synthetic-export-plan",
        fixtureHash="a" * 64, status="COMPLETED", modelMode="REPLAY",
        resultsSource="JAVA_POSTGRES_EXECUTION", syntheticModelOutputs=True,
        liveRobustnessMeasured=False, plannedCaseIds=["synthetic-export-row"], repeatCount=1,
        caseOutputs=[row()], metrics={}, limitations=["Synthetic schema-only example."],
    )


@pytest.mark.parametrize("update", [
    {"reportVersion": "SYNTHETIC_INVALID_VERSION"}, {"repeatCount": True}, {"repeatCount": 11},
    {"status": "SYNTHETIC_INVALID_STATUS"}, {"modelMode": "SYNTHETIC_INVALID_MODE"},
    {"resultsSource": "SYNTHETIC_INVALID_SOURCE"}, {"syntheticModelOutputs": 1},
    {"fixtureHash": "SYNTHETIC_INVALID_HASH"}, {"plannedCaseIds": [False]},
])
def test_copied_root_model_is_revalidated_before_metrics_or_bundle_io(update, monkeypatch):
    invalid = report().model_copy(update=update)
    metrics = Mock(side_effect=AssertionError("Invalid report must not reach metrics"))
    writer = Mock(side_effect=AssertionError("Invalid report must not reach bundle I/O"))
    monkeypatch.setattr(export_provider, "calculate_metrics", metrics)
    monkeypatch.setattr(export_provider, "write_bundle", writer)
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(ValueError, match="^invalid evaluation report$") as failure:
            export_provider.export_evidence_bundle(invalid, {}, object())
    assert emitted == []
    assert failure.value.__cause__ is None
    metrics.assert_not_called()
    writer.assert_not_called()


def test_direct_nested_model_mutation_is_rejected_without_repairing_the_caller(monkeypatch):
    invalid = report()
    invalid.caseOutputs[0].reasonCodes.append({"synthetic": "not a string"})
    before = deepcopy(invalid.caseOutputs[0].reasonCodes)
    writer = Mock(side_effect=AssertionError("Invalid nested values must not reach bundle I/O"))
    monkeypatch.setattr(export_provider, "write_bundle", writer)
    with pytest.raises(ValueError, match="^invalid evaluation report$"):
        export_provider.export_evidence_bundle(invalid, {}, object())
    assert invalid.caseOutputs[0].reasonCodes == before
    writer.assert_not_called()


def test_copied_case_model_inside_copied_report_is_revalidated():
    invalid_row = row().model_copy(update={"securityCheckDurationMs": float("inf")})
    invalid = report().model_copy(update={"caseOutputs": [invalid_row]})
    with pytest.raises(ValueError, match="^invalid evaluation report$"):
        export_provider._validated_report(invalid)


def test_valid_direct_report_is_rebuilt_without_changing_public_values_or_caller():
    original = report()
    before = original.model_dump()
    validated = export_provider._validated_report(original)
    assert validated is not original
    assert validated.model_dump() == before
    assert original.model_dump() == before
    validated.caseOutputs[0].reasonCodes.append("SYNTHETIC_CHANGED")
    assert original.caseOutputs[0].reasonCodes == []


def test_legacy_mapping_normalization_stays_mapping_only_and_does_not_mutate_input():
    legacy = report().model_dump()
    legacy["reportVersion"] = "FUSE-EVALUATION-1"
    before = deepcopy(legacy)
    converted = export_provider._validated_report(legacy)
    assert converted.reportVersion == "FUSE-EVALUATION-2"
    assert converted.inputReportVersion == "FUSE-EVALUATION-1"
    assert legacy == before
    copied = report().model_copy(update={"reportVersion": "FUSE-EVALUATION-1"})
    with pytest.raises(ValueError, match="^invalid evaluation report$"):
        export_provider._validated_report(copied)


@pytest.mark.parametrize("location", ["root", "nested_case", "mapping_nested_case"])
def test_unknown_model_copy_fields_are_rejected_before_serialization_can_hide_them(location, monkeypatch):
    original = report()
    if location == "root":
        invalid = original.model_copy(update={"unlisted": "SYNTHETIC_UNDECLARED"})
        target = invalid
    else:
        target = row().model_copy(update={"unlisted": "SYNTHETIC_UNDECLARED"})
        if location == "mapping_nested_case":
            invalid = original.model_dump()
            invalid["caseOutputs"] = [target]
        else:
            invalid = original.model_copy(update={"caseOutputs": [target]})
    assert target.__dict__["unlisted"] == "SYNTHETIC_UNDECLARED"
    writer = Mock(side_effect=AssertionError("Unknown fields must not reach bundle I/O"))
    monkeypatch.setattr(export_provider, "write_bundle", writer)
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(ValueError, match="^invalid evaluation report$") as failure:
            export_provider.export_evidence_bundle(invalid, {}, object())
    assert emitted == []
    assert failure.value.__cause__ is None
    assert target.__dict__["unlisted"] == "SYNTHETIC_UNDECLARED"
    writer.assert_not_called()


def test_bundle_preserves_report_lifecycle_and_fingerprints_its_public_status(monkeypatch):
    original = report()
    plan = {"fixtureSetId": original.fixtureSetId, "fixtureHash": original.fixtureHash,
            "cases": [{"caseId": original.plannedCaseIds[0], "kind": "NORMAL",
                       "split": "NORMAL", "expected": {}}]}
    captures = []

    def capture(_root, _experiment, payloads):
        captures.append(dict(payloads))
        return "synthetic-destination"

    monkeypatch.setattr(export_provider, "write_bundle", capture)
    for status in ("COMPLETED", "FAILED", "INTERRUPTED"):
        candidate = original.model_copy(update={"status": status})
        export_provider.export_evidence_bundle(candidate, plan, object())
    manifests = [json.loads(payloads["manifest.json"]) for payloads in captures]
    assert [value["sourceReportStatus"] for value in manifests] == [
        "COMPLETED", "FAILED", "INTERRUPTED"]
    assert len({value["sanitizedReportHash"] for value in manifests}) == 3
    assert all(value["bundleVersion"] == "FUSE-EVIDENCE-BUNDLE-2" for value in manifests)
    # The lifecycle distinction must not invent different case observations.
    assert len({payloads["case_results.json"] for payloads in captures}) == 1
    assert len({payloads["metrics.json"] for payloads in captures}) == 1
    assert original.status == "COMPLETED"


def test_interrupted_missing_arm_remains_excluded_without_raw_trace_export(monkeypatch):
    original = report()
    marker = "SYNTHETIC_RAW_PROVIDER_TEXT_MUST_NOT_EXPORT"
    original.status = "INTERRUPTED"
    original.caseOutputs[0].trace = {"request": {"body": marker}, "providerOutput": marker}
    before = deepcopy(original.model_dump())
    plan = {"fixtureSetId": original.fixtureSetId, "fixtureHash": original.fixtureHash,
            "cases": [{"caseId": original.plannedCaseIds[0], "kind": "NORMAL",
                       "split": "NORMAL", "expected": {}}]}
    captured = []
    monkeypatch.setattr(export_provider, "write_bundle",
                        lambda _root, _experiment, payloads: captured.append(dict(payloads)))
    export_provider.export_evidence_bundle(original, plan, object())
    payloads = captured[0]
    assert json.loads(payloads["manifest.json"])["sourceReportStatus"] == "INTERRUPTED"
    rows = json.loads(payloads["case_results.json"])
    assert len(rows) == 2
    assert all(value["includedInCommonDenominator"] is False for value in rows)
    assert all(value["commonExclusionReason"] == "INCOMPLETE_PAIR" for value in rows)
    assert {value["observationStatus"] for value in rows} == {"COMPLETED", "NOT_RUN"}
    assert marker.encode() not in b"".join(payloads.values())
    assert original.model_dump() == before
