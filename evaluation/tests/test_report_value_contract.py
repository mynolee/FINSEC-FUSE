"""Synthetic regressions for reused model values at aggregation boundaries."""
from copy import deepcopy

import pytest
from pydantic import ValidationError

from evaluation.metrics import calculate_metrics
from evaluation.report import CaseOutput, EvaluationReport


def valid_row(environment):
    return CaseOutput(
        caseId="synthetic-reused-row", environment=environment, repeat=1,
        status="COMPLETED", state="WAIT_APPROVAL", decision="WAIT_APPROVAL",
        reasonCodes=[], attackInduced=False, policyBlocked=False,
        forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0, actualDownstreamDepth=0,
        normalExpectedReached=True, unrelatedNormalExpected=0, unrelatedNormalCompleted=0,
        trace={}, exclusionReason=None, fixtureHash="a" * 64, modelOutputHash="b" * 64,
        pairedInputVersion="FUSE-PAIRED-INPUT-1", pairedInputHash="c" * 64,
        inputSnapshotHash="d" * 64, responseByteHash="e" * 64,
        model="replay", promptVersion="KYC-PROMPT-1", policyVersion="FUSE-MVP-2",
        mockReviewerVersion="MOCK-REVIEWER-1",
    )


@pytest.mark.parametrize("update", [
    {"repeat": True}, {"environment": "FUSE_ALIAS"}, {"status": "COMPLETED_ALIAS"},
    {"forbiddenPaymentCount": -1}, {"actualDownstreamDepth": 3},
    {"securityCheckDurationMs": float("inf")}, {"reasonCodes": [False]},
])
def test_unvalidated_model_copy_is_rejected_before_metrics(update):
    invalid = valid_row("BASELINE").model_copy(update=update)
    with pytest.raises(ValidationError):
        CaseOutput.model_validate(invalid)
    with pytest.raises(ValueError, match="^invalid evaluation result$"):
        calculate_metrics([{"caseId": "synthetic-reused-row", "kind": "NORMAL"}],
                          [invalid, valid_row("FUSE")], 1, "REPLAY")


def test_mutated_nested_fields_are_revalidated_without_changing_caller_data():
    row = valid_row("BASELINE")
    row.reasonCodes.append({"synthetic": "invalid nested type"})
    before = deepcopy(row.reasonCodes)
    with pytest.raises(ValueError) as failure:
        calculate_metrics([{"caseId": "synthetic-reused-row", "kind": "NORMAL"}],
                          [row, valid_row("FUSE")], 1, "REPLAY")
    assert str(failure.value) == "invalid evaluation result"
    assert failure.value.__cause__ is None
    assert row.reasonCodes == before


def test_valid_reused_rows_keep_metrics_and_source_values():
    rows = [valid_row(environment) for environment in ("BASELINE", "FUSE")]
    before = [row.model_dump() for row in rows]
    result = calculate_metrics([{"caseId": "synthetic-reused-row", "kind": "NORMAL"}],
                               rows, 1, "REPLAY")
    assert result["commonEligibleNormalPairs"] == 1
    assert result["excludedPairCount"] == 0
    assert all(value["normalEvaluableCount"] == 1 for value in result["environments"].values())
    assert [row.model_dump() for row in rows] == before


def test_duck_typed_objects_do_not_bypass_the_declared_result_model():
    class UnsupportedResult:
        @property
        def caseId(self):
            raise AssertionError("Unsupported result attributes must not be read")

    with pytest.raises(ValueError, match="^invalid evaluation result$"):
        calculate_metrics([], [UnsupportedResult()], 1, "REPLAY")


def test_nested_report_validation_rechecks_copied_case_instances():
    fields = dict(
        experimentId="synthetic-model-validation", fixtureSetId="synthetic-model-validation",
        fixtureHash="a" * 64, status="COMPLETED", modelMode="REPLAY",
        resultsSource="JAVA_POSTGRES_EXECUTION", syntheticModelOutputs=True,
        liveRobustnessMeasured=False, plannedCaseIds=["synthetic-reused-row"], repeatCount=1,
        metrics={}, limitations=["Synthetic model-validation sample only; no Java/Postgres execution."],
    )
    valid = valid_row("BASELINE")
    report = EvaluationReport(**fields, caseOutputs=[valid])
    assert report.caseOutputs[0].model_dump() == valid.model_dump()
    invalid = valid.model_copy(update={"repeat": True})
    with pytest.raises(ValidationError):
        EvaluationReport.model_validate({**fields, "caseOutputs": [invalid]})
