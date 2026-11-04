"""Synthetic report, fixture-registration and aggregation input contracts."""
import pytest
from pydantic import ValidationError

from evaluation.fixture_loader import load_fixture_set, register_fixture_set
from evaluation.metrics import calculate_metrics
from evaluation.report import CaseOutput


def row_fields():
    return dict(
        caseId="SYNTHETIC_NORMAL", environment="BASELINE", repeat=1, status="COMPLETED",
        state="WAIT_APPROVAL", decision="WAIT_APPROVAL", reasonCodes=[], attackInduced=False,
        policyBlocked=False, forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0,
        actualDownstreamDepth=0, normalExpectedReached=True, unrelatedNormalExpected=0,
        unrelatedNormalCompleted=0, trace={}, exclusionReason=None, fixtureHash="a" * 64,
        modelOutputHash="b" * 64, model="replay", promptVersion="KYC-PROMPT-1",
        policyVersion="FUSE-MVP-2", mockReviewerVersion="MOCK-REVIEWER-1",
    )


@pytest.mark.parametrize("field", ["securityCheckDurationMs", "quarantineLatencyMs"])
@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), -0.1])
def test_durations_reject_nonfinite_or_negative_values(field, value):
    with pytest.raises(ValidationError):
        CaseOutput(**{**row_fields(), field: value})


@pytest.mark.parametrize("value", [None, 0.0, 1.5])
def test_available_and_unavailable_duration_contract_is_preserved(value):
    row = CaseOutput(**{**row_fields(), "securityCheckDurationMs": value,
                        "quarantineLatencyMs": value})
    assert row.securityCheckDurationMs == row.quarantineLatencyMs == value


def test_registered_split_counts_match_kind_defaults_and_development_alias():
    identifier = "synthetic-input-default-splits"
    register_fixture_set(identifier, {"cases": [
        {"caseId": "synthetic-normal", "kind": "NORMAL"},
        {"caseId": "synthetic-attack-default", "kind": "ATTACK"},
        {"caseId": "synthetic-attack-alias", "kind": "ATTACK", "split": "DEVELOPMENT"},
    ]})
    selected = load_fixture_set(identifier, ["synthetic-attack-default"])
    assert selected["registeredPlannedCaseCount"] == 3
    assert selected["registeredSplitCaseCounts"] == {"DEV": 2, "TUNE": 0, "FINAL": 0, "NORMAL": 1}
    assert selected["cases"] == [{"caseId": "synthetic-attack-default", "kind": "ATTACK"}]


@pytest.mark.parametrize("split", [True, None, [], "DEV_UNKNOWN"])
def test_invalid_split_is_rejected_before_registry_mutation(split):
    identifier = "synthetic-input-rejected-split"
    with pytest.raises(ValueError, match="unsupported split"):
        register_fixture_set(identifier, {"cases": [
            {"caseId": "synthetic-case", "kind": "ATTACK", "split": split},
        ]})
    with pytest.raises(ValueError, match="not registered"):
        load_fixture_set(identifier)


def test_duplicate_planned_case_is_rejected_before_denominator_inflation():
    case = {"caseId": "synthetic-normal", "kind": "NORMAL"}
    with pytest.raises(ValueError, match="duplicate evaluation cases"):
        calculate_metrics([case, dict(case)], [], 1, "REPLAY")


@pytest.mark.parametrize("repeat", [True, 1.5, 0, -1, 11])
def test_metrics_repeat_count_obeys_report_integer_contract(repeat):
    with pytest.raises(ValueError, match="planned repeat count"):
        calculate_metrics([], [], repeat, "REPLAY")


@pytest.mark.parametrize("mode", ["live", "UNKNOWN", None])
def test_unknown_model_mode_cannot_silently_bypass_live_validation(mode):
    with pytest.raises(ValueError, match="unsupported model mode"):
        calculate_metrics([], [], 1, mode)


@pytest.mark.parametrize("case", [
    {"caseId": "synthetic-case", "kind": "NORMAL_ALIAS"},
    {"caseId": True, "kind": "NORMAL"},
    {"caseId": "synthetic-case"},
])
def test_invalid_case_contract_is_rejected_before_aggregation(case):
    with pytest.raises(ValueError, match="invalid evaluation cases"):
        calculate_metrics([case], [], 1, "REPLAY")
