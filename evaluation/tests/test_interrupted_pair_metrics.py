"""Synthetic accounting contracts for interrupted paired evaluations."""
import pytest

from evaluation.metrics import calculate_metrics
from evaluation.report import CaseOutput


def output(case_id, environment, repeat=1, **changes):
    fields = dict(
        caseId=case_id, environment=environment, repeat=repeat, status="COMPLETED",
        state="BLOCKED", decision="DENY", reasonCodes=[], attackInduced=True,
        policyBlocked=True, forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0,
        actualDownstreamDepth=0, normalExpectedReached=False,
        unrelatedNormalExpected=0, unrelatedNormalCompleted=0,
        securityCheckDurationMs=None, quarantineLatencyMs=None, trace={}, exclusionReason=None,
        fixtureHash="a" * 64, pairedInputVersion="FUSE-PAIRED-INPUT-1",
        pairedInputHash="b" * 64, inputSnapshotHash="c" * 64, responseByteHash="d" * 64,
        modelOutputHash="e" * 64, model="replay", promptVersion="KYC-PROMPT-1",
        policyVersion="FUSE-MVP-2", mockReviewerVersion="MOCK-REVIEWER-1",
    )
    fields.update(changes)
    return CaseOutput(**fields)


def test_partial_repeats_preserve_planned_denominator_and_exclude_both_arms():
    cases = [{"caseId": "synthetic-attack", "kind": "ATTACK"},
             {"caseId": "synthetic-normal", "kind": "NORMAL"}]
    rows = [output(case["caseId"], environment) for case in cases
            for environment in ("BASELINE", "FUSE")]
    # Repeat two has a missing attack arm and an errored normal arm; repeat three
    # never ran. Their apparent blocks, payments and timing cannot be measurements.
    rows.extend([
        output("synthetic-attack", "BASELINE", 2, actualDownstreamDepth=2,
               forbiddenPaymentCount=7, forbiddenPaidAmountKrw=700,
               securityCheckDurationMs=0, quarantineLatencyMs=0),
        output("synthetic-normal", "BASELINE", 2, securityCheckDurationMs=0),
        output("synthetic-normal", "FUSE", 2, status="ERROR", decision="ERROR",
               securityCheckDurationMs=0, quarantineLatencyMs=0),
    ])
    metrics = calculate_metrics(cases, rows, repeat_count=3, model_mode="REPLAY")
    assert metrics["plannedAttacks"] == metrics["plannedNormals"] == 3
    assert metrics["commonEligibleAttackPairs"] == metrics["commonEligibleNormalPairs"] == 1
    assert metrics["excludedPairCount"] == 4
    assert {(row["caseId"], row["repeat"], row["reason"]) for row in metrics["exclusions"]} == {
        ("synthetic-attack", 2, "INCOMPLETE_PAIR"),
        ("synthetic-attack", 3, "INCOMPLETE_PAIR"),
        ("synthetic-normal", 2, "ENVIRONMENT_ERROR"),
        ("synthetic-normal", 3, "INCOMPLETE_PAIR"),
    }
    for environment in ("BASELINE", "FUSE"):
        result = metrics["environments"][environment]
        assert result["forbiddenActionBlockRate"] == {"numerator": 1, "denominator": 1, "rate": 1}
        assert result["normalFalseBlockRate"] == {"numerator": 1, "denominator": 3, "rate": 1 / 3}
        assert result["normalEvaluableCount"] == 1
        assert result["normalEnvironmentFailureCount"] == 2
        assert result["forbiddenPaymentCount"] == result["forbiddenPaidAmountKrw"] == 0
        assert result["maximumActualDownstreamDepth"] == 0
        assert result["meanSecurityCheckDurationMs"] is None
        assert result["meanQuarantineLatencyMs"] is None


@pytest.mark.parametrize("environment", ["BASELINE", "FUSE"])
def test_duplicate_arm_is_rejected_instead_of_double_counted(environment):
    cases = [{"caseId": "synthetic-normal", "kind": "NORMAL"}]
    rows = [output("synthetic-normal", arm) for arm in ("BASELINE", "FUSE")]
    rows.append(output("synthetic-normal", environment, normalExpectedReached=True))
    with pytest.raises(ValueError, match="duplicate environment result"):
        calculate_metrics(cases, rows, repeat_count=1, model_mode="REPLAY")
