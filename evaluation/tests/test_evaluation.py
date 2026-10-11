import asyncio
from collections import Counter
import copy
import json
from pathlib import Path

import pytest

from evaluation.fixture_loader import load_fixture_set, fingerprint
from evaluation.metrics import calculate_metrics
from evaluation.report import CaseOutput, EvaluationReport
from evaluation.scenario_runner import prompt_audit, normalize_java_report, main


def result(case_id, environment, **changes):
    row = dict(caseId=case_id, environment=environment, repeat=1, status="COMPLETED", state="BLOCKED",
        decision="DENY", reasonCodes=["EVIDENCE_MISSING"], attackInduced=True, policyBlocked=True,
        forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0, actualDownstreamDepth=0,
        normalExpectedReached=None, unrelatedNormalExpected=0, unrelatedNormalCompleted=0,
        securityCheckDurationMs=None, quarantineLatencyMs=None, trace={}, exclusionReason=None,
        pairedInputVersion="FUSE-PAIRED-INPUT-1", pairedInputHash="d"*64, inputSnapshotHash="e"*64, responseByteHash="f"*64,
        fixtureHash="a"*64, modelOutputHash="b"*64, model="replay", promptVersion="KYC-PROMPT-1",
        policyVersion="FUSE-MVP-2", mockReviewerVersion="MOCK-REVIEWER-1")
    row.update(changes)
    return CaseOutput.model_validate(row)


def test_60_fixture_plan_and_splits():
    manifest = load_fixture_set("security-evaluation-v1")
    attacks = [c for c in manifest["cases"] if c["kind"] == "ATTACK"]
    normal = [c for c in manifest["cases"] if c["kind"] == "NORMAL"]
    assert len(attacks) == 40 and len(normal) == 20
    assert Counter(c["split"] for c in attacks) == {"DEVELOPMENT": 16, "TUNING": 8, "FINAL": 16}
    assert set(Counter(c["family"] for c in attacks).values()) == {5}
    assert set(Counter(c["family"] for c in normal).values()) == {2}
    assert len({c["caseId"] for c in manifest["cases"]}) == 60
    assert "not the original acceptance suite" in manifest["provenance"]


def test_registry_is_closed_and_selection_fixed():
    with pytest.raises(ValueError): load_fixture_set("../../secrets")
    with pytest.raises(ValueError): load_fixture_set("security-evaluation-v1", ["NOT_REGISTERED"])
    with pytest.raises(ValueError): load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01"]*2)
    manifest = load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01"])
    assert len(manifest["cases"]) == 1
    assert manifest["fixtureHash"] == load_fixture_set("security-evaluation-v1")["fixtureHash"]


def test_mvp_six_exact_ids():
    manifest = load_fixture_set("mvp-security-v1")
    assert [c["caseId"] for c in manifest["cases"]] == ["T01_NORMAL_PAYMENT", "T02_MISSING_EVIDENCE",
        "T03_WRONG_CUSTOMER_EVIDENCE", "T04_PRIVILEGE_REQUEST", "T05_APPROVAL_RISK_WAIT", "T06_SELECTIVE_QUARANTINE"]


def test_fixture_generation_is_reproducible():
    from evaluation.generate_fixtures import generate
    paths = [Path("evaluation/fixtures/security-evaluation-v1.json"), Path("evaluation/fixtures/mvp-security-v1.json"), Path("evaluation/cases.csv")]
    old = [p.read_bytes() for p in paths]
    generate()
    assert old == [p.read_bytes() for p in paths]


def test_metrics_errors_are_excluded_from_both_environments():
    cases = load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01", "A_EVIDENCE_02"])["cases"]
    rows = [result(c["caseId"], env) for c in cases for env in ("BASELINE", "FUSE")]
    rows[-1] = result("A_EVIDENCE_02", "FUSE", status="ERROR", decision="ERROR", policyBlocked=False, exclusionReason="DATABASE_UNAVAILABLE")
    metrics = calculate_metrics(cases, rows, 1, "REPLAY")
    assert metrics["commonEligibleAttackPairs"] == 1
    assert metrics["excludedPairCount"] == 1
    for env in ("BASELINE", "FUSE"):
        assert metrics["environments"][env]["forbiddenActionBlockRate"] == {"numerator": 1, "denominator": 1, "rate": 1.0}
        assert metrics["environments"][env]["meanQuarantineLatencyMs"] is None


def test_failed_live_induction_not_defense_success():
    cases = load_fixture_set("security-evaluation-v1", ["A_RAG_POISONING_01"])["cases"]
    rows = [result(cases[0]["caseId"], env, attackInduced=False, policyBlocked=False, state="ON_HOLD") for env in ("BASELINE", "FUSE")]
    metrics = calculate_metrics(cases, rows, 1, "LIVE")
    assert metrics["commonEligibleAttackPairs"] == 0
    assert metrics["exclusions"][0]["reason"] == "INDUCTION_FAILED"
    assert metrics["environments"]["FUSE"]["forbiddenActionBlockRate"]["rate"] is None


def test_same_candidate_output_required():
    cases = load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01"])["cases"]
    rows = [result(cases[0]["caseId"], "BASELINE"), result(cases[0]["caseId"], "FUSE", modelOutputHash="c"*64)]
    assert calculate_metrics(cases, rows, 1, "REPLAY")["exclusions"][0]["reason"] == "UNPAIRED_MODEL_OUTPUT"


def test_normal_expected_outcome_not_necessarily_payment():
    cases = load_fixture_set("security-evaluation-v1", ["N_LOAN_REJECTION_01", "N_EVIDENCE_SUPPLEMENT_01"])["cases"]
    rows = [result(c["caseId"], env, state=c["expected"][env]["state"], normalExpectedReached=True,
                   policyBlocked=False, attackInduced=False) for c in cases for env in ("BASELINE", "FUSE")]
    metrics = calculate_metrics(cases, rows, 1, "REPLAY")
    assert metrics["environments"]["FUSE"]["normalFalseBlockRate"] == {"numerator": 0, "denominator": 2, "rate": 0.0}


def test_duplicates_and_unregistered_results_rejected():
    cases = load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01"])["cases"]
    row = result("A_EVIDENCE_01", "FUSE")
    with pytest.raises(ValueError): calculate_metrics(cases, [row, row], 1, "REPLAY")
    with pytest.raises(ValueError): calculate_metrics(cases, [result("unregistered", "FUSE")], 1, "REPLAY")


def test_payment_with_block_claim_is_not_blocked():
    cases = load_fixture_set("security-evaluation-v1", ["A_EVIDENCE_01"])["cases"]
    rows = [result(cases[0]["caseId"], env, forbiddenPaymentCount=1, forbiddenPaidAmountKrw=1_000_000,
                   actualDownstreamDepth=2) for env in ("BASELINE", "FUSE")]
    metrics = calculate_metrics(cases, rows, 1, "REPLAY")
    assert metrics["environments"]["FUSE"]["forbiddenActionBlockRate"]["numerator"] == 0
    assert metrics["environments"]["FUSE"]["forbiddenPaidAmountKrw"] == 1_000_000


def test_prompt_audit_is_honestly_labeled(internal_service_token):
    manifest = load_fixture_set("security-evaluation-v1", ["A_RAG_POISONING_01", "N_NORMAL_PAYMENT_01"])
    report = asyncio.run(prompt_audit(manifest, "offline", 1))
    assert report["resultsSource"] == "PROMPT_ONLY"
    assert report["liveRobustnessMeasured"] is False
    assert report["syntheticModelOutputs"] is True
    assert "metrics" not in report
    assert [row["modelOutput"]["status"] for row in report["caseOutputs"]] == ["NOT_VERIFIED", "VERIFIED"]
    assert all(row["status"] == "COMPLETED" for row in report["caseOutputs"])


def test_live_cli_does_not_accidentally_call_provider():
    assert main(["prompt-audit", "--model-mode", "LIVE"]) == 2
    assert main(["prompt-audit", "--model-mode", "LIVE", "--allow-live", "--repeat-count", "1"]) == 2


def test_non_execution_reports_do_not_get_policy_metrics():
    with pytest.raises(ValueError): normalize_java_report({"resultsSource": "SYNTHETIC"}, load_fixture_set("mvp-security-v1"), "REPLAY", 1)


def test_report_schema_matches():
    assert json.loads(Path("evaluation/schemas/report.schema.json").read_text()) == EvaluationReport.model_json_schema()


# Shared hand-specified arithmetic oracles. These fabricate scalar result rows;
# they do not execute scenarios, contact services, or measure policy behavior.
METRICS_PARITY = json.loads((Path(__file__).parent / "fixtures" / "metrics-parity.json").read_text())


@pytest.mark.parametrize("vector", METRICS_PARITY["vectors"], ids=lambda vector: vector["name"])
def test_metrics_match_shared_java_arithmetic_vectors(vector):
    rows = [CaseOutput.model_validate({**METRICS_PARITY["defaults"], **overrides})
            for overrides in vector["rows"]]
    if vector["throughNormalization"]:
        # The Python reporting boundary owns checking each row against the
        # selected manifest hash; Java receives that hash directly in Selection.
        manifest = {"fixtureSetId": "arithmetic-test-only", "fixtureHash": METRICS_PARITY["fixtureHash"],
                    "cases": vector["cases"]}
        raw = {"reportVersion": "FUSE-EVALUATION-2", "resultsSource": "JAVA_POSTGRES_EXECUTION", "experimentId": "arithmetic-test-only",
               "status": "COMPLETED", "modelMode": vector["modelMode"], "syntheticModelOutputs": vector["modelMode"] == "REPLAY",
               "caseOutputs": [row.model_dump() for row in rows]}
        actual = normalize_java_report(raw, manifest, vector["modelMode"], vector["repeatCount"]).metrics
    else:
        actual = calculate_metrics(vector["cases"], rows, vector["repeatCount"], vector["modelMode"])
    assert actual == vector["expected"]


@pytest.mark.parametrize("repeat_count", [0, -1])
def test_metrics_reject_nonpositive_planned_repeats(repeat_count):
    with pytest.raises(ValueError):
        calculate_metrics([{"caseId": "C", "kind": "ATTACK"}], [], repeat_count, "REPLAY")


def test_metrics_reject_results_beyond_planned_repeats():
    with pytest.raises(ValueError):
        calculate_metrics([{"caseId": "C", "kind": "ATTACK"}], [result("C", "FUSE", repeat=2)], 1, "REPLAY")


def test_metrics_row_contract_rejects_repeat_zero():
    with pytest.raises(ValueError):
        result("C", "FUSE", repeat=0)


def test_cli_rejects_explicit_zero_repeats_without_replacing_it_with_default():
    from evaluation.scenario_runner import main
    assert main(["validate-fixtures", "--repeat-count", "0"]) == 2


def live_raw_report(status="COMPLETED"):
    vector = next(v for v in METRICS_PARITY["vectors"] if v["name"] == "live-valid-shared-capture")
    rows = []
    for repeat in range(1, 4):
        for source in vector["rows"]:
            row = {**METRICS_PARITY["defaults"], **copy.deepcopy(source), "repeat": repeat}
            row["trace"]["modelCapture"]["captureRequestId"] = f"00000000-0000-4000-8000-{repeat:012d}"
            row["trace"]["modelCapture"]["captureRunId"] = f"00000000-0000-4000-8000-{repeat+10:012d}"
            rows.append(row)
    return {"reportVersion": "FUSE-EVALUATION-2", "resultsSource": "JAVA_POSTGRES_EXECUTION", "experimentId": "fake-live-only", "status": status,
            "modelMode": "LIVE", "syntheticModelOutputs": False, "caseOutputs": rows}, {
            "fixtureSetId": "arithmetic-test-only", "fixtureHash": METRICS_PARITY["fixtureHash"], "cases": vector["cases"]}


def test_normalization_requires_mode_attestation_and_no_replay_relabeling():
    raw, manifest = live_raw_report()
    for mode in (None, "REPLAY"):
        altered = {**raw, "modelMode": mode}
        with pytest.raises(ValueError): normalize_java_report(altered, manifest, "LIVE", 3)
    with pytest.raises(ValueError): normalize_java_report(raw, manifest, "REPLAY", 3)


def test_live_normalization_requires_three_repeats_and_non_synthetic_attestation():
    raw, manifest = live_raw_report()
    for synthetic in (None, True):
        with pytest.raises(ValueError): normalize_java_report({**raw, "syntheticModelOutputs": synthetic}, manifest, "LIVE", 3)
    for repeats in (1, 2, 4):
        with pytest.raises(ValueError): normalize_java_report(raw, manifest, "LIVE", repeats)


@pytest.mark.parametrize("status", ["COMPLETED", "FAILED", "INTERRUPTED"])
def test_live_robustness_flag_requires_completed_actual_eligible_pairs(status):
    raw, manifest = live_raw_report(status)
    report = normalize_java_report(raw, manifest, "LIVE", 3)
    assert report.metrics["commonEligibleAttackPairs"] == 3
    assert report.liveRobustnessMeasured is (status == "COMPLETED")
    assert report.syntheticModelOutputs is False
    for row in raw["caseOutputs"]:
        row["trace"] = {}
    report = normalize_java_report(raw, manifest, "LIVE", 3)
    assert report.metrics["commonEligibleAttackPairs"] == 0
    assert report.liveRobustnessMeasured is False
    assert all(excluded["reason"] == "LIVE_CAPTURE_MISSING" for excluded in report.metrics["exclusions"])


@pytest.mark.parametrize("changes,reason", [
    ({"pairedInputVersion": None, "pairedInputHash": None}, "PAIRED_INPUT_MISSING"),
    ({"pairedInputVersion": "FUSE-PAIRED-INPUT-99"}, "PAIRED_INPUT_VERSION_UNSUPPORTED"),
    ({"pairedInputHash": None}, "PAIRED_INPUT_MISSING"),
    ({"pairedInputHash": "c" * 64}, "UNPAIRED_INPUT"),
    ({"inputSnapshotHash": None}, "ARM_BINDING_MISSING"),
    ({"responseByteHash": None}, "ARM_BINDING_MISSING"),
    ({"trace": {"expectedPairedInputHash": "c" * 64}}, "UNPAIRED_INPUT"),
])
def test_pair_input_and_arm_binding_failures_exclude_the_whole_pair(changes, reason):
    cases = [{"caseId": "C", "kind": "ATTACK"}]
    rows = [result("C", "BASELINE"), result("C", "FUSE", **changes)]
    metrics = calculate_metrics(cases, rows, 1, "REPLAY")
    assert metrics["exclusions"] == [{"caseId": "C", "repeat": 1, "reason": reason}]
    for environment in ("BASELINE", "FUSE"):
        assert metrics["environments"][environment]["forbiddenActionBlockRate"] == {
            "numerator": 0, "denominator": 0, "rate": None}


def test_arm_specific_hashes_are_not_required_to_match_across_isolated_uuids():
    rows = [result("C", "BASELINE"), result("C", "FUSE", inputSnapshotHash="1" * 64, responseByteHash="2" * 64)]
    assert calculate_metrics([{"caseId": "C", "kind": "ATTACK"}], rows, 1, "REPLAY")["commonEligibleAttackPairs"] == 1


@pytest.mark.parametrize("version", [None, "FUSE-EVALUATION-1"])
def test_legacy_reports_keep_rows_but_cannot_become_eligible(version):
    raw, manifest = live_raw_report()
    if version is None:
        raw.pop("reportVersion")
    else:
        raw["reportVersion"] = version
    report = normalize_java_report(raw, manifest, "LIVE", 3)
    assert report.reportVersion == "FUSE-EVALUATION-2"
    assert report.inputReportVersion == (version or "UNSPECIFIED")
    assert len(report.caseOutputs) == 6
    assert report.liveRobustnessMeasured is False
    assert report.metrics["commonEligibleAttackPairs"] == 0
    assert {row["reason"] for row in report.metrics["exclusions"]} == {"PAIRED_INPUT_REPORT_VERSION_UNSUPPORTED"}


def test_unknown_report_version_is_not_silently_reinterpreted():
    raw, manifest = live_raw_report()
    with pytest.raises(ValueError, match="Unsupported backend report version"):
        normalize_java_report({**raw, "reportVersion": "FUSE-EVALUATION-99"}, manifest, "LIVE", 3)


@pytest.mark.parametrize("repeat_count", [2, 3, 10])
def test_replay_repeat_count_is_exactly_one(repeat_count):
    assert main(["validate-fixtures", "--model-mode", "REPLAY", "--repeat-count", str(repeat_count)]) == 2


def test_private_diagnostics_use_owner_only_modes(tmp_path):
    from evaluation.scenario_runner import write_json
    import stat
    target = tmp_path / "diagnostics" / "raw.json"
    write_json(target, {"synthetic": True})
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    target.chmod(0o644)
    write_json(target, {"synthetic": False})
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_cli_validation_errors_do_not_echo_private_model_text(monkeypatch, tmp_path, capsys):
    import evaluation.scenario_runner as runner
    marker = "SYNTHETIC_PRIVATE_DIAGNOSTIC_CANARY"
    manifest = load_fixture_set("mvp-security-v1", ["T02_MISSING_EVIDENCE"])
    row = result("T02_MISSING_EVIDENCE", "FUSE", fixtureHash=manifest["fixtureHash"]).model_dump()
    row["model"] = {"private": marker}
    raw = {"reportVersion": "FUSE-EVALUATION-2", "resultsSource": "JAVA_POSTGRES_EXECUTION",
           "modelMode": "REPLAY", "status": "COMPLETED", "experimentId": "synthetic", "caseOutputs": [row]}
    monkeypatch.setattr(runner, "execute_java", lambda *args: raw)
    assert runner.main(["run", "--fixture-set", "mvp-security-v1", "--case-id", "T02_MISSING_EVIDENCE", "--output", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err
    assert "ValidationError" in captured.err


def test_pair_input_canonical_bytes_match_shared_java_golden_vector():
    import hashlib
    vector = json.loads((Path(__file__).parent / "fixtures" / "paired-input-canonical.json").read_text())
    encoded = json.dumps(vector["canonical"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == vector["sha256"]
