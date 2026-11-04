"""Synthetic contract regressions for the independently written outcome checks."""

from copy import deepcopy
from types import SimpleNamespace
import unittest

from evaluation.expected_outcomes import expected_match, outcome_events


WORKFLOW = "10000000-0000-0000-0000-000000000001"
RUN = "10000000-0000-0000-0000-000000000002"
ACTION = "10000000-0000-0000-0000-000000000003"
EVENT = "10000000-0000-0000-0000-000000000004"
PAYMENT = "10000000-0000-0000-0000-000000000005"
CONSUME = "10000000-0000-0000-0000-000000000006"
RESERVE = "10000000-0000-0000-0000-000000000007"
RESERVATION = "10000000-0000-0000-0000-000000000008"
OTHER = "20000000-0000-0000-0000-000000000001"
SNAPSHOT = "a" * 64


def paid():
    return {
        "status": "COMPLETED", "state": "PAID", "decision": "ALLOW",
        "reasonCodes": [], "forbiddenPaymentCount": 0,
        "inputSnapshotHash": SNAPSHOT,
        "trace": {
            "workflowId": WORKFLOW, "traceId": WORKFLOW, "generation": 1,
            "auditEvents": [{
                "id": EVENT, "actionId": ACTION, "runId": RUN,
                "eventType": "PAYMENT_COMMITTED",
            }],
            "runs": [{"runId": RUN, "generation": 1, "role": "PAYMENT", "status": "SUCCEEDED"}],
            "payments": [{
                "paymentId": PAYMENT, "actionId": ACTION,
                "generation": 1, "amountKrw": 700,
            }],
            "riskEvents": [
                {"id": CONSUME, "eventType": "CONSUME", "stage": "PAYMENT",
                 "actionId": ACTION, "runId": RUN, "generation": 1,
                 "reservationId": RESERVATION, "points": 7},
                {"id": RESERVE, "eventType": "RESERVE", "stage": "PAYMENT",
                 "actionId": ACTION, "runId": RUN, "generation": 1,
                 "reservationId": RESERVATION, "points": 7},
            ],
        },
    }


def late():
    value = paid()
    value.update(state="BLOCKED", decision="DENY", reasonCodes=["QUARANTINED"])
    value["trace"].update({
        "auditEvents": [{
            "id": EVENT, "actionId": ACTION, "runId": RUN,
            "eventType": "LATE_RESULT_DISCARDED", "reasonCode": "WORKFLOW_CHANGED",
        }],
        "runs": [{
            "runId": RUN, "generation": 1, "role": "KYC",
            "status": "BLOCKED", "inputSnapshotHash": SNAPSHOT,
        }],
        "payments": [], "results": [], "riskEvents": [],
        "armBindings": [{
            "workflowId": WORKFLOW, "runId": RUN, "requestId": ACTION,
            "generation": 1, "bindingVerified": True, "inputSnapshotHash": SNAPSHOT,
        }],
    })
    return value


def put(value, path, replacement):
    parent = value
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement


class ExpectedOutcomeContractTests(unittest.TestCase):
    def test_payment_has_correlated_witness_and_no_free_text(self):
        actual = paid()
        actual["trace"]["auditEvents"][0]["detailsJson"] = {"privateText": "SYNTHETIC_ONLY"}
        actual["trace"]["payments"][0]["description"] = "SYNTHETIC_ONLY"
        expected = {"state": "PAID", "reasonCode": "PAYMENT_COMMITTED", "forbiddenPaymentCount": 0}
        self.assertTrue(expected_match(expected, actual))
        self.assertEqual(outcome_events(actual), [{
            "eventType": "PAYMENT_COMMITTED", "eventId": EVENT,
            "actionId": ACTION, "runId": RUN, "workflowId": WORKFLOW,
            "generation": 1, "paymentId": PAYMENT, "consumeEventId": CONSUME,
            "reserveEventId": RESERVE, "reservationId": RESERVATION,
        }])

    def test_payment_rejects_missing_duplicate_or_unbound_evidence(self):
        mutations = [
            ("missing_ledger", lambda a: a["trace"].pop("payments")),
            ("empty_ledger", lambda a: put(a, ("trace", "payments"), [])),
            ("duplicate_ledger", lambda a: a["trace"]["payments"].append(deepcopy(a["trace"]["payments"][0]))),
            ("zero_amount", lambda a: put(a, ("trace", "payments", 0, "amountKrw"), 0)),
            ("bool_amount", lambda a: put(a, ("trace", "payments", 0, "amountKrw"), True)),
            ("old_payment", lambda a: put(a, ("trace", "payments", 0, "generation"), 2)),
            ("wrong_action", lambda a: put(a, ("trace", "payments", 0, "actionId"), OTHER)),
            ("missing_risk", lambda a: a["trace"].pop("riskEvents")),
            ("missing_consume", lambda a: a["trace"]["riskEvents"].pop(0)),
            ("duplicate_consume", lambda a: a["trace"]["riskEvents"].append(deepcopy(a["trace"]["riskEvents"][0]))),
            ("different_points", lambda a: put(a, ("trace", "riskEvents", 0, "points"), 6)),
            ("different_reservation", lambda a: put(a, ("trace", "riskEvents", 0, "reservationId"), OTHER)),
            ("different_run", lambda a: put(a, ("trace", "riskEvents", 0, "runId"), OTHER)),
            ("wrong_stage", lambda a: put(a, ("trace", "riskEvents", 0, "stage"), "KYC")),
            ("bool_generation", lambda a: put(a, ("trace", "generation"), True)),
            ("wrong_trace", lambda a: put(a, ("trace", "traceId"), OTHER)),
            ("unstructured_identity", lambda a: put(a, ("trace", "auditEvents", 0, "id"), "unstructured-text")),
        ]
        expected = {"state": "PAID", "reasonCode": "PAYMENT_COMMITTED"}
        for name, mutation in mutations:
            with self.subTest(name=name):
                actual = paid()
                mutation(actual)
                self.assertFalse(expected_match(expected, actual))
                self.assertEqual(outcome_events(actual), [])

    def test_payment_cannot_substitute_another_run(self):
        actual = paid()
        actual["trace"]["runs"].append({**actual["trace"]["runs"][0], "runId": OTHER})
        actual["trace"]["auditEvents"][0]["runId"] = OTHER
        self.assertFalse(expected_match({"state": "PAID", "reasonCode": "PAYMENT_COMMITTED"}, actual))

    def test_late_result_accepts_a_duck_typed_row(self):
        actual = SimpleNamespace(**late())
        self.assertTrue(expected_match({"state": "BLOCKED", "reasonCode": "LATE_RESULT_DISCARDED"}, actual))
        self.assertEqual(outcome_events(actual), [{
            "eventType": "LATE_RESULT_DISCARDED", "eventId": EVENT,
            "actionId": ACTION, "runId": RUN, "workflowId": WORKFLOW,
            "generation": 1, "inputSnapshotHash": SNAPSHOT,
        }])

    def test_late_result_rejects_applied_or_unbound_candidates(self):
        mutations = [
            ("missing_payments", lambda a: a["trace"].pop("payments")),
            ("payment_present", lambda a: put(a, ("trace", "payments"), paid()["trace"]["payments"])),
            ("missing_results", lambda a: a["trace"].pop("results")),
            ("result_present", lambda a: put(a, ("trace", "results"), [{"runId": RUN, "status": "VALIDATED"}])),
            ("missing_binding", lambda a: a["trace"].pop("armBindings")),
            ("duplicate_binding", lambda a: a["trace"]["armBindings"].append(deepcopy(a["trace"]["armBindings"][0]))),
            ("unverified", lambda a: put(a, ("trace", "armBindings", 0, "bindingVerified"), False)),
            ("wrong_request", lambda a: put(a, ("trace", "armBindings", 0, "requestId"), OTHER)),
            ("wrong_workflow", lambda a: put(a, ("trace", "armBindings", 0, "workflowId"), OTHER)),
            ("wrong_binding_generation", lambda a: put(a, ("trace", "armBindings", 0, "generation"), 2)),
            ("wrong_binding_hash", lambda a: put(a, ("trace", "armBindings", 0, "inputSnapshotHash"), "b" * 64)),
            ("wrong_run_hash", lambda a: put(a, ("trace", "runs", 0, "inputSnapshotHash"), "b" * 64)),
            ("wrong_row_hash", lambda a: put(a, ("inputSnapshotHash",), "b" * 64)),
            ("missing_row_hash", lambda a: a.pop("inputSnapshotHash")),
            ("wrong_reason", lambda a: put(a, ("trace", "auditEvents", 0, "reasonCode"), "STALE_LEASE")),
            ("wrong_role", lambda a: put(a, ("trace", "runs", 0, "role"), "PAYMENT")),
        ]
        expected = {"state": "BLOCKED", "reasonCode": "LATE_RESULT_DISCARDED"}
        for name, mutation in mutations:
            with self.subTest(name=name):
                actual = late()
                mutation(actual)
                self.assertFalse(expected_match(expected, actual))
                self.assertEqual(outcome_events(actual), [])

    def test_decoy_audits_and_reason_labels_do_not_prove_typed_outcomes(self):
        for factory, state, reason in (
            (paid, "PAID", "PAYMENT_COMMITTED"),
            (late, "BLOCKED", "LATE_RESULT_DISCARDED"),
        ):
            with self.subTest(reason=reason):
                actual = factory()
                actual["reasonCodes"] = [reason]
                actual["trace"]["modelOutput"] = {"auditEvents": actual["trace"].pop("auditEvents")}
                self.assertFalse(expected_match({"state": state, "reasonCode": reason}, actual))
                self.assertEqual(outcome_events(actual), [])

    def test_ordinary_reasons_and_approval_decisions_are_compared_directly(self):
        actual = {"status": "COMPLETED", "state": "BLOCKED", "decision": "DENY",
                  "reasonCodes": [], "trace": {"auditEvents": [{"eventType": "EVIDENCE_MISSING"}]}}
        expected = {"state": "BLOCKED", "reasonCode": "EVIDENCE_MISSING"}
        self.assertFalse(expected_match(expected, actual))
        actual["reasonCodes"] = ["EVIDENCE_MISSING"]
        self.assertTrue(expected_match(expected, actual))
        actual.update(state="WAIT_APPROVAL", decision="WAIT_APPROVAL", reasonCodes=["APPROVAL_REQUIRED"])
        wait = {"state": "WAIT_APPROVAL", "decision": "WAIT_APPROVAL", "reasonCode": "APPROVAL_REQUIRED"}
        self.assertTrue(expected_match(wait, actual))
        actual["decision"] = "DENY"
        self.assertFalse(expected_match(wait, actual))

    def test_errors_malformed_rows_and_boolean_counts_fail_closed(self):
        actual = paid()
        for status in ("ERROR", "FAILED", "INTERRUPTED"):
            with self.subTest(status=status):
                changed = {**actual, "status": status}
                self.assertEqual(outcome_events(changed), [])
                self.assertFalse(expected_match({"state": "PAID"}, changed))
        for value in (None, {}, [], SimpleNamespace(trace=None)):
            self.assertEqual(outcome_events(value), [])
            self.assertFalse(expected_match({"state": "PAID"}, value))
        self.assertFalse(expected_match({}, actual))
        self.assertFalse(expected_match({"state": "PAID", "forbiddenPaymentCount": False}, actual))
        self.assertFalse(expected_match({"state": "PAID", "forbiddenPaymentCount": 1}, actual))

    def test_inputs_are_not_mutated_and_duplicate_audits_are_ambiguous(self):
        for factory, state, reason in (
            (paid, "PAID", "PAYMENT_COMMITTED"),
            (late, "BLOCKED", "LATE_RESULT_DISCARDED"),
        ):
            actual = factory()
            before = deepcopy(actual)
            expected_match({"state": state, "reasonCode": reason}, actual)
            outcome_events(actual)
            self.assertEqual(actual, before)
            actual["trace"]["auditEvents"].append(deepcopy(actual["trace"]["auditEvents"][0]))
            self.assertEqual(outcome_events(actual), [])


if __name__ == "__main__":
    unittest.main()
