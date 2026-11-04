"""New typed-outcome checks derived from the permitted public test contracts.

This is an independent implementation, not a recovered exporter. Only a fixed
set of typed identifiers is returned; free text and arbitrary trace fields are
never included in witnesses.
"""

from collections.abc import Mapping
import re
from typing import Any


__all__ = ("expected_match", "outcome_events")

_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_HASH = re.compile(r"[0-9a-fA-F]{64}")
_TYPED = {"PAYMENT_COMMITTED", "LATE_RESULT_DISCARDED"}
_DECISIONS = {"ALLOW", "DENY", "WAIT_APPROVAL"}
_MISSING = object()


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def _records(trace: Mapping, key: str) -> list | None:
    value = trace.get(key)
    if not isinstance(value, list) or not all(isinstance(row, Mapping) for row in value):
        return None
    return value


def _one(rows: list | None, key: str, value: Any) -> Mapping | None:
    if rows is None:
        return None
    selected = [row for row in rows if row.get(key) == value]
    return selected[0] if len(selected) == 1 else None


def _base(actual: Any, event: Mapping, trace: Mapping, event_type: str) -> tuple | None:
    workflow = trace.get("workflowId")
    generation = trace.get("generation")
    if (
        not _identifier(workflow)
        or trace.get("traceId") != workflow
        or not _positive_integer(generation)
        or not all(_identifier(event.get(key)) for key in ("id", "actionId", "runId"))
        or event.get("eventType") != event_type
    ):
        return None
    if "workflowId" in event and event["workflowId"] != workflow:
        return None
    if "generation" in event and (
        type(event["generation"]) is not int or event["generation"] != generation
    ):
        return None
    count = _get(actual, "forbiddenPaymentCount")
    if type(count) is not int or count < 0:
        return None
    run = _one(_records(trace, "runs"), "runId", event["runId"])
    if (
        run is None
        or type(run.get("generation")) is not int
        or run["generation"] != generation
        or ("workflowId" in run and run["workflowId"] != workflow)
    ):
        return None
    witness = {
        "eventType": event_type,
        "eventId": event["id"],
        "actionId": event["actionId"],
        "runId": event["runId"],
        "workflowId": workflow,
        "generation": generation,
    }
    return run, witness


def _payment(actual: Any, event: Mapping, trace: Mapping) -> dict | None:
    base = _base(actual, event, trace, "PAYMENT_COMMITTED")
    if base is None:
        return None
    run, witness = base
    if (
        _get(actual, "state") != "PAID"
        or _get(actual, "decision") != "ALLOW"
        or run.get("role") != "PAYMENT"
        or run.get("status") != "SUCCEEDED"
    ):
        return None
    payment = _one(_records(trace, "payments"), "actionId", event["actionId"])
    if (
        payment is None
        or not _identifier(payment.get("paymentId"))
        or type(payment.get("generation")) is not int
        or payment["generation"] != witness["generation"]
        or not _positive_integer(payment.get("amountKrw"))
    ):
        return None
    risk = _records(trace, "riskEvents")
    if risk is None:
        return None
    action_risk = [row for row in risk if row.get("actionId") == event["actionId"]]
    consume = _one(action_risk, "eventType", "CONSUME")
    reserve = _one(action_risk, "eventType", "RESERVE")
    if consume is None or reserve is None:
        return None
    for row in (consume, reserve):
        if (
            not _identifier(row.get("id"))
            or row.get("stage") != "PAYMENT"
            or row.get("runId") != event["runId"]
            or type(row.get("generation")) is not int
            or row["generation"] != witness["generation"]
            or not _identifier(row.get("reservationId"))
            or not _positive_integer(row.get("points"))
        ):
            return None
    if (
        consume["id"] == reserve["id"]
        or consume["reservationId"] != reserve["reservationId"]
        or consume["points"] != reserve["points"]
    ):
        return None
    witness.update({
        "paymentId": payment["paymentId"],
        "consumeEventId": consume["id"],
        "reserveEventId": reserve["id"],
        "reservationId": consume["reservationId"],
    })
    return witness


def _late_result(actual: Any, event: Mapping, trace: Mapping) -> dict | None:
    base = _base(actual, event, trace, "LATE_RESULT_DISCARDED")
    if base is None:
        return None
    run, witness = base
    if (
        _get(actual, "state") != "BLOCKED"
        or _get(actual, "decision") != "DENY"
        or _get(actual, "forbiddenPaymentCount") != 0
        or run.get("role") != "KYC"
        or run.get("status") != "BLOCKED"
        or event.get("reasonCode") != "WORKFLOW_CHANGED"
        or _records(trace, "payments") != []
        or _records(trace, "results") != []
    ):
        return None
    binding = _one(_records(trace, "armBindings"), "runId", event["runId"])
    row_hash = _get(actual, "inputSnapshotHash")
    if (
        binding is None
        or binding.get("bindingVerified") is not True
        or binding.get("workflowId") != witness["workflowId"]
        or binding.get("requestId") != event["actionId"]
        or type(binding.get("generation")) is not int
        or binding["generation"] != witness["generation"]
        or not _hash(row_hash)
        or not _hash(run.get("inputSnapshotHash"))
        or not _hash(binding.get("inputSnapshotHash"))
        or run["inputSnapshotHash"] != row_hash
        or binding["inputSnapshotHash"] != row_hash
    ):
        return None
    witness["inputSnapshotHash"] = row_hash
    return witness


def outcome_events(actual: Any) -> list[dict]:
    """Return only unambiguous, correlated public typed-outcome witnesses.

    Malformed or incomplete data produces no witness. Identifiers are restricted
    to UUID strings and snapshot hashes to SHA256 hex, preventing arbitrary text
    from crossing this interface.
    """
    try:
        if _get(actual, "status") != "COMPLETED":
            return []
        trace = _get(actual, "trace")
        if not isinstance(trace, Mapping):
            return []
        events = _records(trace, "auditEvents")
        if events is None:
            return []
        witnesses = []
        for event_type, checker in (
            ("PAYMENT_COMMITTED", _payment),
            ("LATE_RESULT_DISCARDED", _late_result),
        ):
            event = _one(events, "eventType", event_type)
            if event is None:
                continue
            if sum(row.get("id") == event.get("id") for row in events) != 1:
                continue
            witness = checker(actual, event, trace)
            if witness is not None:
                witnesses.append(witness)
        return witnesses
    except (AttributeError, KeyError, TypeError, ValueError):
        return []


def expected_match(expected: Any, actual: Any) -> bool:
    """Check the declared state, decision, reason and optional payment count.

    Typed outcome reason codes require correlated witnesses, never a reason-code
    label or a nested trace lookalike. Unknown or incomplete inputs fail closed.
    """
    try:
        if not isinstance(expected, Mapping) or _get(actual, "status") != "COMPLETED":
            return False
        state = expected.get("state")
        if not isinstance(state, str) or not state or _get(actual, "state") != state:
            return False
        decision = _get(actual, "decision")
        if decision not in _DECISIONS:
            return False
        expected_decision = expected.get("decision")
        if expected_decision is not None and decision != expected_decision:
            return False
        if "forbiddenPaymentCount" in expected:
            wanted = expected["forbiddenPaymentCount"]
            observed = _get(actual, "forbiddenPaymentCount", _MISSING)
            if type(wanted) is not int or wanted < 0 or type(observed) is not int or observed != wanted:
                return False
        reason = expected.get("reasonCode")
        if reason is None:
            return True
        if not isinstance(reason, str) or not reason:
            return False
        if reason in _TYPED:
            return len([item for item in outcome_events(actual) if item["eventType"] == reason]) == 1
        reasons = _get(actual, "reasonCodes")
        return isinstance(reasons, list) and reason in reasons
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
