"""New evidence exporter derived from public models and ordinary test contracts."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

from pydantic import ValidationError

from .expected_outcomes import expected_match as _expected_match, outcome_events
from .bundle_writer import write_bundle
from .fixture_loader import fingerprint, load_fixture_set
from .metrics import calculate_metrics
from .report import CaseOutput, EvaluationReport
from .trace_sanitizer import safe_identifier, safe_label, sanitize_trace

_SPLITS = ("DEV", "TUNE", "FINAL", "NORMAL")
_COLUMNS = (
    "caseId", "kind", "split", "family", "environment", "repeat", "workflowId",
    "observationStatus", "actualState", "actualDecision", "actualReasonCodes",
    "actualOutcomeEvents", "expectedEndState", "expectedDecision", "expectedReasonCode",
    "expectedReasonEvidenceType", "expectedMatch", "includedInCommonDenominator",
    "commonExclusionReason", "attackAttemptEstablished", "forbiddenGoalOccurred",
    "forbiddenPaymentCount", "forbiddenPaidAmountKrw", "actualDownstreamDepth",
    "ledgerPaymentCount", "ledgerPaidAmountKrw", "securityCheckDurationMs",
    "quarantineLatencyMs", "fixtureHash", "pairedInputVersion", "pairedInputHash",
    "inputSnapshotHash", "responseByteHash", "modelOutputHash", "model",
    "promptVersion", "policyVersion", "mockReviewerVersion", "sanitizedResultHash", "trace",
)
_UNAVAILABLE_ON_ERROR = (
    "expectedMatch", "attackAttemptEstablished", "forbiddenGoalOccurred",
    "forbiddenPaymentCount", "forbiddenPaidAmountKrw", "actualDownstreamDepth",
    "ledgerPaymentCount", "ledgerPaidAmountKrw", "securityCheckDurationMs", "quarantineLatencyMs",
)


def _split(case):
    value = case.get("split", "NORMAL" if case.get("kind") == "NORMAL" else "DEV")
    value = "DEV" if value == "DEVELOPMENT" else value
    if value not in _SPLITS:
        raise ValueError("unsupported split")
    return value


def calculate_split_metrics(cases, caseOutputs, repeat_count, model_mode):
    result = {}
    for split in _SPLITS[:3]:
        selected = [case for case in cases if _split(case) == split]
        ids = {case["caseId"] for case in selected}
        result[split] = calculate_metrics(selected, [r for r in caseOutputs if r.caseId in ids],
                                          repeat_count, model_mode)
    return result


def _counts(cases):
    return {split: sum(_split(case) == split for case in cases) for split in _SPLITS}


def _public_case_ids(cases):
    """Give omitted identifiers unique plan-local labels, independent of their text."""
    result = {case["caseId"]: safe_label(case["caseId"]) for case in cases}
    occupied = {value for value in result.values() if value is not None}
    ordinal = 1
    for case in cases:
        if result[case["caseId"]] is not None:
            continue
        while f"PUBLIC_CASE_{ordinal}" in occupied:
            ordinal += 1
        value = f"PUBLIC_CASE_{ordinal}"
        result[case["caseId"]] = value
        occupied.add(value)
        ordinal += 1
    return result


def _row(case, environment, repeat, observed, exclusion, public_case_id):
    expected = case.get("expected", {}).get(environment, {})
    if not isinstance(expected, dict):
        raise ValueError("invalid expected result")
    row = dict.fromkeys(_COLUMNS)
    row.update(caseId=public_case_id, kind=safe_label(case["kind"]),
               split=_split(case), family=safe_label(case.get("family")), environment=environment,
               repeat=repeat, observationStatus="NOT_RUN" if observed is None else observed.status,
               actualReasonCodes=[], actualOutcomeEvents=[],
               expectedEndState=safe_label(expected.get("state")),
               expectedDecision=safe_label(expected.get("decision")),
               expectedReasonCode=safe_label(expected.get("reasonCode")),
               expectedReasonEvidenceType=("AUDIT_EVENT" if expected.get("reasonCode") in
                   ("PAYMENT_COMMITTED", "LATE_RESULT_DISCARDED") else
                   "REASON_CODE" if expected.get("reasonCode") else None),
               includedInCommonDenominator=exclusion is None, commonExclusionReason=safe_label(exclusion))
    if observed is None:
        return row
    source = observed.model_dump()
    trace = observed.trace
    events = outcome_events(observed)
    for event in events:
        for key in ("eventId", "actionId", "runId", "workflowId", "paymentId",
                    "consumeEventId", "reserveEventId", "reservationId"):
            if key in event:
                event[key] = safe_identifier(event[key])
    payments = trace.get("payments")
    ledger = payments if isinstance(payments, list) else None
    row.update(workflowId=safe_identifier(trace.get("traceId") or trace.get("workflowId")),
               observationStatus=safe_label(observed.status), actualState=safe_label(observed.state),
               actualDecision=safe_label(observed.decision),
               actualReasonCodes=[safe_label(v) for v in observed.reasonCodes],
               actualOutcomeEvents=events, expectedMatch=_expected_match(expected, observed),
               attackAttemptEstablished=observed.attackInduced if case["kind"] == "ATTACK" else None,
               forbiddenGoalOccurred=observed.forbiddenPaymentCount > 0 if case["kind"] == "ATTACK" else None,
               forbiddenPaymentCount=observed.forbiddenPaymentCount,
               forbiddenPaidAmountKrw=observed.forbiddenPaidAmountKrw,
               actualDownstreamDepth=observed.actualDownstreamDepth,
               ledgerPaymentCount=len(ledger) if ledger is not None else None,
               ledgerPaidAmountKrw=sum(p.get("amountKrw", 0) for p in ledger
                   if isinstance(p, dict) and type(p.get("amountKrw", 0)) is int) if ledger is not None else None,
               securityCheckDurationMs=observed.securityCheckDurationMs,
               quarantineLatencyMs=observed.quarantineLatencyMs,
               trace=sanitize_trace(trace))
    for key in ("fixtureHash", "pairedInputHash", "inputSnapshotHash", "responseByteHash", "modelOutputHash"):
        row[key] = source[key]
    for key in ("pairedInputVersion", "model", "promptVersion", "policyVersion", "mockReviewerVersion"):
        row[key] = safe_label(source[key])
    if observed.status == "ERROR" or observed.decision == "ERROR":
        row.update(dict.fromkeys(_UNAVAILABLE_ON_ERROR))
    row["sanitizedResultHash"] = fingerprint({
        key: value for key, value in row.items() if key != "sanitizedResultHash"
    })
    return row


def _redact_metrics(metrics, case_ids):
    return {**metrics, "exclusions": [
        {"caseId": case_ids[row["caseId"]], "repeat": row["repeat"],
         "reason": safe_label(row["reason"])} for row in metrics["exclusions"]
    ]}


def _registered_counts(manifest, cases):
    selected = _counts(cases)
    count = manifest.get("registeredPlannedCaseCount", len(cases))
    splits = manifest.get("registeredSplitCaseCounts", selected)
    if type(count) is not int or count < len(cases):
        raise ValueError("invalid registered case count")
    if (not isinstance(splits, dict) or set(splits) != set(_SPLITS)
            or any(type(splits[key]) is not int or splits[key] < selected[key] for key in _SPLITS)
            or sum(splits.values()) != count):
        raise ValueError("invalid registered split counts")
    return count, {key: splits[key] for key in _SPLITS}


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _reject_undeclared_model_fields(value, declared_model):
    # model_copy(update=...) can put unknown keys in __dict__ even when extra is
    # forbidden; serialization would omit them before schema validation sees them.
    fields = object.__getattribute__(value, "__dict__")
    extra = object.__getattribute__(value, "__pydantic_extra__")
    if any(key not in declared_model.model_fields for key in fields) or extra:
        raise ValueError("invalid evaluation report")


def _reject_undeclared_case_fields(outputs):
    if isinstance(outputs, (list, tuple)):
        for output in outputs:
            if isinstance(output, CaseOutput):
                _reject_undeclared_model_fields(output, CaseOutput)


def _validated_report(value):
    try:
        if isinstance(value, EvaluationReport):
            _reject_undeclared_model_fields(value, EvaluationReport)
            _reject_undeclared_case_fields(object.__getattribute__(value, "__dict__").get("caseOutputs"))
            # model_copy and later mutation do not revalidate the root model.
            # Re-enter through plain values, suppressing invalid-value dump warnings.
            value = value.model_dump(mode="python", round_trip=True, warnings=False)
        else:
            if not isinstance(value, dict):
                raise ValueError("report must be an object")
            value = dict(value)
            if value.get("reportVersion") == "FUSE-EVALUATION-1":
                value["reportVersion"] = "FUSE-EVALUATION-2"
                value["inputReportVersion"] = "FUSE-EVALUATION-1"
            _reject_undeclared_case_fields(value.get("caseOutputs"))
        report = EvaluationReport.model_validate(value)
    except (ValidationError, TypeError, ValueError):
        raise ValueError("invalid evaluation report") from None
    if report.inputReportVersion not in ("FUSE-EVALUATION-1", "FUSE-EVALUATION-2"):
        raise ValueError("unsupported input report version")
    return report


def export_evidence_bundle(report, manifest, output_root):
    report = _validated_report(report)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", report.experimentId) or ".." in report.experimentId:
        raise ValueError("invalid experiment identifier")
    if not isinstance(manifest, dict) or manifest.get("fixtureHash") != report.fixtureHash:
        raise ValueError("fixture hash does not match")
    if manifest.get("fixtureSetId", report.fixtureSetId) != report.fixtureSetId:
        raise ValueError("fixture identifier does not match")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or any(not isinstance(c, dict) for c in cases):
        raise ValueError("invalid selected plan")
    ids = [c.get("caseId") for c in cases]
    if (any(not isinstance(v, str) or not v for v in ids) or len(set(ids)) != len(ids)
            or len(set(report.plannedCaseIds)) != len(report.plannedCaseIds)
            or set(ids) != set(report.plannedCaseIds)):
        raise ValueError("selected plan does not match")
    if any(c.get("kind") not in ("ATTACK", "NORMAL") for c in cases):
        raise ValueError("invalid case kind")
    registered_count, registered_splits = _registered_counts(manifest, cases)
    public_case_ids = _public_case_ids(cases)
    overall = calculate_metrics(cases, report.caseOutputs, report.repeatCount, report.modelMode)
    exclusions = {(r["caseId"], r["repeat"]): r["reason"] for r in overall["exclusions"]}
    observed = {(r.caseId, r.repeat, r.environment): r for r in report.caseOutputs}
    rows = [_row(case, env, repeat, observed.get((case["caseId"], repeat, env)),
                 exclusions.get((case["caseId"], repeat)), public_case_ids[case["caseId"]])
            for case in cases for repeat in range(1, report.repeatCount + 1) for env in ("BASELINE", "FUSE")]
    by_split = calculate_split_metrics(cases, report.caseOutputs, report.repeatCount, report.modelMode)
    metric_data = {"overall": _redact_metrics(overall, public_case_ids), "bySplit": {
        key: _redact_metrics(value, public_case_ids) for key, value in by_split.items()}}
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, separators=(",", ":"), ensure_ascii=False)
                         if value is None or isinstance(value, (list, dict, bool)) else value
                         for key, value in row.items()})
    payloads = {
        "case_results.json": _json_bytes(rows),
        "case_results.csv": stream.getvalue().encode("utf-8"),
        "metrics.json": _json_bytes(metric_data),
    }
    bundle = {
        "bundleVersion": "FUSE-EVIDENCE-BUNDLE-2", "sourceReportVersion": report.reportVersion,
        "inputReportVersion": report.inputReportVersion,
        "sourceReportStatus": report.status,
        "experimentId": report.experimentId, "fixtureHash": report.fixtureHash,
        "fixtureSetId": safe_label(report.fixtureSetId),
        "selectedCaseCount": len(cases), "actualEnvironmentResultCount": len(report.caseOutputs),
        "exportedEnvironmentRowCount": len(rows), "splitCaseCounts": _counts(cases),
        "registeredPlannedCaseCount": registered_count,
        "registeredSplitCaseCounts": registered_splits,
        "provenanceVersions": {"pairedInputVersion": sorted({r.pairedInputVersion
            for r in report.caseOutputs if r.pairedInputVersion == "FUSE-PAIRED-INPUT-1"})},
        "implementationStatus": "NEW_PUBLIC_CONTRACT_IMPLEMENTATION",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                  for name, data in payloads.items()},
    }
    # Fingerprint only fields already included in the public projection. Original
    # requests, free-text metadata and unexported report fields are not inputs.
    plan_fields = ("caseId", "kind", "split", "family", "environment",
                   "expectedEndState", "expectedDecision", "expectedReasonCode",
                   "expectedReasonEvidenceType")
    bundle["sanitizedFixturePlanHash"] = fingerprint([
        {key: row[key] for key in plan_fields} for row in rows if row["repeat"] == 1
    ])
    bundle["sanitizedReportHash"] = fingerprint({
        "manifest": bundle, "caseResults": rows, "metrics": metric_data,
    })
    payloads["manifest.json"] = _json_bytes(bundle)
    return write_bundle(output_root, report.experimentId, payloads)


def _strict_json(path):
    # A byte cap cannot bound a blocking FIFO open or admit a device as a
    # stored report. Preserve symlink-to-regular-file compatibility; this is
    # file-type admission, not an ancestor/symlink isolation boundary.
    limit = 8 * 1024 * 1024
    if not hasattr(os, "O_NONBLOCK"):
        raise ValueError("regular input files are unavailable")
    fd = os.open(Path(path), os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("input must be a regular file")
        if info.st_size > limit:
            raise ValueError("input is too large")
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > limit:
            raise ValueError("input is too large")
    finally:
        os.close(fd)
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def reject_constant(_value):
        raise ValueError("nonfinite JSON value")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    pending = [(value, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > 64:
            raise ValueError("JSON is too deep")
        if isinstance(node, dict):
            pending.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            pending.extend((child, depth + 1) for child in node)
    return value


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("invalid arguments")


def main(argv=None):
    parser = _Parser(description="Export an explicit stored evaluation report.")
    parser.add_argument("--report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", help="Explicit approved fixture plan; no bundled private data is loaded.")
    try:
        args = parser.parse_args(argv)
        report = _validated_report(_strict_json(args.report))
        manifest = (_strict_json(args.manifest) if args.manifest else
                    load_fixture_set(report.fixtureSetId, report.plannedCaseIds))
        destination = export_evidence_bundle(report, manifest, args.output)
        print(json.dumps({"bundle": str(destination), "experimentId": report.experimentId}))
        return 0
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Invalid evaluation input.", file=sys.stderr)
        return 2
