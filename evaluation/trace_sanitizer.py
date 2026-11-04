"""Public metadata projection. Unknown metadata is omitted rather than fingerprinted."""
from __future__ import annotations

import json
from pathlib import Path
import re

from .fixture_loader import fingerprint

PUBLIC_LABELS = frozenset(json.loads(Path(__file__).with_name("export_labels.json").read_text(
    encoding="utf-8"))["labels"])
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def safe_label(value):
    if value is None:
        return None
    return value if isinstance(value, str) and value in PUBLIC_LABELS else None


def safe_identifier(value):
    if value is None:
        return None
    if isinstance(value, str) and (_UUID.fullmatch(value) or _HASH.fullmatch(value)):
        return value
    return None


def _project(source, fields):
    if not isinstance(source, dict):
        return {}
    result = {}
    for key, kind in fields.items():
        if key not in source:
            continue
        value = source[key]
        if kind == "label":
            result[key] = safe_label(value)
        elif kind == "id":
            result[key] = safe_identifier(value)
        elif kind == "hash" and isinstance(value, str) and _HASH.fullmatch(value):
            result[key] = value
        elif kind == "int" and type(value) is int and value >= 0:
            result[key] = value
        elif kind == "bool" and type(value) is bool:
            result[key] = value
    return result


def sanitize_trace(trace: dict) -> dict:
    if not isinstance(trace, dict):
        raise ValueError("trace must be an object")
    result = {}
    common = {
        "id": "id", "workflowId": "id", "traceId": "id", "actionId": "id",
        "runId": "id", "requestId": "id", "generation": "int",
        "role": "label", "status": "label", "reasonCode": "label",
        "eventType": "label", "paymentId": "id", "reservationId": "id",
        "inputSnapshotHash": "hash", "responseByteHash": "hash",
        "bindingVerified": "bool", "amountKrw": "int", "points": "int", "stage": "label",
    }
    for key in ("traceId", "workflowId"):
        if key in trace:
            result[key] = safe_identifier(trace[key])
    for key in ("actionRuns", "payments", "riskEvents", "auditEvents", "armBindings"):
        value = trace.get(key)
        if isinstance(value, list):
            result[key] = [_project(row, common) for row in value if isinstance(row, dict)]
        elif key == "armBindings" and isinstance(value, dict):
            result[key] = _project(value, common)
    capture = trace.get("modelCapture")
    if isinstance(capture, dict):
        projected = _project(capture, {
            "modelMode": "label", "model": "label", "promptVersion": "label",
            "promptHash": "hash", "modelOutputHash": "hash", "inputSnapshotHash": "hash",
            "captureRequestId": "id", "captureRunId": "id",
        })
        candidate = capture.get("sanitizedCandidate")
        if isinstance(candidate, dict):
            clean = _project(candidate, {"status": "label"})
            if isinstance(candidate.get("evidenceIds"), list):
                clean["evidenceIds"] = [safe_identifier(v) for v in candidate["evidenceIds"]]
            projected["sanitizedCandidate"] = clean
        result["modelCapture"] = projected
    if isinstance(trace.get("quarantineMeasurement"), dict):
        result["quarantineMeasurement"] = _project(trace["quarantineMeasurement"], {
            "measurementVersion": "label", "causeType": "label", "jobId": "id",
            "workflowId": "id", "runId": "id", "actionId": "id",
            "generation": "int", "elapsedNanos": "int", "attempt": "int",
        })
    if "expectedPairedInputHash" in trace:
        result.update(_project(trace, {"expectedPairedInputHash": "hash"}))
    result["sanitizedTraceHash"] = fingerprint(result)
    return result
