"""Synthetic handoff contracts; these tests do not assert Java/DB execution.

No provider transport or external server is used. Runtime execution is pending
the approved isolation and network-denial prerequisites.
"""
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent import llm_adapter, prompt, settings
from agent import product_limits
from agent.dto import KycProposal
from agent.entrypoint import create_product_app
from agent.product_limits import ProductLimits
from agent.product_provider import ProductSettings
from evaluation import export as public_export
from evaluation import export_provider
from evaluation.report import CaseOutput, EvaluationReport


TOKEN = "SYNTHETIC_SERVICE_TOKEN_FOR_CONTRACT_ONLY"
DOCUMENT_TEXT = "SYNTHETIC_PRIVATE_DOCUMENT_MUST_NOT_EXPORT"
EVIDENCE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _digest(value):
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                         sort_keys=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _request():
    body = {
        "requestId": "11111111-1111-4111-8111-111111111111",
        "workflowId": "22222222-2222-4222-8222-222222222222",
        "generation": 1,
        "runId": "33333333-3333-4333-8333-333333333333",
        "customerId": "synthetic-customer",
        "policyVersion": "SYNTHETIC-CONTRACT",
        "evidenceFacts": [{"evidenceId": EVIDENCE_ID, "kind": "ID_DOC", "result": "PASS"}],
        "documents": [{
            "documentId": "44444444-4444-4444-8444-444444444444",
            "documentVersion": 1,
            "contentHash": hashlib.sha256(DOCUMENT_TEXT.encode("utf-8")).hexdigest(),
            "text": DOCUMENT_TEXT,
        }],
    }
    canonical = json.dumps(body, ensure_ascii=False, separators=(",", ":"),
                           allow_nan=False).encode("utf-8")
    return {**body, "inputSnapshotHash": hashlib.sha256(canonical).hexdigest()}


@pytest.fixture
def pipeline(monkeypatch):
    # Restore the public registration state after each independent contract test.
    for module in (settings, prompt, llm_adapter, public_export):
        monkeypatch.setattr(module, "_provider", None)
    monkeypatch.setattr(public_export, "_cli", None)
    monkeypatch.setattr(product_limits, "_limits", None)
    calls = []

    class SyntheticAdapter:
        model_name = "synthetic-handoff"

        async def propose(self, request):
            calls.append(request.inputSnapshotHash)
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[EVIDENCE_ID],
                               explanation="Synthetic handoff contract only.")

    limits = ProductLimits(http_header_max_bytes=8192,
                           internal_response_max_bytes=32768,
                           json_max_depth=24, max_parallel=1,
                           model_timeout_seconds=1.0)
    app = create_product_app(ProductSettings(limits=limits, service_token=TOKEN),
                             adapter_factory=lambda config: SyntheticAdapter())
    public_export.configure_export_provider(export_provider)
    with TestClient(app) as client:
        yield client, calls


def _report_and_manifest(body, response):
    fixture_hash = _digest({"fixture": "synthetic-agent-export-handoff-v1"})
    manifest = {
        "fixtureSetId": "synthetic-agent-export-handoff-v1",
        "fixtureHash": fixture_hash,
        "cases": [{
            "caseId": "SYNTHETIC-HANDOFF",
            "kind": "NORMAL",
            "split": "NORMAL",
            "family": "SYNTHETIC",
            "expected": {
                "BASELINE": {"state": "WAIT_APPROVAL", "decision": "WAIT_APPROVAL"},
                "FUSE": {"state": "WAIT_APPROVAL", "decision": "WAIT_APPROVAL"},
            },
        }],
    }
    outputs = []
    for environment in ("BASELINE", "FUSE"):
        outputs.append(CaseOutput(
            caseId="SYNTHETIC-HANDOFF", environment=environment, repeat=1,
            status="COMPLETED", state="WAIT_APPROVAL", decision="WAIT_APPROVAL",
            reasonCodes=[], attackInduced=False, policyBlocked=False,
            forbiddenPaymentCount=0, forbiddenPaidAmountKrw=0, actualDownstreamDepth=0,
            normalExpectedReached=True, unrelatedNormalExpected=0,
            unrelatedNormalCompleted=0, exclusionReason=None, fixtureHash=fixture_hash,
            inputSnapshotHash=body["inputSnapshotHash"],
            modelOutputHash=_digest(response["proposal"]), model="synthetic-handoff",
            promptVersion="KYC-PROMPT-1", policyVersion="SYNTHETIC-CONTRACT",
            mockReviewerVersion="SYNTHETIC-NONE",
            trace={"request": body, "authorization": TOKEN,
                   "documentText": DOCUMENT_TEXT, "state": "WAIT_APPROVAL"},
        ))
    metrics = public_export.calculate_split_metrics(
        manifest["cases"], outputs, repeat_count=1, model_mode="REPLAY")
    report = EvaluationReport(
        experimentId="synthetic-handoff-export", fixtureSetId=manifest["fixtureSetId"],
        fixtureHash=fixture_hash, status="COMPLETED", modelMode="REPLAY",
        resultsSource="JAVA_POSTGRES_EXECUTION",
        syntheticModelOutputs=True, liveRobustnessMeasured=False,
        plannedCaseIds=["SYNTHETIC-HANDOFF"], repeatCount=1,
        caseOutputs=outputs, metrics=metrics,
        limitations=[
            "Synthetic contract data only; Java, database, payments and real model were not executed.",
            "The resultsSource value is a legacy schema literal, not an execution claim.",
        ],
    )
    return report, manifest


def test_authenticated_proposal_reaches_export_without_raw_documents(pipeline, tmp_path):
    client, calls = pipeline
    body = _request()
    result = client.post("/internal/v1/kyc/evaluations",
                         headers={"X-Fuse-Service-Token": TOKEN}, json=body)
    assert result.status_code == 200
    response = result.json()
    assert response["inputSnapshotHash"] == body["inputSnapshotHash"]
    assert response["workflowId"] == body["workflowId"]
    assert response["proposal"]["status"] == "NEEDS_REVIEW"
    assert calls == [body["inputSnapshotHash"]]

    report, manifest = _report_and_manifest(body, response)
    output = Path(public_export.export_evidence_bundle(report, manifest, tmp_path))
    expected_names = {"manifest.json", "case_results.json", "case_results.csv", "metrics.json"}
    assert expected_names <= {path.name for path in output.iterdir()}
    before = {name: (output / name).read_bytes() for name in expected_names}
    assert TOKEN.encode() not in b"".join(before.values())
    assert DOCUMENT_TEXT.encode() not in b"".join(before.values())
    assert Path(public_export.export_evidence_bundle(report, manifest, tmp_path)) == output
    assert {name: (output / name).read_bytes() for name in expected_names} == before


def test_invalid_or_unauthenticated_input_never_calls_provider(pipeline):
    client, calls = pipeline
    body = _request()
    unauthenticated = client.post("/internal/v1/kyc/evaluations", json=body)
    assert unauthenticated.status_code == 401
    corrupted = {**body, "inputSnapshotHash": "0" * 64}
    rejected = client.post("/internal/v1/kyc/evaluations",
                           headers={"X-Fuse-Service-Token": TOKEN}, json=corrupted)
    assert rejected.status_code == 422
    assert calls == []
