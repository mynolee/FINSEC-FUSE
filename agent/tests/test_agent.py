import asyncio
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from agent.app import create_app
from agent.dto import KycRequest, KycProposal, strict_json_loads
from agent.llm_adapter import LiveAdapter, ModelOutputInvalid, ModelUnavailable
from agent.prompt import build_messages
from agent.settings import Settings

TOKEN = "test-only-not-a-real-credential-0000000000"
HEADERS = {"X-Fuse-Service-Token": TOKEN}
PATH = "/internal/v1/kyc/evaluations"


def request_body(customer="customer-102", version=1, facts=None, text="fixture-text-001"):
    if facts is None:
        facts = [{"evidenceId": f"00000000-0000-4000-8000-00000000102{n}", "kind": kind, "result": "PASS"}
                 for n, kind in [(1, "ID_DOC"), (2, "FACE_MATCH")]]
    body = {"requestId": "d4b948b6-811b-4e90-ae7a-4f9d15f80d8e",
            "workflowId": "256c4d72-ab54-4b03-a4eb-1b0f30b56a41", "generation": 1,
            "runId": "9758854f-6e94-4c7a-9c94-fb22d21d7f0b", "customerId": customer,
            "policyVersion": "FUSE-MVP-2", "evidenceFacts": facts,
            "documents": [{"documentId": "00000000-0000-4000-8000-000000000201",
                           "documentVersion": version, "contentHash": hashlib.sha256(text.encode()).hexdigest(),
                           "text": text}]}
    return rehash(body)


def rehash(body):
    ordered = {key: body[key] for key in ["requestId", "workflowId", "generation", "runId", "customerId", "policyVersion", "evidenceFacts", "documents"]}
    body["inputSnapshotHash"] = hashlib.sha256(json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return body


@pytest.fixture
def client():
    return TestClient(create_app(Settings(service_token=TOKEN)))


def test_normal_two_facts_and_context_binding(client):
    body = request_body()
    response = client.post(PATH, headers=HEADERS, json=body)
    assert response.status_code == 200
    data = response.json()
    assert data["proposal"]["status"] == "VERIFIED"
    assert len(data["proposal"]["evidenceIds"]) == 2
    assert data["modelMetadata"] == {"model": "replay", "promptVersion": "KYC-PROMPT-1"}
    for key in ["requestId", "workflowId", "generation", "runId", "inputSnapshotHash"]:
        assert data[key] == body[key]
    assert set(data) == {"requestId", "workflowId", "generation", "runId", "inputSnapshotHash", "proposal", "modelMetadata"}


def test_deliberately_unsafe_replay_visible(client):
    data = client.post(PATH, headers=HEADERS, json=request_body("customer-101", 2, [])).json()
    assert data["proposal"]["status"] == "VERIFIED"
    assert data["proposal"]["evidenceIds"] == []
    assert "Synthetic adversarial replay" in data["proposal"]["explanation"]


def test_offline_mode_uses_facts_for_seeded_case():
    client = TestClient(create_app(Settings(service_token=TOKEN, mode="offline")))
    body = request_body("customer-101", 2, [], "fixture-text-002")
    data = client.post(PATH, headers=HEADERS, json=body).json()
    assert data["proposal"]["status"] == "NOT_VERIFIED"
    assert data["modelMetadata"]["model"] == "offline-rule-v1"


@pytest.mark.parametrize("facts", [[], [{"evidenceId": "00000000-0000-4000-8000-000000001022", "kind": "FACE_MATCH", "result": "FAIL"}]])
def test_missing_or_failed_evidence_is_not_verified(client, facts):
    assert client.post(PATH, headers=HEADERS, json=request_body(facts=facts)).json()["proposal"]["status"] == "NOT_VERIFIED"


def test_authentication_and_readiness(client):
    assert client.post(PATH, json=request_body()).status_code == 401
    assert client.post(PATH, headers={"X-Fuse-Service-Token": "wrong"}, json=request_body()).status_code == 401
    assert client.get("/ready").json()["ready"] is True
    assert client.get("/health").json() == {"status": "ok"}
    unconfigured = TestClient(create_app(Settings()))
    assert unconfigured.get("/ready").status_code == 503
    assert unconfigured.post(PATH, headers=HEADERS, json=request_body()).status_code == 401


@pytest.mark.parametrize("change", [lambda b: b.update(principal="admin"), lambda b: b.update(generation=True),
    lambda b: b.update(generation="1"), lambda b: b.update(inputSnapshotHash="0" * 64),
    lambda b: b["documents"][0].update(text="changed"), lambda b: b.update(requestId="not-a-uuid"),
    lambda b: b["evidenceFacts"][0].update(issuerId="self"), lambda b: b.update(evidenceFacts=b["evidenceFacts"]*6)])
def test_strict_invalid_requests(client, change):
    body = request_body()
    change(body)
    assert client.post(PATH, headers=HEADERS, json=body).status_code == 422


def test_duplicate_keys_rejected_before_dto(client):
    raw = json.dumps(request_body()).replace('"generation": 1', '"generation": 1, "generation": 2')
    assert client.post(PATH, headers={**HEADERS, "Content-Type": "application/json"}, content=raw).status_code == 422
    with pytest.raises(ValueError):
        strict_json_loads('{"outer":{"x":1,"x":2}}')
    with pytest.raises(ValueError):
        strict_json_loads('{"x":NaN}')


def test_request_size_and_media_type(client):
    assert client.post(PATH, headers={**HEADERS, "Content-Type": "text/plain"}, content="{}").status_code == 415
    assert client.post(PATH, headers={**HEADERS, "Content-Type": "application/json"}, content="x"*262_145).status_code == 413


def test_prompt_separates_reference_and_evidence():
    reference = "fixture-text-003"
    request = KycRequest.model_validate(request_body(text=reference))
    messages = build_messages(request, "fixture-system-001")
    assert len(messages) == 3
    assert reference not in messages[0]["content"]
    assert "EVIDENCE_FACTS" in messages[1]["content"]
    assert "UNTRUSTED_REFERENCE_DOCUMENTS" in messages[2]["content"]
    assert reference in messages[2]["content"]
    rendered = json.dumps(messages)
    assert TOKEN not in rendered and request.runId not in rendered and request.inputSnapshotHash not in rendered


@pytest.mark.parametrize("raised,code,status", [(ModelUnavailable(), "DEPENDENCY_UNAVAILABLE", 503),
    (ModelOutputInvalid(), "MODEL_OUTPUT_INVALID", 502)])
def test_failures_are_errors_not_security_success(raised, code, status):
    class Failing:
        model_name = "test-only"
        async def propose(self, request):
            raise raised
    client = TestClient(create_app(Settings(service_token=TOKEN), Failing()))
    result = client.post(PATH, headers=HEADERS, json=request_body())
    assert result.status_code == status
    assert result.json() == {"decision": "ERROR", "reasonCode": code}


def test_timeout():
    class Slow:
        model_name = "test-only"
        async def propose(self, request):
            await asyncio.sleep(1)
    client = TestClient(create_app(Settings(service_token=TOKEN, model_timeout_seconds=0.01), Slow()))
    assert client.post(PATH, headers=HEADERS, json=request_body()).json()["reasonCode"] == "DEPENDENCY_UNAVAILABLE"


def test_live_requires_explicit_configuration(tmp_path):
    prompt_path = tmp_path / "private.txt"
    prompt_path.write_text("fixture-system-001")
    assert Settings(service_token=TOKEN, mode="live").errors()
    assert Settings(service_token=TOKEN, mode="live", model="model", api_key="key", base_url="http://untrusted.example").errors()
    assert not Settings(service_token=TOKEN, mode="live", model="model", api_key="key", prompt_path=str(prompt_path)).errors()


def test_response_dto_rejects_authority_fields():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        KycProposal(status="VERIFIED", evidenceIds=[], explanation="test", allowedAction="EXECUTE_MOCK_PAYMENT")


def test_schema_matches_checked_in_files():
    from pathlib import Path
    from agent.dto import KycResponse
    for name, cls in [("kyc-request.schema.json", KycRequest), ("kyc-response.schema.json", KycResponse), ("kyc-proposal.schema.json", KycProposal)]:
        assert json.loads((Path("agent/schemas") / name).read_text()) == cls.model_json_schema()
