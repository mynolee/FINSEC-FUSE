"""LIVE capture boundaries with fake adapters/providers only; never a paid request."""
import asyncio
import hashlib
import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.app import create_app
from agent.dto import KycRequest, KycProposal
from agent.llm_adapter import LiveAdapter, ModelOutputInvalid, ModelUnavailable
from agent.prompt import build_messages
from agent.settings import Settings
from agent.tests.test_agent import TOKEN, HEADERS, request_body

PATH = "/internal/v1/kyc/captures"


@pytest.fixture(autouse=True)
def private_prompt(tmp_path, monkeypatch):
    path = tmp_path / "private.txt"
    path.write_text("fixture-system-001")
    monkeypatch.setenv("FUSE_KYC_PROMPT_PATH", str(path))
    return path


def settings(**changes):
    return Settings(service_token=TOKEN, mode="live", model="test-alias", api_key="fake-test-value",
                    prompt_path=os.environ["FUSE_KYC_PROMPT_PATH"], **changes)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakeCapture:
    model_name = "test-alias"
    calls = 0

    async def capture(self, request):
        self.calls += 1
        return KycProposal(status="NOT_VERIFIED", evidenceIds=[], explanation="독립 증거 부족"), "test-provider-resolved-version"


def test_capture_once_preserves_actual_model_prompt_output_and_binding():
    adapter = FakeCapture()
    client = TestClient(create_app(settings(), adapter))
    body = request_body(facts=[])
    result = client.post(PATH, headers=HEADERS, json=body)
    assert result.status_code == 200
    data = result.json()
    assert adapter.calls == 1
    assert data["modelMode"] == "LIVE"
    assert data["response"]["modelMetadata"]["model"] == "test-provider-resolved-version"
    assert data["promptHash"] == fingerprint(build_messages(KycRequest.model_validate(body), settings().system_prompt()))
    assert data["modelOutputHash"] == fingerprint(data["response"]["proposal"])
    assert data["response"]["inputSnapshotHash"] == body["inputSnapshotHash"]
    assert TOKEN not in json.dumps(data)
    assert "fake-test-value" not in json.dumps(data)


@pytest.mark.parametrize("mode", ["replay", "offline"])
def test_capture_rejects_synthetic_modes_before_call(mode):
    adapter = FakeCapture()
    client = TestClient(create_app(Settings(service_token=TOKEN, mode=mode), adapter))
    assert client.post(PATH, headers=HEADERS, json=request_body()).json()["reasonCode"] == "LIVE_NOT_AVAILABLE"
    assert adapter.calls == 0


def test_capture_requires_auth_and_valid_snapshot_before_call():
    adapter = FakeCapture()
    client = TestClient(create_app(settings(), adapter))
    assert client.post(PATH, json=request_body()).status_code == 401
    body = request_body()
    body["inputSnapshotHash"] = "0" * 64
    assert client.post(PATH, headers=HEADERS, json=body).status_code == 422
    assert adapter.calls == 0


@pytest.mark.parametrize("failure,expected", [(ModelOutputInvalid(), "MODEL_OUTPUT_INVALID"), (ModelUnavailable(), "DEPENDENCY_UNAVAILABLE")])
def test_capture_failure_is_explicit_error(failure, expected):
    class Failing(FakeCapture):
        async def capture(self, request):
            self.calls += 1
            raise failure
    adapter = Failing()
    client = TestClient(create_app(settings(), adapter))
    result = client.post(PATH, headers=HEADERS, json=request_body())
    assert result.json() == {"decision": "ERROR", "reasonCode": expected}
    assert adapter.calls == 1


def test_capture_timeout_does_not_retry():
    class Slow(FakeCapture):
        async def capture(self, request):
            self.calls += 1
            await asyncio.sleep(1)
    adapter = Slow()
    client = TestClient(create_app(settings(model_timeout_seconds=0.01), adapter))
    assert client.post(PATH, headers=HEADERS, json=request_body()).json()["reasonCode"] == "DEPENDENCY_UNAVAILABLE"
    assert adapter.calls == 1


def test_live_adapter_resolves_provider_model_in_single_mock_transport_call(monkeypatch):
    real_client = httpx.AsyncClient
    calls = []
    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={"model": "resolved-provider-version", "choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps({"status": "NOT_VERIFIED", "evidenceIds": [], "explanation": "No independent facts"})}}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(**{**kwargs, "transport": httpx.MockTransport(respond)}))
    proposal, model = asyncio.run(LiveAdapter(settings()).capture(KycRequest.model_validate(request_body(facts=[]))))
    assert proposal.status == "NOT_VERIFIED"
    assert model == "resolved-provider-version"
    assert len(calls) == 1


def test_capture_refuses_missing_provider_model_but_normal_propose_contract_stays_compatible(monkeypatch):
    real_client = httpx.AsyncClient
    def respond(request):
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps({"status": "NOT_VERIFIED", "evidenceIds": [], "explanation": "No facts"})}}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(**{**kwargs, "transport": httpx.MockTransport(respond)}))
    adapter = LiveAdapter(settings())
    body = KycRequest.model_validate(request_body(facts=[]))
    with pytest.raises(ModelOutputInvalid):
        asyncio.run(adapter.capture(body))
    assert asyncio.run(adapter.propose(body)).status == "NOT_VERIFIED"
