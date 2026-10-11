"""Private-file plumbing uses opaque markers, never service instruction bodies."""
import asyncio
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.app import create_app
from agent.dto import KycRequest
from agent.llm_adapter import LiveAdapter
from agent.prompt import PromptConfigurationError, build_messages, load_system_prompt
from agent.settings import Settings
from agent.tests.test_agent import HEADERS, TOKEN, request_body


def configured(path):
    return Settings(service_token=TOKEN, mode="live", model="test-model", api_key="test-value", prompt_path=str(path))


def test_external_file_is_exact_and_frozen_for_capture(tmp_path, monkeypatch):
    path = tmp_path / "private.txt"
    body_text = "fixture-system-001\nfixture-system-002\n"
    path.write_text(body_text, encoding="utf-8")
    settings = configured(path)
    path.write_text("fixture-system-replacement")
    assert settings.system_prompt() == body_text
    assert body_text not in repr(settings)
    real_client = httpx.AsyncClient
    sent_messages = []

    def respond(request):
        sent_messages.append(json.loads(request.content)["messages"])
        return httpx.Response(200, json={"model": "test-resolved-model", "choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps({"status": "NOT_VERIFIED", "evidenceIds": [], "explanation": "fixture-output-001"})}}]})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(**{**kwargs, "transport": httpx.MockTransport(respond)}))
    response = TestClient(create_app(settings)).post("/internal/v1/kyc/captures", headers=HEADERS, json=request_body())
    assert response.status_code == 200
    assert len(sent_messages) == 1
    assert sent_messages[0][0]["content"] == body_text
    fingerprint = hashlib.sha256(json.dumps(sent_messages[0], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert response.json()["promptHash"] == fingerprint


@pytest.mark.parametrize("state", ["missing", "empty", "whitespace", "invalid-utf8", "directory"])
def test_live_missing_or_invalid_file_fails_closed_without_provider(tmp_path, monkeypatch, state):
    path = tmp_path / "private.txt"
    if state == "empty": path.write_text("")
    if state == "whitespace": path.write_text(" \n\t")
    if state == "invalid-utf8": path.write_bytes(b"\xff")
    if state == "directory": path.mkdir()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: pytest.fail("provider must not be contacted"))
    settings = configured(path)
    client = TestClient(create_app(settings))
    ready = client.get("/ready")
    assert ready.status_code == 503
    assert ready.json() == {"ready": False}
    assert client.post("/internal/v1/kyc/evaluations", headers=HEADERS, json=request_body()).status_code == 503
    assert client.post("/internal/v1/kyc/captures", headers=HEADERS, json=request_body()).json()["reasonCode"] == "LIVE_NOT_AVAILABLE"
    with pytest.raises(PromptConfigurationError):
        asyncio.run(LiveAdapter(settings).propose(KycRequest.model_validate(request_body())))


def test_unset_prompt_path_has_no_implicit_fallback():
    with pytest.raises(PromptConfigurationError, match="FUSE_KYC_PROMPT_PATH"):
        load_system_prompt("")
    with pytest.raises(PromptConfigurationError):
        build_messages(KycRequest.model_validate(request_body()), "")


@pytest.mark.parametrize("mode", ["replay", "offline"])
def test_synthetic_modes_never_read_private_files(mode, monkeypatch):
    monkeypatch.setattr("agent.settings.load_system_prompt", lambda path: pytest.fail("synthetic modes must not read private assets"))
    settings = Settings(service_token=TOKEN, mode=mode, prompt_path="/unavailable/private.txt")
    assert settings.errors() == []
    client = TestClient(create_app(settings))
    assert client.get("/ready").status_code == 200
    assert client.post("/internal/v1/kyc/evaluations", headers=HEADERS, json=request_body()).status_code == 200


def test_settings_reads_explicit_external_path_from_environment(tmp_path, monkeypatch):
    path = tmp_path / "private.txt"
    path.write_text("fixture-system-001")
    monkeypatch.setenv("FUSE_KYC_MODE", "live")
    monkeypatch.setenv("FUSE_KYC_PROMPT_PATH", str(path))
    monkeypatch.setenv("FUSE_PRIVATE_DOCUMENTS_PATH", "test-documents.json")
    settings = Settings.from_env()
    assert settings.system_prompt() == "fixture-system-001"
    assert settings.private_documents_path == "test-documents.json"


@pytest.mark.parametrize("route", ["evaluations", "captures"])
def test_live_rejects_unresolved_reference_marker_before_provider(tmp_path, monkeypatch, route):
    path = tmp_path / "private.txt"
    path.write_text("fixture-system-001")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: pytest.fail("provider must not be contacted"))
    client = TestClient(create_app(configured(path)))
    response = client.post(f"/internal/v1/kyc/{route}", headers=HEADERS, json=request_body(text="FUSE_DOCUMENT_ID:rag-01"))
    assert response.status_code == 503
    assert response.json()["reasonCode"] == "PRIVATE_DOCUMENTS_UNAVAILABLE"
