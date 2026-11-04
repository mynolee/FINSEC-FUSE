"""Synthetic product HTTP contracts. These tests do not call a model or network."""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent import llm_adapter, prompt, settings, product_limits
from agent.dto import KycRequest, KycProposal, KycResponse, strict_json_loads
from agent.entrypoint import create_product_app
from agent.product_limits import ProductLimits
from agent.product_provider import ProductSettings
from agent.product_messages import PreparedProductPrompt, assemble_messages
from starlette.requests import Request


TOKEN = "synthetic-only-not-a-real-token-0000000000"
HEADERS = {"X-Fuse-Service-Token": TOKEN}
EVALUATE = "/internal/v1/kyc/evaluations"
CAPTURE = "/internal/v1/kyc/captures"


@pytest.fixture(autouse=True)
def isolated_public_providers(monkeypatch):
    for module in (settings, prompt, llm_adapter):
        monkeypatch.setattr(module, "_provider", None)
    monkeypatch.setattr(product_limits, "_limits", None)


@pytest.fixture
def limits():
    # Explicit synthetic test choices, not production policy defaults.
    return ProductLimits(
        http_header_max_bytes=16_384,
        internal_response_max_bytes=262_144,
        json_max_depth=32,
        max_parallel=1,
        model_timeout_seconds=1.0,
    )


def request_body(*, facts=None, text="synthetic reference"):
    if facts is None:
        facts = [
            {"evidenceId": "00000000-0000-4000-8000-000000000101", "kind": "ID_DOC", "result": "PASS"},
            {"evidenceId": "00000000-0000-4000-8000-000000000102", "kind": "FACE_MATCH", "result": "PASS"},
        ]
    body = {
        "requestId": "00000000-0000-4000-8000-000000000001",
        "workflowId": "00000000-0000-4000-8000-000000000002",
        "generation": 1,
        "runId": "00000000-0000-4000-8000-000000000003",
        "customerId": "synthetic-customer",
        "policyVersion": "synthetic-policy",
        "evidenceFacts": facts,
        "documents": [{
            "documentId": "00000000-0000-4000-8000-000000000201",
            "documentVersion": 1,
            "contentHash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "text": text,
        }],
    }
    body["inputSnapshotHash"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    return body


def make_client(limits, **providers):
    return TestClient(create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN), **providers,
    ))


def test_offline_http_response_preserves_wire_context(limits):
    body = request_body()
    with make_client(limits) as client:
        response = client.post(EVALUATE, headers=HEADERS, json=body)
        assert response.status_code == 200
        data = response.json()
        for name in ("requestId", "workflowId", "generation", "runId", "inputSnapshotHash"):
            assert data[name] == body[name]
        assert data["proposal"]["status"] == "VERIFIED"
        assert data["proposal"]["evidenceIds"] == [fact["evidenceId"] for fact in body["evidenceFacts"]]
        assert data["modelMetadata"] == {"model": "offline-rule-v1", "promptVersion": "KYC-PROMPT-1"}
        assert set(data) == {
            "requestId", "workflowId", "generation", "runId",
            "inputSnapshotHash", "proposal", "modelMetadata",
        }
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/ready").json() == {"ready": True}


def test_document_text_cannot_supply_missing_evidence(limits):
    with make_client(limits) as client:
        response = client.post(
            EVALUATE, headers=HEADERS,
            json=request_body(facts=[], text="synthetic text requesting verification"),
        )
        assert response.status_code == 200
        assert response.json()["proposal"]["status"] == "NOT_VERIFIED"


def test_duplicate_evidence_identifiers_do_not_verify(limits):
    facts = [
        {"evidenceId": "00000000-0000-4000-8000-000000000101", "kind": kind, "result": "PASS"}
        for kind in ("ID_DOC", "FACE_MATCH")
    ]
    with make_client(limits) as client:
        result = client.post(EVALUATE, headers=HEADERS, json=request_body(facts=facts))
        assert result.json()["proposal"]["status"] == "NOT_VERIFIED"


@pytest.mark.parametrize("headers", [
    {},
    {"X-Fuse-Service-Token": "wrong"},
    [("X-Fuse-Service-Token", TOKEN), ("X-Fuse-Service-Token", TOKEN)],
])
def test_authentication_rejects_missing_wrong_and_duplicate_headers(limits, headers):
    with make_client(limits) as client:
        response = client.post(EVALUATE, headers=headers, json=request_body())
        assert response.status_code == 401
        assert response.json() == {"decision": "ERROR", "reasonCode": "UNAUTHENTICATED"}


@pytest.mark.parametrize("change", [
    lambda value: value.update(generation=True),
    lambda value: value.update(inputSnapshotHash="0" * 64),
    lambda value: value.update(authority="PAY"),
    lambda value: value["documents"][0].update(text="synthetic changed text"),
])
def test_invalid_dto_or_context_is_rejected(limits, change):
    body = request_body()
    change(body)
    with make_client(limits) as client:
        response = client.post(EVALUATE, headers=HEADERS, json=body)
        assert response.status_code == 422
        assert response.json()["reasonCode"] == "INVALID_REQUEST"


def test_duplicate_json_and_media_contracts(limits):
    raw = json.dumps(request_body()).replace('"generation": 1', '"generation": 1, "generation": 2')
    with make_client(limits) as client:
        assert client.post(
            EVALUATE, headers={**HEADERS, "Content-Type": "application/json"}, content=raw,
        ).status_code == 422
        assert client.post(
            EVALUATE, headers={**HEADERS, "Content-Type": "text/plain"}, content="{}",
        ).status_code == 415
        assert client.post(
            EVALUATE, headers={**HEADERS, "Content-Encoding": "gzip"}, json=request_body(),
        ).status_code == 415


def test_request_header_and_body_bounds(limits):
    with make_client(limits) as client:
        assert client.post(
            EVALUATE, headers={**HEADERS, "Content-Type": "application/json"},
            content="x" * 262_145,
        ).status_code == 413
        assert client.post(
            EVALUATE, headers={**HEADERS, "X-Synthetic-Extra": "x" * 16_385}, json=request_body(),
        ).status_code == 431


def test_response_bound_is_enforced(limits):
    with make_client(replace(limits, internal_response_max_bytes=64)) as client:
        response = client.post(EVALUATE, headers=HEADERS, json=request_body())
        assert response.status_code == 502
        assert response.json()["reasonCode"] == "MODEL_OUTPUT_INVALID"


@pytest.mark.parametrize("failure,code,status", [
    (llm_adapter.ModelOutputInvalid("synthetic detail"), "MODEL_OUTPUT_INVALID", 502),
    (llm_adapter.ModelUnavailable("synthetic detail"), "DEPENDENCY_UNAVAILABLE", 503),
    (llm_adapter.PrivateDocumentsUnavailable("synthetic detail"), "PRIVATE_DOCUMENTS_UNAVAILABLE", 503),
    (RuntimeError("synthetic detail"), "DEPENDENCY_UNAVAILABLE", 503),
])
def test_adapter_failures_use_fixed_http_errors(limits, failure, code, status):
    class Failing:
        model_name = "synthetic"

        async def propose(self, request):
            raise failure

    with make_client(limits, adapter_factory=lambda config: Failing()) as client:
        response = client.post(EVALUATE, headers=HEADERS, json=request_body())
        assert response.status_code == status
        assert response.json() == {"decision": "ERROR", "reasonCode": code}


def test_timeout_uses_dependency_error(limits):
    class Slow:
        model_name = "synthetic"

        async def propose(self, request):
            await asyncio.sleep(1)

    with make_client(
        replace(limits, model_timeout_seconds=0.01), adapter_factory=lambda config: Slow(),
    ) as client:
        response = client.post(EVALUATE, headers=HEADERS, json=request_body())
        assert response.status_code == 503
        assert response.json()["reasonCode"] == "DEPENDENCY_UNAVAILABLE"


def test_offline_cannot_masquerade_as_live_capture(limits):
    with make_client(limits) as client:
        response = client.post(CAPTURE, headers=HEADERS, json=request_body())
        assert response.status_code == 503
        assert response.json()["reasonCode"] == "LIVE_NOT_AVAILABLE"


def test_capture_requires_explicit_callables_and_binds_response(limits):
    class SyntheticCapture:
        model_name = "synthetic"

        async def capture(self, body, *, messages):
            assert messages == assemble_messages(body, PreparedProductPrompt(system_text="synthetic context"))
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: SyntheticCapture(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic context"),
        prompt_loader=lambda config: pytest.fail("Legacy loader must not run in HTTP"),
        message_builder=lambda body, context: pytest.fail("Legacy builder must not run in HTTP"),
    )
    with TestClient(app) as client:
        body = request_body()
        assert client.get("/ready").json() == {"ready": True}
        response = client.post(CAPTURE, headers=HEADERS, json=body)
        assert response.status_code == 200
        data = response.json()
        assert data["modelMode"] == "LIVE"
        assert data["response"]["inputSnapshotHash"] == body["inputSnapshotHash"]
        assert data["response"]["proposal"]["status"] == "NEEDS_REVIEW"
        assert len(data["promptHash"]) == len(data["modelOutputHash"]) == 64
        expected_messages = assemble_messages(
            KycRequest.model_validate(body), PreparedProductPrompt(system_text="synthetic context"),
        )
        assert data["promptHash"] == hashlib.sha256(json.dumps(
            expected_messages, ensure_ascii=False, separators=(",", ":"),
            sort_keys=True, allow_nan=False,
        ).encode("utf-8")).hexdigest()


def test_schema_and_parser_contracts(limits):
    make_client(limits)
    root = Path(__file__).resolve().parents[1] / "schemas"
    for filename, model in (
        ("kyc-request.schema.json", KycRequest),
        ("kyc-response.schema.json", KycResponse),
        ("kyc-proposal.schema.json", KycProposal),
    ):
        assert json.loads((root / filename).read_text()) == model.model_json_schema()
    with pytest.raises(ValueError):
        strict_json_loads('{"outer":{"value":1,"value":2}}')
    with pytest.raises(ValueError):
        strict_json_loads('{"value":NaN}')
    with pytest.raises(ValueError, match="depth"):
        strict_json_loads("[" * 33 + "0" + "]" * 33)


@pytest.mark.parametrize("failure", [
    llm_adapter.ModelOutputInvalid("synthetic capture getter"),
    llm_adapter.ModelUnavailable("synthetic capture getter"),
    llm_adapter.PrivateDocumentsUnavailable("synthetic capture getter"),
    RuntimeError("synthetic capture getter"),
])
def test_capture_getter_failures_disable_live_at_startup(limits, failure):
    class SyntheticGetter:
        model_name = "synthetic"

        @property
        def capture(self):
            raise failure

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: SyntheticGetter(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic context"),
    )
    with TestClient(app) as client:
        response = client.post(CAPTURE, headers=HEADERS, json=request_body())
        assert response.status_code == 503
        assert response.json() == {"decision": "ERROR", "reasonCode": "LIVE_NOT_AVAILABLE"}


@pytest.mark.parametrize("value", [None, "synthetic noncallable", object()])
def test_capture_attribute_must_be_callable(limits, value):
    class SyntheticCapture:
        model_name = "synthetic"
        capture = value

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: SyntheticCapture(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic context"),
    )
    with TestClient(app) as client:
        readiness = client.get("/ready")
        assert readiness.status_code == 503
        assert readiness.json() == {"ready": False}
        response = client.post(CAPTURE, headers=HEADERS, json=request_body())
        assert response.status_code == 503
        assert response.json() == {"decision": "ERROR", "reasonCode": "LIVE_NOT_AVAILABLE"}


def streaming_request(receive):
    return Request({
        "type": "http", "method": "POST", "path": EVALUATE,
        "headers": [(b"content-type", b"application/json"),
                    (b"x-fuse-service-token", TOKEN.encode())],
    }, receive)


def evaluation_endpoint(app):
    return next(route.endpoint for route in app.routes if route.path == EVALUATE)


def test_body_deadline_is_absolute_and_releases_receiver(limits, monkeypatch):
    from agent import app as app_module
    endpoint = evaluation_endpoint(create_product_app(ProductSettings(limits=limits, service_token=TOKEN)))
    original_timeout = asyncio.timeout
    timeouts = []

    def short_body_timeout(seconds):
        timeouts.append(seconds)
        return original_timeout(0.02 if seconds == 10 else seconds)

    monkeypatch.setattr(asyncio, "timeout", short_body_timeout)

    async def scenario():
        calls = 0

        async def receive():
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.005)
            return {"type": "http.request", "body": b" ", "more_body": True}

        response = await endpoint(streaming_request(receive))
        assert response.status_code == 408
        assert json.loads(response.body) == {"decision": "ERROR", "reasonCode": "REQUEST_BODY_TIMEOUT"}
        assert calls > 1
        assert timeouts == [10]
        assert app_module._body_receivers == 0

    asyncio.run(scenario())


def test_four_body_receivers_reject_fifth_and_release_on_cancel(limits):
    from agent import app as app_module
    endpoint = evaluation_endpoint(create_product_app(ProductSettings(limits=limits, service_token=TOKEN)))

    async def scenario():
        entered = 0
        full = asyncio.Event()
        blocked = asyncio.Event()

        async def receive():
            nonlocal entered
            entered += 1
            if entered == 4:
                full.set()
            await blocked.wait()
            return {"type": "http.request", "body": b"{}", "more_body": False}

        tasks = [asyncio.create_task(endpoint(streaming_request(receive))) for _ in range(4)]
        try:
            await asyncio.wait_for(full.wait(), 1)

            async def forbidden_receive():
                pytest.fail("Over-capacity request must not consume body")

            response = await endpoint(streaming_request(forbidden_receive))
            assert response.status_code == 503
            assert json.loads(response.body)["reasonCode"] == "DEPENDENCY_UNAVAILABLE"
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        assert app_module._body_receivers == 0

        async def valid_receive():
            return {"type": "http.request", "body": json.dumps(request_body()).encode(), "more_body": False}

        assert (await endpoint(streaming_request(valid_receive))).status_code == 200
        assert app_module._body_receivers == 0

    asyncio.run(scenario())


def test_process_body_capacity_spans_apps_and_survives_lifespan_and_receiver_exit(limits):
    from agent import app as app_module
    from starlette.requests import ClientDisconnect

    config = ProductSettings(limits=limits, service_token=TOKEN)
    first = create_product_app(config)
    second = app_module.create_app(config)
    endpoints = [evaluation_endpoint(first), evaluation_endpoint(second)]

    async def scenario():
        entered = 0
        full = asyncio.Event()
        release = asyncio.Event()

        async def receive():
            nonlocal entered
            entered += 1
            if entered == 4:
                full.set()
            await release.wait()
            return {"type": "http.request", "body": b"{}", "more_body": False}

        tasks = [asyncio.create_task(endpoints[index % 2](streaming_request(receive)))
                 for index in range(4)]
        try:
            await asyncio.wait_for(full.wait(), 1)
            assert app_module._body_receivers == 4
            third = app_module.create_app(config)
            async with third.router.lifespan_context(third):
                assert app_module._body_receivers == 4
            assert app_module._body_receivers == 4
            third_endpoint = evaluation_endpoint(third)

            async def forbidden_receive():
                pytest.fail("A new app must share the process body receiver limit")

            rejected = await third_endpoint(streaming_request(forbidden_receive))
            assert rejected.status_code == 503
            assert json.loads(rejected.body)["reasonCode"] == "DEPENDENCY_UNAVAILABLE"
            tasks[0].cancel()
            with pytest.raises(asyncio.CancelledError):
                await tasks[0]
            assert app_module._body_receivers == 3

            async def eof_receive():
                return {"type": "http.request", "body": b"{}", "more_body": False}

            # Invalid JSON-shaped DTO still completes receive and returns its slot.
            assert (await third_endpoint(streaming_request(eof_receive))).status_code == 422
            assert app_module._body_receivers == 3

            async def disconnected_receive():
                return {"type": "http.disconnect"}

            with pytest.raises(ClientDisconnect):
                await third_endpoint(streaming_request(disconnected_receive))
            assert app_module._body_receivers == 3
            release.set()
            responses = await asyncio.gather(*tasks[1:])
            assert all(response.status_code == 422 for response in responses)
            assert app_module._body_receivers == 0
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(scenario())


def test_live_capture_without_prepared_data_remains_unavailable(limits):
    class Capture:
        async def capture(self, body, *, messages):
            pytest.fail("Unprepared LIVE capture must not invoke adapter")

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: Capture(),
    )
    with TestClient(app) as client:
        response = client.post(CAPTURE, headers=HEADERS, json=request_body())
        assert response.status_code == 503
        assert response.json()["reasonCode"] == "LIVE_NOT_AVAILABLE"
        readiness = client.get("/ready")
        assert readiness.status_code == 503
        assert readiness.json() == {"ready": False}


def test_capture_rejects_adapter_message_mutation(limits):
    class MutatingCapture:
        async def capture(self, body, *, messages):
            messages[0]["content"] = "synthetic changed message"
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: MutatingCapture(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic context"),
    )
    with TestClient(app) as client:
        response = client.post(CAPTURE, headers=HEADERS, json=request_body())
        assert response.status_code == 502
        assert response.json() == {"decision": "ERROR", "reasonCode": "MODEL_OUTPUT_INVALID"}


def test_http_binds_provider_descriptors_once_at_startup(limits):
    counts = {"capture": 0, "propose": 0, "model": 0}

    class Descriptors:
        @property
        def model_name(self):
            counts["model"] += 1
            return "synthetic"

        @property
        def propose(self):
            counts["propose"] += 1

            async def operation(body):
                return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic")

            return operation

        @property
        def capture(self):
            counts["capture"] += 1

            async def operation(body, *, messages):
                return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

            return operation

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: Descriptors(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic context"),
    )
    assert counts == {"capture": 1, "propose": 1, "model": 1}
    with TestClient(app) as client:
        for _ in range(2):
            assert client.get("/ready").status_code == 200
            assert client.post(CAPTURE, headers=HEADERS, json=request_body()).status_code == 200
            assert client.post(EVALUATE, headers=HEADERS, json=request_body()).status_code == 200
    assert counts == {"capture": 1, "propose": 1, "model": 1}


def test_sync_adapter_callbacks_are_rejected_without_invocation(limits):
    class Synchronous:
        model_name = "synthetic"

        def propose(self, body):
            pytest.fail("Synchronous propose must not be invoked")

        def capture(self, body, *, messages):
            pytest.fail("Synchronous capture must not be invoked")

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: Synchronous(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic context"),
    )
    with TestClient(app) as client:
        assert client.get("/ready").status_code == 503
        result = client.post(CAPTURE, headers=HEADERS, json=request_body())
        assert result.status_code == 503
        assert result.json()["reasonCode"] == "LIVE_NOT_AVAILABLE"
        result = client.post(EVALUATE, headers=HEADERS, json=request_body())
        assert result.status_code == 503
        assert result.json()["reasonCode"] == "DEPENDENCY_UNAVAILABLE"


@pytest.mark.parametrize("interruption", ["disconnect", "exception", "cancel"])
def test_live_interrupted_body_releases_process_slot_before_any_provider(interruption, limits):
    from agent import app as app_module

    calls = []
    prepared = PreparedProductPrompt(system_text="synthetic prepared context")

    def forbidden_prompt_callback(*args, **kwargs):
        pytest.fail("Request serving must use prepared data, not synchronous prompt callbacks")

    class Capture:
        async def capture(self, body, *, messages):
            calls.append(messages)
            assert messages == assemble_messages(body, prepared)
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: Capture(), prepared_prompt=prepared,
        prompt_loader=forbidden_prompt_callback, message_builder=forbidden_prompt_callback,
    )
    endpoint = next(route.endpoint for route in app.routes if route.path == CAPTURE)

    async def scenario():
        blocked = asyncio.Event()
        reached = asyncio.Event()
        receives = 0

        async def interrupted_receive():
            nonlocal receives
            receives += 1
            if receives == 1:
                return {"type": "http.request", "body": b'{"requestId":', "more_body": True}
            reached.set()
            if interruption == "disconnect":
                return {"type": "http.disconnect"}
            if interruption == "exception":
                raise RuntimeError("synthetic-receive-detail-must-not-be-returned")
            await blocked.wait()
            pytest.fail("Cancelled receive must not resume")

        task = asyncio.create_task(endpoint(streaming_request(interrupted_receive)))
        try:
            await asyncio.wait_for(reached.wait(), 1)
            if interruption == "cancel":
                assert app_module._body_receivers == 1
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                response = await task
                assert response.status_code == 503
                assert json.loads(response.body) == {"decision": "ERROR", "reasonCode": "DEPENDENCY_UNAVAILABLE"}
            assert calls == []
            assert app_module._body_receivers == 0

            async def valid_receive():
                return {"type": "http.request", "body": json.dumps(request_body()).encode(), "more_body": False}

            assert (await endpoint(streaming_request(valid_receive))).status_code == 200
            assert len(calls) == 1
            assert app_module._body_receivers == 0
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


def test_live_model_cancellation_returns_queue_capacity_and_discards_mutable_messages(limits):
    from agent import app as app_module

    prepared = PreparedProductPrompt(system_text="synthetic immutable prepared context")
    state = {"release": False, "calls": 0, "first_messages": None}
    events = {}

    class Capture:
        async def capture(self, body, *, messages):
            state["calls"] += 1
            if not state["release"]:
                state["first_messages"] = messages
                messages[0]["content"] = "synthetic cancelled transient mutation"
                events["started"].set()
                await events["blocked"].wait()
                pytest.fail("Cancelled active model must not return a proposal")
            assert messages is not state["first_messages"]
            assert messages == assemble_messages(body, prepared)
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: Capture(), prepared_prompt=prepared,
    )
    endpoint = next(route.endpoint for route in app.routes if route.path == CAPTURE)

    async def scenario():
        events.update(started=asyncio.Event(), blocked=asyncio.Event())
        queued_body_received = asyncio.Event()
        raw = json.dumps(request_body()).encode()

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        async def queued_receive():
            queued_body_received.set()
            return {"type": "http.request", "body": raw, "more_body": False}

        first = asyncio.create_task(endpoint(streaming_request(receive)))
        second = None
        try:
            await asyncio.wait_for(events["started"].wait(), 1)
            assert app_module._body_receivers == 0
            second = asyncio.create_task(endpoint(streaming_request(queued_receive)))
            await asyncio.wait_for(queued_body_received.wait(), 1)
            # max_parallel1 allows one active plus one pending; bodies already released.
            rejected = await endpoint(streaming_request(receive))
            assert rejected.status_code == 503
            assert json.loads(rejected.body) == {"decision": "ERROR", "reasonCode": "DEPENDENCY_UNAVAILABLE"}
            assert state["calls"] == 1
            assert app_module._body_receivers == 0
            second.cancel()
            with pytest.raises(asyncio.CancelledError):
                await second
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            state["release"] = True
            assert (await endpoint(streaming_request(receive))).status_code == 200
            assert state["calls"] == 2
            assert app_module._body_receivers == 0
        finally:
            tasks = [task for task in (first, second) if task is not None]
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("invalid_output", ["shape", "proposal", "raised"])
def test_live_invalid_output_releases_full_model_queue_and_rebuilds_messages(limits, invalid_output):
    from agent import app as app_module

    prepared = PreparedProductPrompt(system_text="synthetic prepared recovery context")
    state = {"calls": 0, "failed_messages": None}
    events = {}

    class Capture:
        async def capture(self, body, *, messages):
            state["calls"] += 1
            if state["calls"] == 1:
                state["failed_messages"] = messages
                if invalid_output == "proposal":
                    # No message mutation: this case must reach DTO output validation.
                    return None, "synthetic"
                messages[0]["content"] = "synthetic failed-provider transient message"
                if invalid_output == "shape":
                    return ("synthetic-private-invalid-output-detail",)
                raise llm_adapter.ModelOutputInvalid("synthetic-private-invalid-output-detail")
            assert messages is not state["failed_messages"]
            assert messages == assemble_messages(body, prepared)
            events["active"].set()
            await events["release"].wait()
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        live_factory=lambda config: Capture(), prepared_prompt=prepared,
    )
    endpoint = next(route.endpoint for route in app.routes if route.path == CAPTURE)

    async def scenario():
        events.update(active=asyncio.Event(), release=asyncio.Event())
        queued_received = asyncio.Event()
        raw = json.dumps(request_body()).encode()

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        async def queued_receive():
            queued_received.set()
            return {"type": "http.request", "body": raw, "more_body": False}

        invalid = await endpoint(streaming_request(receive))
        assert invalid.status_code == 502
        assert json.loads(invalid.body) == {"decision": "ERROR", "reasonCode": "MODEL_OUTPUT_INVALID"}
        assert b"synthetic-private-invalid-output-detail" not in invalid.body
        assert state["calls"] == 1
        assert app_module._body_receivers == 0
        active = asyncio.create_task(endpoint(streaming_request(receive)))
        queued = None
        try:
            await asyncio.wait_for(events["active"].wait(), 1)
            queued = asyncio.create_task(endpoint(streaming_request(queued_receive)))
            await asyncio.wait_for(queued_received.wait(), 1)
            overflow = await endpoint(streaming_request(receive))
            assert overflow.status_code == 503
            assert json.loads(overflow.body) == {"decision": "ERROR", "reasonCode": "DEPENDENCY_UNAVAILABLE"}
            assert state["calls"] == 2
            assert app_module._body_receivers == 0
            events["release"].set()
            responses = await asyncio.gather(active, queued)
            assert all(response.status_code == 200 for response in responses)
            assert state["calls"] == 3
            assert app_module._body_receivers == 0
        finally:
            tasks = [task for task in (active, queued) if task is not None]
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("route", [EVALUATE, CAPTURE])
@pytest.mark.parametrize("mutation", ["requestId", "workflowId", "generation", "runId",
                                       "inputSnapshotHash", "bool-generation", "callback-scalar", "deleted-field"])
def test_provider_cannot_rebind_validated_response_context(limits, route, mutation):
    from agent import app as app_module

    callbacks = []
    calls = []

    class CallbackText(str):
        def __eq__(self, other):
            callbacks.append("equality")
            raise AssertionError("Provider scalar equality callback must not run")

    def mutate(body):
        calls.append(route)
        if mutation == "deleted-field":
            del body.requestId
        elif mutation == "bool-generation":
            body.generation = True
        elif mutation == "callback-scalar":
            body.requestId = CallbackText(body.requestId)
        elif mutation == "generation":
            body.generation += 1
        elif mutation == "inputSnapshotHash":
            body.inputSnapshotHash = "b" * 64
        else:
            setattr(body, mutation, "00000000-0000-4000-8000-000000000099")

    class MutatingAdapter:
        model_name = "synthetic"

        async def propose(self, body):
            mutate(body)
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic")

        async def capture(self, body, *, messages):
            mutate(body)
            # Leave messages unchanged: rejection must detect body correlation,
            # independently of the existing message-fingerprint protection.
            return KycProposal(status="NEEDS_REVIEW", evidenceIds=[], explanation="synthetic"), "synthetic"

    app = create_product_app(
        ProductSettings(limits=limits, service_token=TOKEN, mode="live"),
        adapter_factory=lambda config: MutatingAdapter(),
        prepared_prompt=PreparedProductPrompt(system_text="synthetic prepared context"),
    )
    with TestClient(app) as client:
        response = client.post(route, headers=HEADERS, json=request_body())
        assert response.status_code == 502
        assert response.json() == {"decision": "ERROR", "reasonCode": "MODEL_OUTPUT_INVALID"}
    assert calls == [route]
    assert callbacks == []
    assert app_module._body_receivers == 0
