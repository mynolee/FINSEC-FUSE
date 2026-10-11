"""FastAPI KYC boundary. It returns a proposal and never has DB/payment authority."""
from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .dto import KycRequest, KycResponse, KycCaptureResponse, ModelMetadata, strict_json_loads
from .prompt import build_messages
from .llm_adapter import Adapter, ModelOutputInvalid, ModelUnavailable, PrivateDocumentsUnavailable, make_adapter
from .settings import Settings
from .security_policy import POLICY


def create_app(settings: Settings | None = None, adapter: Adapter | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    adapter = adapter or make_adapter(settings)
    @asynccontextmanager
    async def lifespan(app):
        if not valid_configured_token():
            raise RuntimeError("internal service token is missing or invalid")
        yield

    def valid_configured_token():
        token = settings.service_token
        return len(token.encode("utf-8")) >= 32 and token != "CHANGE_ME" and not any(c.isspace() or c == "," for c in token)

    def authenticated(request):
        tokens = request.headers.getlist("X-Fuse-Service-Token")
        if not valid_configured_token() or len(tokens) != 1 or not tokens[0] or any(c.isspace() or c == "," for c in tokens[0]):
            return False
        return hmac.compare_digest(hashlib.sha256(tokens[0].encode()).digest(),
                                   hashlib.sha256(settings.service_token.encode()).digest())

    app = FastAPI(lifespan=lifespan, openapi_url=None, title="FINSEC-FUSE Candidate-only KYC", version="1.0.0", docs_url=None, redoc_url=None)
    semaphore = asyncio.Semaphore(settings.max_parallel)
    pending = 0

    async def generate(body, capture=False):
        nonlocal pending
        # At most four active calls and four waiting calls. No unbounded model queue.
        if pending >= 2 * settings.max_parallel:
            raise ModelUnavailable("model admission capacity reached")
        pending += 1
        try:
            async with asyncio.timeout(settings.model_timeout_seconds):
                async with semaphore:
                    return await (adapter.capture(body) if capture else adapter.propose(body))
        finally:
            pending -= 1

    def error(code: str, status: int):
        return JSONResponse({"decision": "ERROR", "reasonCode": code}, status_code=status)

    @app.middleware("http")
    async def bounded_headers(request: Request, call_next):
        header_bytes = sum(len(name) + len(value) + 4 for name, value in request.scope.get("headers", []))
        if header_bytes > POLICY["httpHeaderMaxBytes"]:
            return error("REQUEST_TOO_LARGE", 431)
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    async def ready():
        errors = settings.errors()
        return JSONResponse({"ready": not errors}, status_code=503 if errors else 200)

    @app.post("/internal/v1/kyc/evaluations")
    async def evaluate(request: Request):
        if not authenticated(request):
            return error("UNAUTHENTICATED", 401)
        if settings.errors():
            return error("DEPENDENCY_UNAVAILABLE", 503)
        if (len(request.headers.getlist("content-type")) != 1 or
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json" or
            "content-encoding" in request.headers):
            return error("UNSUPPORTED_MEDIA_TYPE", 415)
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > settings.max_request_bytes:
                return error("REQUEST_TOO_LARGE", 413)
            raw.extend(chunk)
        try:
            body = KycRequest.model_validate(strict_json_loads(bytes(raw)))
        except (ValueError, ValidationError, UnicodeError):
            return error("INVALID_REQUEST", 422)
        try:
            # Queueing and generation are bounded together so Java's outer 30s
            # deadline is not silently consumed by an unbounded Python queue.
            proposal = await generate(body)
            result = KycResponse(requestId=body.requestId, workflowId=body.workflowId,
                                 generation=body.generation, runId=body.runId,
                                 inputSnapshotHash=body.inputSnapshotHash, proposal=proposal,
                                 modelMetadata=ModelMetadata(model=adapter.model_name))
            if len(result.model_dump_json().encode("utf-8")) > POLICY["internalResponseMaxBytes"]:
                return error("MODEL_OUTPUT_INVALID", 502)
            return JSONResponse(result.model_dump())
        except ModelOutputInvalid:
            return error("MODEL_OUTPUT_INVALID", 502)
        except PrivateDocumentsUnavailable:
            return error("PRIVATE_DOCUMENTS_UNAVAILABLE", 503)
        except (TimeoutError, ModelUnavailable):
            return error("DEPENDENCY_UNAVAILABLE", 503)
        except (ValidationError, TypeError, ValueError):
            return error("MODEL_OUTPUT_INVALID", 502)

    @app.post("/internal/v1/kyc/captures")
    async def capture(request: Request):
        # Capture is a separate LIVE-only boundary. Replay/offline cannot masquerade
        # as a live measurement even if the Java experiment switch is enabled.
        if not authenticated(request):
            return error("UNAUTHENTICATED", 401)
        if settings.mode != "live" or settings.errors() or not callable(getattr(adapter, "capture", None)):
            return error("LIVE_NOT_AVAILABLE", 503)
        if (len(request.headers.getlist("content-type")) != 1 or
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json" or
            "content-encoding" in request.headers):
            return error("UNSUPPORTED_MEDIA_TYPE", 415)
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > settings.max_request_bytes:
                return error("REQUEST_TOO_LARGE", 413)
            raw.extend(chunk)
        try:
            body = KycRequest.model_validate(strict_json_loads(bytes(raw)))
        except (ValueError, ValidationError, UnicodeError):
            return error("INVALID_REQUEST", 422)
        try:
            messages = build_messages(body, settings.system_prompt())
            proposal, actual_model = await generate(body, capture=True)
            response = KycResponse(requestId=body.requestId, workflowId=body.workflowId,
                generation=body.generation, runId=body.runId, inputSnapshotHash=body.inputSnapshotHash,
                proposal=proposal, modelMetadata=ModelMetadata(model=actual_model))
            fingerprint = lambda value: hashlib.sha256(json.dumps(value, ensure_ascii=False,
                separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")).hexdigest()
            result = KycCaptureResponse(response=response, promptHash=fingerprint(messages),
                modelOutputHash=fingerprint(proposal.model_dump()))
            if len(result.model_dump_json().encode("utf-8")) > POLICY["internalResponseMaxBytes"]:
                return error("MODEL_OUTPUT_INVALID", 502)
            return JSONResponse(result.model_dump())
        except ModelOutputInvalid:
            return error("MODEL_OUTPUT_INVALID", 502)
        except PrivateDocumentsUnavailable:
            return error("PRIVATE_DOCUMENTS_UNAVAILABLE", 503)
        except (TimeoutError, ModelUnavailable):
            return error("DEPENDENCY_UNAVAILABLE", 503)
        except (ValidationError, TypeError, ValueError):
            return error("MODEL_OUTPUT_INVALID", 502)

    return app


app = create_app()
