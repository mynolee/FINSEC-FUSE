"""KYC HTTP proposal boundary with explicit providers and operator-supplied limits."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .dto import KycRequest, KycResponse, KycCaptureResponse, ModelMetadata, strict_json_loads
from .llm_adapter import ModelOutputInvalid, ModelUnavailable, PrivateDocumentsUnavailable, make_adapter, bind_http_adapter
from .prompt import PromptConfigurationError
from .product_messages import PreparedProductPrompt, assemble_messages
from .product_provider import ProductSettings, valid_service_token
from .product_limits import require_limits
from .settings import Settings

_body_receivers = 0
_body_receiver_lock = threading.Lock()


def create_app(settings: ProductSettings | None = None, adapter=None, *, prepared_prompt=None) -> FastAPI:
    if prepared_prompt is not None and type(prepared_prompt) is not PreparedProductPrompt:
        raise TypeError("Prepared product prompt data is required")
    settings = Settings.from_env() if settings is None else settings
    if not isinstance(settings, ProductSettings) or require_limits() is not settings.limits:
        raise TypeError("The app requires its explicitly configured product settings")
    if settings.errors():
        raise RuntimeError("Internal service token is missing or invalid")
    adapter = make_adapter(settings) if adapter is None else adapter
    bindings = bind_http_adapter(adapter)
    model_name = bindings.model_name
    try:
        ModelMetadata(model=model_name)
    except (TypeError, ValueError, ValidationError):
        model_name = None
    limits = settings.limits

    @asynccontextmanager
    async def lifespan(app):
        if settings.errors():
            raise RuntimeError("Internal service token is missing or invalid")
        yield

    def authenticated(request):
        values = request.headers.getlist("X-Fuse-Service-Token")
        if (
            not valid_service_token(settings.service_token)
            or len(values) != 1
            or not valid_service_token(values[0])
        ):
            return False
        return hmac.compare_digest(
            hashlib.sha256(values[0].encode("utf-8")).digest(),
            hashlib.sha256(settings.service_token.encode("utf-8")).digest(),
        )

    def error(code: str, status: int):
        return JSONResponse({"decision": "ERROR", "reasonCode": code}, status_code=status)

    app = FastAPI(
        lifespan=lifespan, openapi_url=None, docs_url=None, redoc_url=None,
        title="FINSEC-FUSE Candidate-only KYC", version="1.0.0",
    )
    semaphore = asyncio.Semaphore(settings.max_parallel)
    pending = 0

    async def generate(body, *, capture=False, messages=None):
        nonlocal pending
        if pending >= 2 * settings.max_parallel:
            raise ModelUnavailable("Model admission capacity reached")
        pending += 1
        try:
            async with asyncio.timeout(settings.model_timeout_seconds):
                async with semaphore:
                    operation = bindings.capture if capture else bindings.propose
                    if operation is None:
                        raise ModelUnavailable("Model operation is not available")
                    return await (operation(body, messages=messages) if capture else operation(body))
        finally:
            pending -= 1

    async def parse_body(request):
        global _body_receivers
        if (
            len(request.headers.getlist("content-type")) != 1
            or request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
            or "content-encoding" in request.headers
        ):
            return error("UNSUPPORTED_MEDIA_TYPE", 415)
        raw = bytearray()
        with _body_receiver_lock:
            if _body_receivers >= 4:
                return error("DEPENDENCY_UNAVAILABLE", 503)
            _body_receivers += 1
        try:
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > settings.max_request_bytes:
                        return error("REQUEST_TOO_LARGE", 413)
                    raw.extend(chunk)
        except TimeoutError:
            return error("REQUEST_BODY_TIMEOUT", 408)
        finally:
            with _body_receiver_lock:
                _body_receivers -= 1
        try:
            return KycRequest.model_validate(strict_json_loads(bytes(raw)))
        except (ValueError, ValidationError, UnicodeError):
            return error("INVALID_REQUEST", 422)

    context_fields = ("requestId", "workflowId", "generation", "runId", "inputSnapshotHash")

    def request_context(body):
        # Validated request correlation consists only of immutable native scalars.
        return tuple(getattr(body, name) for name in context_fields)

    def context_matches(body, context):
        for name, expected in zip(context_fields, context):
            actual = getattr(body, name, None)
            # Reject subclasses/bool before equality can invoke a provider callback
            # or make True compare equal to generation1.
            if type(actual) is not type(expected) or actual != expected:
                return False
        return True

    def response_for(context, proposal, model_name):
        request_id, workflow_id, generation, run_id, snapshot_hash = context
        return KycResponse(
            requestId=request_id, workflowId=workflow_id,
            generation=generation, runId=run_id,
            inputSnapshotHash=snapshot_hash, proposal=proposal,
            modelMetadata=ModelMetadata(model=model_name),
        )

    def bounded_response(result):
        encoded = result.model_dump_json().encode("utf-8")
        if len(encoded) > limits.internal_response_max_bytes:
            return error("MODEL_OUTPUT_INVALID", 502)
        return JSONResponse(result.model_dump())

    @app.middleware("http")
    async def bounded_headers(request: Request, call_next):
        size = sum(len(name) + len(value) + 4 for name, value in request.scope.get("headers", []))
        if size > limits.http_header_max_bytes:
            return error("REQUEST_TOO_LARGE", 431)
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    async def ready():
        available = not settings.errors()
        if settings.mode == "live":
            available = available and prepared_prompt is not None and bindings.capture is not None
        return JSONResponse({"ready": available}, status_code=200 if available else 503)

    @app.post("/internal/v1/kyc/evaluations")
    async def evaluate(request: Request):
        if not authenticated(request):
            return error("UNAUTHENTICATED", 401)
        if settings.errors():
            return error("DEPENDENCY_UNAVAILABLE", 503)
        body = await parse_body(request)
        if isinstance(body, JSONResponse):
            return body
        try:
            context = request_context(body)
            proposal = await generate(body)
            if model_name is None or not context_matches(body, context):
                return error("MODEL_OUTPUT_INVALID", 502)
            return bounded_response(response_for(context, proposal, model_name))
        except ModelOutputInvalid:
            return error("MODEL_OUTPUT_INVALID", 502)
        except PrivateDocumentsUnavailable:
            return error("PRIVATE_DOCUMENTS_UNAVAILABLE", 503)
        except (ValidationError, TypeError, ValueError):
            return error("MODEL_OUTPUT_INVALID", 502)
        except (TimeoutError, ModelUnavailable):
            return error("DEPENDENCY_UNAVAILABLE", 503)
        except Exception:
            return error("DEPENDENCY_UNAVAILABLE", 503)

    @app.post("/internal/v1/kyc/captures")
    async def capture(request: Request):
        if not authenticated(request):
            return error("UNAUTHENTICATED", 401)
        try:
            if (
                settings.mode != "live"
                or prepared_prompt is None
                or settings.errors()
                or bindings.capture is None
            ):
                return error("LIVE_NOT_AVAILABLE", 503)
            body = await parse_body(request)
            if isinstance(body, JSONResponse):
                return body
            context = request_context(body)
            messages = assemble_messages(body, prepared_prompt)

            def fingerprint(value):
                return hashlib.sha256(json.dumps(
                    value, ensure_ascii=False, separators=(",", ":"),
                    sort_keys=True, allow_nan=False,
                ).encode("utf-8")).hexdigest()

            prompt_hash = fingerprint(messages)
            proposal, model_name = await generate(body, capture=True, messages=messages)
            if not context_matches(body, context) or fingerprint(messages) != prompt_hash:
                return error("MODEL_OUTPUT_INVALID", 502)
            response = response_for(context, proposal, model_name)
            result = KycCaptureResponse(
                response=response, promptHash=prompt_hash,
                modelOutputHash=fingerprint(response.proposal.model_dump()),
            )
            return bounded_response(result)
        except (PromptConfigurationError, PrivateDocumentsUnavailable):
            return error("PRIVATE_DOCUMENTS_UNAVAILABLE", 503)
        except ModelOutputInvalid:
            return error("MODEL_OUTPUT_INVALID", 502)
        except (ValidationError, TypeError, ValueError):
            return error("MODEL_OUTPUT_INVALID", 502)
        except (TimeoutError, ModelUnavailable):
            return error("DEPENDENCY_UNAVAILABLE", 503)
        except Exception:
            return error("DEPENDENCY_UNAVAILABLE", 503)

    return app
