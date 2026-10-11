"""Candidate adapters. Replay is an adversarial fixture, not an LLM measurement."""
from __future__ import annotations

from typing import Protocol

import httpx
from pydantic import ValidationError

from .dto import KycProposal, KycRequest, strict_json_loads
from .prompt import build_messages
from .settings import Settings
from .outbound import MODEL_BASE_URL, model_transport
from .security_policy import POLICY


class ModelOutputInvalid(Exception):
    pass


class ModelUnavailable(Exception):
    pass


class PrivateDocumentsUnavailable(ModelUnavailable):
    pass


class Adapter(Protocol):
    model_name: str
    async def propose(self, request: KycRequest) -> KycProposal: ...


class OfflineAdapter:
    model_name = "offline-rule-v1"

    async def propose(self, request: KycRequest) -> KycProposal:
        facts = request.evidenceFacts
        kinds = {fact.kind for fact in facts if fact.result == "PASS"}
        valid = {"ID_DOC", "FACE_MATCH"}.issubset(kinds) and not any(f.result == "FAIL" for f in facts)
        return KycProposal(status="VERIFIED" if valid else "NOT_VERIFIED",
                           evidenceIds=[fact.evidenceId for fact in facts],
                           explanation="Synthetic deterministic proposal: both checks PASS." if valid else
                           "Synthetic deterministic proposal: required checks are missing or FAIL.")


class ReplayAdapter(OfflineAdapter):
    model_name = "replay"

    async def propose(self, request: KycRequest) -> KycProposal:
        # The exact seeded poisoned document/customer trigger is deliberate and
        # immutable; arbitrary text cannot activate control-plane behavior.
        poisoned_fixture = request.customerId == "customer-101" and any(
            d.documentId == "00000000-0000-4000-8000-000000000201" and d.documentVersion == 2
            for d in request.documents)
        if poisoned_fixture:
            return KycProposal(status="VERIFIED", evidenceIds=[], explanation=
                               "Synthetic adversarial replay: falsely claims VERIFIED without evidence; Java must reject.")
        return await super().propose(request)


class LiveAdapter:
    """Opt-in OpenAI-compatible HTTPS JSON-schema adapter; no tools or retries."""
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model_name = settings.model

    async def propose(self, request: KycRequest) -> KycProposal:
        proposal, _ = await self._generate(request, require_model=False)
        return proposal

    async def capture(self, request: KycRequest) -> tuple[KycProposal, str]:
        """Return the proposal and actual provider model ID in one bounded call."""
        return await self._generate(request, require_model=True)

    async def _generate(self, request: KycRequest, *, require_model: bool) -> tuple[KycProposal, str]:
        if self.settings.base_url != MODEL_BASE_URL:
            raise ModelUnavailable("unregistered model destination")
        if any(document.text.startswith("FUSE_DOCUMENT_ID:") for document in request.documents):
            raise PrivateDocumentsUnavailable("private reference documents are not configured for LIVE")
        payload = {"model": self.settings.model, "messages": build_messages(request, self.settings.system_prompt()),
                   "response_format": {"type": "json_schema", "json_schema": {
                       "name": "KycProposal", "strict": True, "schema": KycProposal.model_json_schema()}},
                   "max_completion_tokens": 1200}
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.settings.model_timeout_seconds, connect=2.0),
                                         follow_redirects=False, trust_env=False, transport=model_transport()) as client:
                async with client.stream("POST", f"{self.settings.base_url}/chat/completions", json=payload,
                    headers={"Authorization": f"Bearer {self.settings.api_key}", "Content-Type": "application/json", "Accept-Encoding": "identity"}) as response:
                    if response.status_code != 200:
                        raise ModelUnavailable("model provider did not return success")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise ModelOutputInvalid("compressed model response is unsupported")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > POLICY["internalResponseMaxBytes"]:
                            raise ModelOutputInvalid("model provider response too large")
                        body.extend(chunk)
            envelope = strict_json_loads(bytes(body))
            choice = envelope["choices"][0]
            message = choice["message"]
            if choice.get("finish_reason") != "stop" or message.get("tool_calls") or message.get("refusal"):
                raise ModelOutputInvalid("model output did not complete the candidate contract")
            proposal = KycProposal.model_validate(strict_json_loads(message["content"]))
            model = envelope.get("model", self.model_name if not require_model else None)
            if not isinstance(model, str) or not model.strip() or len(model) > 160:
                if require_model:
                    raise ModelOutputInvalid("model provider response is missing its model identifier")
                model = self.model_name
            return proposal, model
        except httpx.DecodingError as exc:
            raise ModelOutputInvalid("model response encoding is invalid") from exc
        except (httpx.HTTPError, TimeoutError) as exc:
            raise ModelUnavailable("model provider unavailable") from exc
        except (KeyError, IndexError, AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise ModelOutputInvalid("model output does not match KycProposal") from exc


def make_adapter(settings: Settings) -> Adapter:
    return {"replay": ReplayAdapter, "offline": OfflineAdapter}.get(settings.mode, lambda: LiveAdapter(settings))()
