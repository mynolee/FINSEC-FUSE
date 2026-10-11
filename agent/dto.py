"""Strict wire contracts. UUIDs are canonical strings on both sides of the wire."""
from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from .security_policy import POLICY

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator, field_validator

Uuid = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
Hash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
BoundedId = Annotated[str, StringConstraints(min_length=1, max_length=64)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceFact(StrictModel):
    evidenceId: Uuid
    kind: Literal["ID_DOC", "FACE_MATCH"]
    result: Literal["PASS", "FAIL"]


class SourceDocument(StrictModel):
    documentId: Uuid
    documentVersion: int = Field(ge=1, le=2147483647)
    contentHash: Hash
    text: str = Field(max_length=POLICY["documentTextMaxUtf8Bytes"])

    @model_validator(mode="after")
    def matches_content(self):
        encoded = self.text.encode("utf-8")
        if len(encoded) > POLICY["documentTextMaxUtf8Bytes"]:
            raise ValueError("document text exceeds UTF-8 byte limit")
        if hashlib.sha256(encoded).hexdigest() != self.contentHash:
            raise ValueError("document content hash does not match supplied text")
        return self


class KycRequest(StrictModel):
    requestId: Uuid
    workflowId: Uuid
    generation: int = Field(ge=1, le=2147483647)
    runId: Uuid
    customerId: BoundedId
    policyVersion: BoundedId
    inputSnapshotHash: Hash
    evidenceFacts: list[EvidenceFact] = Field(max_length=POLICY["evidenceFactsMaxItems"])
    documents: list[SourceDocument] = Field(max_length=POLICY["documentsMaxItems"])

    def canonical_input(self) -> bytes:
        # DTO field order is the contract; never sort keys or include the hash itself.
        return json.dumps(self.model_dump(exclude={"inputSnapshotHash"}), ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")

    @model_validator(mode="after")
    def matches_snapshot(self):
        if hashlib.sha256(self.canonical_input()).hexdigest() != self.inputSnapshotHash:
            raise ValueError("input snapshot hash mismatch")
        return self


class KycProposal(StrictModel):
    status: Literal["VERIFIED", "NOT_VERIFIED", "NEEDS_REVIEW"]
    evidenceIds: list[Uuid] = Field(max_length=POLICY["evidenceFactsMaxItems"])
    explanation: str = Field(min_length=1, max_length=2000)


class ModelMetadata(StrictModel):
    model: str = Field(min_length=1, max_length=160)
    promptVersion: Literal["KYC-PROMPT-1"] = "KYC-PROMPT-1"

    @field_validator("model")
    @classmethod
    def nonblank_model(cls, value):
        if not value.strip():
            raise ValueError("model identifier must be nonblank")
        return value


class KycResponse(StrictModel):
    requestId: Uuid
    workflowId: Uuid
    generation: int = Field(ge=1, le=2147483647)
    runId: Uuid
    inputSnapshotHash: Hash
    proposal: KycProposal
    modelMetadata: ModelMetadata


class KycCaptureResponse(StrictModel):
    response: KycResponse
    modelMode: Literal["LIVE"] = "LIVE"
    promptHash: Hash
    modelOutputHash: Hash


def strict_json_loads(data: str | bytes):
    """Reject duplicate keys and non-JSON floats at every nesting level."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON value")

    # Count containers before the recursive decoder allocates nested objects.
    text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped: escaped = False
            elif char == "\\": escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in "[{":
            depth += 1
            if depth > POLICY["jsonMaxDepth"]: raise ValueError("JSON depth exceeded")
        elif char in "]}": depth -= 1
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
