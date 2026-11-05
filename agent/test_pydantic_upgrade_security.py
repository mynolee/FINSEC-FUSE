"""Synthetic nested wire-boundary regressions for dependency upgrades."""
from copy import deepcopy
import hashlib
import json

import pytest
from pydantic import ValidationError

from agent.dto import EvidenceFact, SourceDocument, KycCaptureResponse


_UUID = "00000000-0000-0000-0000-000000000001"
_TEXT = "Synthetic document"
_DOCUMENT = {
    "documentId": _UUID, "documentVersion": 1,
    "contentHash": hashlib.sha256(_TEXT.encode("utf-8")).hexdigest(), "text": _TEXT,
}
_CAPTURE = {
    "response": {
        "requestId": _UUID, "workflowId": _UUID, "generation": 1,
        "runId": _UUID, "inputSnapshotHash": "0" * 64,
        "proposal": {"status": "NEEDS_REVIEW", "evidenceIds": [],
                     "explanation": "Synthetic review required"},
        "modelMetadata": {"model": "synthetic-model", "promptVersion": "KYC-PROMPT-1"},
    },
    "modelMode": "LIVE", "promptHash": "1" * 64, "modelOutputHash": "2" * 64,
}


@pytest.mark.parametrize("wire", ["python", "json"])
@pytest.mark.parametrize("model,payload,path", [
    (EvidenceFact, {"evidenceId": _UUID, "kind": "ID_DOC", "result": "PASS"}, ()),
    (SourceDocument, _DOCUMENT, ()),
    (KycCaptureResponse, _CAPTURE, ("response",)),
    (KycCaptureResponse, _CAPTURE, ("response", "proposal")),
    (KycCaptureResponse, _CAPTURE, ("response", "modelMetadata")),
], ids=["evidence", "document", "response", "proposal", "model-metadata"])
def test_unknown_fields_cannot_be_silently_discarded(model, payload, path, wire):
    def validate(value):
        if wire == "json":
            return model.model_validate_json(json.dumps(value, ensure_ascii=False))
        return model.model_validate(value)

    # A malformed positive fixture must fail outside the refusal assertion.
    accepted = validate(deepcopy(payload))
    assert accepted.model_dump(mode="json") == payload
    assert json.loads(accepted.model_dump_json()) == payload

    changed = deepcopy(payload)
    target = changed
    for component in path:
        target = target[component]
    target["authority"] = "UNTRUSTED_SYNTHETIC_VALUE"
    with pytest.raises(ValidationError) as refusal:
        validate(changed)
    errors = refusal.value.errors(include_url=False, include_input=False)
    assert [(error["loc"], error["type"]) for error in errors] == [
        (path + ("authority",), "extra_forbidden")
    ]
