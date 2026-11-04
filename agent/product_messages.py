"""Prepared product prompt data and deterministic public message assembly."""
from dataclasses import dataclass, field
import json

from .dto import EvidenceFact, KycRequest, SourceDocument


@dataclass(frozen=True, kw_only=True, slots=True)
class PreparedProductPrompt:
    system_text: str = field(repr=False)

    def __post_init__(self):
        if type(self.system_text) is not str or not self.system_text.strip():
            raise ValueError("Prepared product prompt must be nonblank text")


def assemble_messages(body: KycRequest, prepared: PreparedProductPrompt):
    """Request documents remain user data, never system instructions."""
    # Only concrete prepared data and DTO field values belong on this path.
    # In particular, subclass serializers and instance method overrides must
    # not introduce caller callbacks while an HTTP request is being served.
    if type(prepared) is not PreparedProductPrompt or type(body) is not KycRequest:
        raise TypeError("Concrete prepared prompt and request data are required")
    for values, item_type in ((body.evidenceFacts, EvidenceFact), (body.documents, SourceDocument)):
        if type(values) is not list or any(type(value) is not item_type for value in values):
            raise TypeError("Concrete request collection data are required")
    def scalar_fields(value, text_fields, integer_fields=()):
        fields = {name: getattr(value, name) for name in (*text_fields, *integer_fields)}
        if (any(type(fields[name]) is not str for name in text_fields)
                or any(type(fields[name]) is not int for name in integer_fields)):
            raise TypeError("Concrete request scalar data are required")
        return fields

    data = scalar_fields(body, ("requestId", "workflowId", "runId", "customerId", "policyVersion",
                               "inputSnapshotHash"), ("generation",))
    data["evidenceFacts"] = [scalar_fields(fact, ("evidenceId", "kind", "result"))
                             for fact in body.evidenceFacts]
    data["documents"] = [scalar_fields(document, ("documentId", "contentHash", "text"),
                                       ("documentVersion",)) for document in body.documents]
    return [
        {"role": "system", "content": prepared.system_text},
        {"role": "user", "content": json.dumps(
            data, ensure_ascii=False, separators=(",", ":"),
            sort_keys=True, allow_nan=False,
        )},
    ]
