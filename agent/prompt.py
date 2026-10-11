"""Privilege-separated message construction; reference text never enters system role."""
import json
from .private_files import read_registered_text

from .dto import KycRequest

PROMPT_VERSION = "KYC-PROMPT-1"


class PromptConfigurationError(ValueError):
    pass


def load_system_prompt(path: str) -> str:
    """Load an operator-provided private file without a repository fallback."""
    if not path:
        raise PromptConfigurationError("live mode requires FUSE_KYC_PROMPT_PATH")
    try:
        content = read_registered_text(path)
    except (OSError, UnicodeError, ValueError):
        raise PromptConfigurationError("FUSE_KYC_PROMPT_PATH must name a readable UTF-8 file") from None
    if not content.strip():
        raise PromptConfigurationError("FUSE_KYC_PROMPT_PATH must contain nonempty text")
    return content


def build_messages(request: KycRequest, system_prompt: str) -> list[dict[str, str]]:
    if not system_prompt.strip():
        raise PromptConfigurationError("private system text is unavailable")
    # Service token, grant/MAC, payment account, risk budget, request/run IDs and
    # snapshot hash are intentionally never made available to the model.
    evidence = {"customerId": request.customerId,
                "EVIDENCE_FACTS": [fact.model_dump() for fact in request.evidenceFacts]}
    references = {"UNTRUSTED_REFERENCE_DOCUMENTS": [document.model_dump() for document in request.documents]}
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(evidence, ensure_ascii=False, separators=(",", ":"))},
        {"role": "user", "content": json.dumps(references, ensure_ascii=False, separators=(",", ":"))},
    ]
