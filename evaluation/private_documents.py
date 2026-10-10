"""Resolve opaque fixture IDs only for explicitly configured LIVE evaluation."""
import re

from agent.private_files import read_registered_text
from agent.security_policy import POLICY

from agent.dto import strict_json_loads

MAX_FILE_BYTES = 1_048_576


def load_private_documents(path: str) -> dict[str, str]:
    if not path:
        raise ValueError("LIVE requires FUSE_PRIVATE_DOCUMENTS_PATH")
    try:
        documents = strict_json_loads(read_registered_text(path, max_bytes=MAX_FILE_BYTES))
    except (OSError, UnicodeError, ValueError):
        raise ValueError("FUSE_PRIVATE_DOCUMENTS_PATH must name a readable UTF-8 JSON map") from None
    if not isinstance(documents, dict) or not documents or len(documents) > 256 or any(
        not isinstance(key, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", key) or not isinstance(value, str) or not value.strip()
        or len(value.encode("utf-8")) > POLICY["documentTextMaxUtf8Bytes"] or value.startswith("FUSE_DOCUMENT_ID:") for key, value in documents.items()
    ):
        raise ValueError("FUSE_PRIVATE_DOCUMENTS_PATH must contain nonempty bounded text values")
    return documents


def resolve_document(document_id: str, documents: dict[str, str]) -> str:
    if document_id not in documents:
        raise ValueError("private document asset is missing for a selected fixture ID")
    return documents[document_id]
