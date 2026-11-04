"""Synthetic strict JSON and UTF-8 wire-boundary regressions."""
import hashlib
import json

import pytest
from pydantic import ValidationError

from agent import product_limits
from agent.dto import SourceDocument, KycResponse, strict_json_loads
from agent.product_limits import ProductLimits


@pytest.fixture(autouse=True)
def explicit_limits(monkeypatch):
    limits = ProductLimits(
        http_header_max_bytes=1024, internal_response_max_bytes=4096,
        json_max_depth=8, max_parallel=1, model_timeout_seconds=1,
    )
    monkeypatch.setattr(product_limits, "_limits", limits)
    return limits


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_nonfinite_values_rejected_at_nested_positions(token):
    with pytest.raises(ValueError, match="non-finite JSON value"):
        strict_json_loads('{"items":[{"number":' + token + '}]}')


def test_finite_exponent_and_nested_escaped_duplicate_key_contract():
    assert strict_json_loads('{"number":1e308}') == {"number": 1e308}
    with pytest.raises(ValueError, match="duplicate JSON key"):
        strict_json_loads('{"items":[{"key":1,"\\u006bey":2}]}')


def test_invalid_utf8_wire_bytes_rejected_before_json_decode():
    with pytest.raises(UnicodeError):
        strict_json_loads(b'{"text":"\xff"}')


def test_depth_counts_containers_but_not_quoted_or_escaped_brackets():
    assert strict_json_loads('[' * 8 + '0' + ']' * 8) == [[[[[[[[0]]]]]]]]
    with pytest.raises(ValueError, match="depth"):
        strict_json_loads('[' * 9 + '0' + ']' * 9)
    quoted = {"text": '[[["{{{'}
    assert strict_json_loads(json.dumps(quoted)) == quoted


def test_decoder_recursion_is_fixed_validation_failure(monkeypatch):
    from agent import dto

    def recursive_decoder(*args, **kwargs):
        raise RecursionError("synthetic decoder recursion")

    monkeypatch.setattr(dto.json, "loads", recursive_decoder)
    with pytest.raises(ValueError, match="nesting|depth"):
        strict_json_loads('{"synthetic":[]}')


def document(text, version=1):
    return {
        "documentId": "00000000-0000-4000-8000-000000000001",
        "documentVersion": version,
        "contentHash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "text": text,
    }


def test_multibyte_document_byte_boundary_and_content_binding():
    text = "가" * 5461 + "a"
    assert len(text.encode("utf-8")) == 16384
    assert SourceDocument.model_validate(document(text)).text == text
    with pytest.raises(ValidationError, match="UTF-8 byte limit"):
        SourceDocument.model_validate(document(text + "a"))
    changed = document("synthetic")
    changed["text"] = "different synthetic"
    with pytest.raises(ValidationError, match="content hash"):
        SourceDocument.model_validate(changed)


@pytest.mark.parametrize("value", [True, False, 1.0, "1"])
def test_integer_wire_fields_do_not_coerce(value):
    with pytest.raises(ValidationError):
        SourceDocument.model_validate(document("synthetic", version=value))
    with pytest.raises(ValidationError):
        KycResponse.model_validate({
            "requestId": "00000000-0000-4000-8000-000000000001",
            "workflowId": "00000000-0000-4000-8000-000000000002",
            "generation": value,
            "runId": "00000000-0000-4000-8000-000000000003",
            "inputSnapshotHash": "a" * 64,
            "proposal": {"status": "NEEDS_REVIEW", "evidenceIds": [], "explanation": "synthetic"},
            "modelMetadata": {"model": "synthetic"},
        })
