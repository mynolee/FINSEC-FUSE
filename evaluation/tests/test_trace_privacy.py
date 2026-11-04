"""Synthetic regression coverage for metadata projection privacy."""

import json

from evaluation.fixture_loader import fingerprint
from evaluation.trace_sanitizer import safe_identifier, safe_label, sanitize_trace


def test_unknown_metadata_is_not_exported_or_fingerprinted():
    marker = "synthetic-private-metadata-example-only"
    source = {
        "traceId": marker,
        "request": {"body": marker},
        "actionRuns": [{"role": marker, "requestId": marker}],
        "modelCapture": {"sanitizedCandidate": {"evidenceIds": [marker]}},
    }
    result = sanitize_trace(source)
    encoded = json.dumps(result)

    assert safe_label(marker) is None
    assert safe_identifier(marker) is None
    assert marker not in encoded
    assert fingerprint(marker) not in encoded
    assert fingerprint(source) not in encoded
    assert "sourceTraceHash" not in result
    projection = {key: value for key, value in result.items() if key != "sanitizedTraceHash"}
    assert result["sanitizedTraceHash"] == fingerprint(projection)


def test_removed_content_does_not_change_projected_trace_hash():
    clean = {"actionRuns": [{"status": "SUCCEEDED"}]}
    with_removed_content = {
        "actionRuns": [{"status": "SUCCEEDED", "requestBody": "synthetic-secret-a"}],
        "authorization": "synthetic-secret-b",
    }
    assert sanitize_trace(clean) == sanitize_trace(with_removed_content)


def test_explicit_product_identifiers_and_evidence_hashes_are_preserved():
    identifier = "11111111-1111-4111-8111-111111111111"
    evidence_hash = "a" * 64
    result = sanitize_trace({
        "traceId": identifier,
        "armBindings": {"responseByteHash": evidence_hash, "bindingVerified": True},
    })
    assert result["traceId"] == identifier
    assert result["armBindings"] == {
        "responseByteHash": evidence_hash, "bindingVerified": True,
    }
