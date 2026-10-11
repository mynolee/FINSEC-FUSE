import asyncio
import json

import pytest

from evaluation.fixture_loader import load_fixture_set
from evaluation.private_documents import load_private_documents, resolve_document
from evaluation.scenario_runner import model_request, prompt_audit


def test_public_fixture_registry_contains_only_opaque_document_ids():
    manifest = load_fixture_set("security-evaluation-v1")
    rag = [case for case in manifest["cases"] if case["family"] == "RAG_POISONING"]
    assert [case["injection"]["parameters"] for case in rag] == [
        {"documentTextId": f"rag-{index:02d}"} for index in range(1, 6)]
    assert all("documentText" not in case["injection"]["parameters"] for case in manifest["cases"])


def test_external_reference_file_and_request_hash_binding(tmp_path):
    path = tmp_path / "private.json"
    path.write_text(json.dumps({"rag-01": "fixture-reference-001"}))
    documents = load_private_documents(str(path))
    case = load_fixture_set("security-evaluation-v1", ["A_RAG_POISONING_01"])["cases"][0]
    replay = model_request(case)
    live = model_request(case, documents)
    assert replay.documents[0].text == "FUSE_DOCUMENT_ID:rag-01"
    assert live.documents[0].text == "fixture-reference-001"
    assert live.documents[0].contentHash != replay.documents[0].contentHash
    assert live.inputSnapshotHash != replay.inputSnapshotHash
    with pytest.raises(ValueError, match="missing"):
        resolve_document("rag-02", documents)


@pytest.mark.parametrize("raw", ["{}", "[]", "null", '{"rag-01":""}', '{"rag-01":1}', '{"rag-01":"a","rag-01":"b"}', '{"rag-01":NaN}', '{"rag-01":"FUSE_DOCUMENT_ID:rag-01"}'])
def test_invalid_private_reference_maps_fail_closed(tmp_path, raw):
    path = tmp_path / "private.json"
    path.write_text(raw)
    with pytest.raises(ValueError, match="FUSE_PRIVATE_DOCUMENTS_PATH"):
        load_private_documents(str(path))


def test_missing_reference_configuration_is_explicit(tmp_path):
    for path in ("", str(tmp_path / "missing.json")):
        with pytest.raises(ValueError, match="FUSE_PRIVATE_DOCUMENTS_PATH"):
            load_private_documents(path)


@pytest.mark.parametrize("raw", [b"\xff", b"x" * 1_048_577, json.dumps({"rag-01": "x" * 65_537}).encode()])
def test_invalid_encoding_or_oversized_private_maps_fail_closed(tmp_path, raw):
    path = tmp_path / "private.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="FUSE_PRIVATE_DOCUMENTS_PATH"):
        load_private_documents(str(path))


def test_offline_audit_does_not_read_private_files(monkeypatch, internal_service_token):
    monkeypatch.setenv("FUSE_KYC_MODE", "live")
    monkeypatch.setenv("FUSE_KYC_PROMPT_PATH", "/unavailable/private.txt")
    monkeypatch.setenv("FUSE_PRIVATE_DOCUMENTS_PATH", "/unavailable/private.json")
    monkeypatch.setattr("evaluation.scenario_runner.load_private_documents", lambda path: pytest.fail("unexpected private read"))
    monkeypatch.setattr("agent.settings.load_system_prompt", lambda path: pytest.fail("unexpected system file read"))
    report = asyncio.run(prompt_audit(load_fixture_set("security-evaluation-v1", ["A_RAG_POISONING_01"]), "offline", 1))
    assert report["privatePromptLoaded"] is False
    assert report["systemPromptHash"] is None
    assert report["caseOutputs"][0]["promptHash"] is None
    assert report["caseOutputs"][0]["status"] == "COMPLETED"


def test_live_audit_preflights_every_selected_reference_before_generation(tmp_path, monkeypatch, internal_service_token):
    prompt = tmp_path / "private.txt"
    prompt.write_text("fixture-system-001")
    documents = tmp_path / "private.json"
    documents.write_text(json.dumps({"rag-01": "fixture-reference-001"}))
    for key, value in {"FUSE_KYC_PROMPT_PATH": str(prompt), "FUSE_PRIVATE_DOCUMENTS_PATH": str(documents),
                       "FUSE_LLM_MODEL": "test-model", "FUSE_LLM_API_KEY": "test-value"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("agent.llm_adapter.LiveAdapter.propose", lambda *args: pytest.fail("provider must not be contacted"))
    manifest = load_fixture_set("security-evaluation-v1", ["A_RAG_POISONING_01", "A_RAG_POISONING_02"])
    with pytest.raises(ValueError, match="missing"):
        asyncio.run(prompt_audit(manifest, "live", 3))


def test_private_reference_map_rejects_symlinks_and_parent_traversal(tmp_path):
    real=tmp_path/'private.json';real.write_text(json.dumps({'rag-01':'opaque'}))
    leaf=tmp_path/'linked.json';leaf.symlink_to(real)
    parent=tmp_path/'linked-parent';parent.symlink_to(tmp_path,target_is_directory=True)
    for path in [leaf,parent/'private.json',tmp_path/'..'/tmp_path.name/'private.json']:
        with pytest.raises(ValueError,match='FUSE_PRIVATE_DOCUMENTS_PATH'): load_private_documents(str(path))
    assert load_private_documents(str(real)) == {'rag-01':'opaque'}


def test_private_reference_limits_count_decoded_utf8_bytes(tmp_path):
    path=tmp_path/'private.json';text='😀'*4096
    path.write_text(json.dumps({'rag-01':text}))
    assert load_private_documents(str(path))['rag-01']==text
    path.write_text(json.dumps({'rag-01':text+'x'}))
    with pytest.raises(ValueError,match='FUSE_PRIVATE_DOCUMENTS_PATH'):load_private_documents(str(path))


def test_private_reference_ids_and_registry_count_are_bounded(tmp_path):
    path=tmp_path/'private.json'
    for documents in [{'../outside':'opaque'}, {str(n):'opaque' for n in range(257)}]:
        path.write_text(json.dumps(documents))
        with pytest.raises(ValueError,match='FUSE_PRIVATE_DOCUMENTS_PATH'):load_private_documents(str(path))
