"""Synthetic filesystem-only contracts; no real reports or credentials."""
import os
import stat

import pytest

from evaluation.bundle_writer import write_bundle
from evaluation import bundle_writer


def payloads():
    return {name: b"synthetic-only\n" for name in (
        "case_results.json", "case_results.csv", "metrics.json", "manifest.json",
    )}


def test_equal_bundle_is_idempotent_and_files_are_private(tmp_path):
    root = tmp_path.resolve() / "output"
    destination = write_bundle(root, "synthetic-run", payloads())
    assert destination == root / "synthetic-run"
    assert write_bundle(root, "synthetic-run", payloads()) == destination
    for name, expected in payloads().items():
        assert (destination / name).read_bytes() == expected
        assert stat.S_IMODE((destination / name).stat().st_mode) & 0o077 == 0


@pytest.mark.parametrize("where", ["ancestor", "destination", "file"])
def test_symlinks_are_rejected_without_writing_target(tmp_path, where):
    base = tmp_path.resolve()
    outside = base / "outside"
    outside.mkdir()
    root = base / "output"
    root.mkdir()
    if where == "ancestor":
        (root / "link").symlink_to(outside, target_is_directory=True)
        root = root / "link" / "nested"
    elif where == "destination":
        (root / "synthetic-run").symlink_to(outside, target_is_directory=True)
    else:
        destination = write_bundle(root, "synthetic-run", payloads())
        (destination / "metrics.json").unlink()
        (outside / "metrics.json").write_bytes(payloads()["metrics.json"])
        (destination / "metrics.json").symlink_to(outside / "metrics.json")
    before = {p.name: p.read_bytes() for p in outside.iterdir() if p.is_file()}
    with pytest.raises(ValueError, match="Secure bundle output unavailable"):
        write_bundle(root, "synthetic-run", payloads())
    assert {p.name: p.read_bytes() for p in outside.iterdir() if p.is_file()} == before
    assert not (outside / "nested").exists()


def test_changed_existing_bytes_are_preserved(tmp_path):
    root = tmp_path.resolve()
    destination = write_bundle(root, "synthetic-run", payloads())
    changed = destination / "metrics.json"
    changed.write_bytes(b"synthetic-altered")
    with pytest.raises(ValueError):
        write_bundle(root, "synthetic-run", payloads())
    assert changed.read_bytes() == b"synthetic-altered"


def test_parent_traversal_and_unexpected_file_names_are_rejected(tmp_path):
    root = tmp_path.resolve()
    with pytest.raises(ValueError):
        write_bundle(root / ".." / "escape", "synthetic-run", payloads())
    invalid = payloads()
    invalid["../escape"] = b"synthetic-only"
    with pytest.raises(ValueError):
        write_bundle(root, "synthetic-run", invalid)
    assert not (root / "synthetic-run").exists()


def test_missing_no_follow_capability_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "O_NOFOLLOW")
    root = tmp_path.resolve() / "output"
    with pytest.raises(ValueError, match="Secure bundle output unavailable"):
        write_bundle(root, "synthetic-run", payloads())
    assert not root.exists()


def test_destination_swap_to_symlink_between_mkdir_and_open_is_rejected(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "output"
    outside = tmp_path.resolve() / "outside"
    outside.mkdir()
    original = bundle_writer._directory

    def swap_before_open(parent, name, *, create):
        if name == "synthetic-run":
            (root / name).rename(root / "preserved-empty")
            (root / name).symlink_to(outside, target_is_directory=True)
        return original(parent, name, create=create)

    monkeypatch.setattr(bundle_writer, "_directory", swap_before_open)
    with pytest.raises(ValueError, match="Secure bundle output unavailable"):
        write_bundle(root, "synthetic-run", payloads())
    assert list(outside.iterdir()) == []
    assert list((root / "preserved-empty").iterdir()) == []


def test_partial_write_failure_preserves_bytes_and_retry_rejects_bundle(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    original_write = os.write
    calls = 0

    def fail_during_second_file(descriptor, value):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(descriptor, value)
        if calls == 2:
            return original_write(descriptor, value[:3])
        raise OSError("synthetic write interruption")

    with monkeypatch.context() as injected:
        injected.setattr(os, "write", fail_during_second_file)
        with pytest.raises(ValueError, match="Secure bundle output unavailable"):
            write_bundle(root, "synthetic-run", payloads())
    destination = root / "synthetic-run"
    preserved = {p.name: p.read_bytes() for p in destination.iterdir()}
    assert preserved == {
        "case_results.json": payloads()["case_results.json"],
        "case_results.csv": payloads()["case_results.csv"][:3],
    }
    assert not (destination / "manifest.json").exists()
    with pytest.raises(ValueError, match="Secure bundle output unavailable"):
        write_bundle(root, "synthetic-run", payloads())
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == preserved


def test_empty_output_root_uses_current_directory(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.chdir(root)
    destination = write_bundle("", "synthetic-run", payloads())
    assert destination.resolve() == root / "synthetic-run"
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == payloads()


@pytest.mark.parametrize("identifier", ["", ".", "..", "/absolute", "a/b", "a\\b"])
def test_invalid_experiment_identifiers_do_not_create_output(tmp_path, identifier):
    root = tmp_path.resolve() / "output"
    with pytest.raises(ValueError, match="Secure bundle output unavailable"):
        write_bundle(root, identifier, payloads())
    assert not root.exists()


def test_payload_snapshot_survives_caller_changes_before_creation(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "output"
    supplied = payloads()
    expected = dict(supplied)
    original = bundle_writer._directory

    def mutate_payloads(parent, name, *, create):
        supplied.clear()
        supplied["../synthetic-unexpected"] = b"synthetic-caller-change"
        return original(parent, name, create=create)

    monkeypatch.setattr(bundle_writer, "_directory", mutate_payloads)
    destination = write_bundle(root, "synthetic-run", supplied)
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == expected
    assert not (root / "synthetic-unexpected").exists()


def test_existing_bundle_comparison_uses_the_detached_payload_snapshot(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    expected = payloads()
    destination = write_bundle(root, "synthetic-run", expected)
    supplied = dict(expected)
    original = bundle_writer._directory

    def mutate_payloads(parent, name, *, create):
        if name == "synthetic-run":
            supplied["metrics.json"] = b"synthetic-late-change"
        return original(parent, name, create=create)

    monkeypatch.setattr(bundle_writer, "_directory", mutate_payloads)
    assert write_bundle(root, "synthetic-run", supplied) == destination
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == expected


def test_custom_payload_mapping_and_keys_are_rejected_before_filesystem_callbacks(tmp_path):
    class CustomPayloads(dict):
        def copy(self):
            raise AssertionError("Custom payload copy must not execute")

    class InheritedName(str):
        pass

    for supplied in (CustomPayloads(payloads()),
                     {InheritedName(name): value for name, value in payloads().items()}):
        with pytest.raises(ValueError, match="Secure bundle output unavailable"):
            write_bundle(tmp_path.resolve() / "output", "synthetic-run", supplied)
    assert not (tmp_path / "output").exists()
