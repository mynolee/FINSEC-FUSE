"""Descriptor-relative, no-overwrite writes for fixed evidence bundle files."""
from __future__ import annotations

import os
from pathlib import Path
import stat

_FILES = frozenset({"case_results.json", "case_results.csv", "metrics.json", "manifest.json"})
_FAILURE = "Secure bundle output unavailable"


def _capabilities():
    if (not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_NONBLOCK")
            or os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd
            or os.listdir not in os.supports_fd):
        raise ValueError(_FAILURE)


def _directory(parent, name, *, create):
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


def _same_bundle(directory, payloads):
    if set(os.listdir(directory)) != _FILES:
        return False
    for name, expected in payloads.items():
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(expected):
                return False
            chunks = []
            remaining = len(expected) + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if b"".join(chunks) != expected:
                return False
        finally:
            os.close(descriptor)
    return True


def write_bundle(output_root, experiment_id, payloads):
    """Reject symlink traversal and preserve existing files, including on failure.

    This does not provide transactional creation or cleanup after partial writes.
    A directory descriptor prevents traversal swaps from redirecting file opens;
    it does not prevent another authorized writer from modifying the same files.
    An empty output-root string denotes the current directory, like Path("").
    """
    _capabilities()
    if type(payloads) is not dict:
        raise ValueError(_FAILURE)
    payloads = payloads.copy()
    if (any(type(name) is not str for name in payloads) or set(payloads) != _FILES
            or any(type(value) is not bytes for value in payloads.values())):
        raise ValueError(_FAILURE)
    root = Path(output_root)
    if (".." in root.parts or not isinstance(experiment_id, str)
            or experiment_id in ("", ".", "..") or "/" in experiment_id
            or "\\" in experiment_id):
        raise ValueError(_FAILURE)
    absolute = root if root.is_absolute() else Path.cwd() / root
    descriptors = []
    try:
        directory = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory)
        for part in absolute.parts[1:]:
            directory = _directory(directory, part, create=True)
            descriptors.append(directory)
        try:
            os.mkdir(experiment_id, mode=0o700, dir_fd=directory)
        except FileExistsError:
            existing = _directory(directory, experiment_id, create=False)
            descriptors.append(existing)
            if not _same_bundle(existing, payloads):
                raise ValueError(_FAILURE)
            return root / experiment_id
        destination = _directory(directory, experiment_id, create=False)
        descriptors.append(destination)
        for name in ("case_results.json", "case_results.csv", "metrics.json", "manifest.json"):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 mode=0o600, dir_fd=destination)
            try:
                pending = memoryview(payloads[name])
                while pending:
                    written = os.write(descriptor, pending)
                    if written <= 0:
                        raise ValueError(_FAILURE)
                    pending = pending[written:]
            finally:
                os.close(descriptor)
        return root / experiment_id
    except (OSError, ValueError):
        raise ValueError(_FAILURE) from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
