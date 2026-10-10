"""Bounded reads of explicitly registered operator files; no path from requests."""
import os
import stat
from pathlib import Path


def read_registered_text(path: str, max_bytes: int = 65_536) -> str:
    candidate = Path(path)
    if not path or ".." in candidate.parts:
        raise ValueError("invalid registered file")
    # The selected parent is the trust root. Every ancestor and final component
    # must be real, and openat/O_NOFOLLOW keeps the leaf selection race-safe.
    absolute = candidate.absolute()
    for ancestor in (*absolute.parents, absolute):
        if ancestor.is_symlink():
            raise ValueError("registered files cannot use symbolic links")
    root = absolute.parent.resolve(strict=True)
    if absolute.resolve(strict=True).parent != root:
        raise ValueError("registered file escaped its root")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                raise ValueError("registered file must be a bounded regular file")
            data = source.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("registered file exceeds limit")
            return data.decode("utf-8", errors="strict")
    finally:
        os.close(directory)
