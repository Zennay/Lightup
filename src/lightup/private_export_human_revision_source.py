"""One fail-closed custody boundary for three original encrypted HUMAN source files.

The original .lue reader, original .lun reader and their source-owner
authentication are not replaced. This shared offline wrapper only adds
owner-private exact-ciphertext identity before/after those original reads.
It neither establishes real client identity nor authorizes any assessment.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from .private_export_encrypted import MAX_ENVELOPE_SIZE
from .private_export_encrypted_notes import MAX_SEALED_PLAN

DIGEST_BYTES = hashlib.sha256().digest_size
ORIGINAL_TRIPLE_BYTES = 3 * DIGEST_BYTES


def _artifact_hash(path: str, max_size: int) -> bytes:
    """Private no-follow original ciphertext digest using a single descriptor."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("owner-private no-follow original ciphertext admission unavailable")
    fd = os.open(
        Path(path).expanduser(),
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_size > max_size or info.st_size == 0):
            raise ValueError("invalid owner-private original encrypted ciphertext")
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                data = stream.read(128 * 1024)
                if not data:
                    break
                digest.update(data)
        return digest.digest()
    finally:
        os.close(fd)


def _source_binding(earlier: str, plan: str, later: str) -> bytes:
    """Ordered original encrypted .lue / original .lun / later .lue bytes."""
    return b"".join((
        _artifact_hash(earlier, MAX_ENVELOPE_SIZE),
        _artifact_hash(plan, MAX_SEALED_PLAN),
        _artifact_hash(later, MAX_ENVELOPE_SIZE),
    ))


def _require_same_originals(earlier: str, plan: str, later: str, binding: bytes) -> None:
    if type(binding) is not bytes or len(binding) != ORIGINAL_TRIPLE_BYTES:
        raise ValueError("invalid original encrypted source identity")
    if _source_binding(earlier, plan, later) != binding:
        raise ValueError("original encrypted source/plan changed during HUMAN handling")


def _read_with_binding(earlier: str, plan: str, later: str) -> tuple:
    """Admit original source triplet once, detecting replacement mid-read.

    Import the unchanged original owner readers lazily to keep this narrow
    source-lock primitive independent from HUMAN carry, vault, UI and console.
    """
    from .private_export_human_revision import _read_unbound_inputs

    digest = _source_binding(earlier, plan, later)
    original = _read_unbound_inputs(earlier, plan, later)
    _require_same_originals(earlier, plan, later, digest)
    return (*original, digest)
