"""Private, no-overwrite, source-bound offline lab score review storage.

The HTML is deliberately source-free. A second owner-private file binds it to
the exact previously verified original archive receipts. No cryptographic
signature or permission to perform real assessments is implied.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from .lab_score_inspect import _private_dir_fd, _artifact_fd
from .lab_score_suite import _private_output_directory

_MAX_HTML = 1024 * 1024
_MAX_BINDING = 16384
_FILES = ("history.html", "source_receipt.json")


def _payloads(html: str, source_receipt: dict[str, Any]) -> dict[str, bytes]:
    return {
        "history.html": html.encode("utf-8"),
        "source_receipt.json": (
            json.dumps(source_receipt, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8"),
    }


def _check_saved(fd: int, name: str, expected: bytes, original: tuple[int, int] | None = None) -> None:
    file_fd = _artifact_fd(fd, name, _MAX_HTML if name == "history.html" else _MAX_BINDING)
    try:
        before = os.fstat(file_fd)
        data = os.pread(file_fd, len(expected) + 1, 0)
        after = os.fstat(file_fd)
        link = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (data != expected
                or (original is not None and (before.st_dev, before.st_ino) != original)
                or (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
                or (link.st_dev, link.st_ino) != (after.st_dev, after.st_ino)):
            raise ValueError("saved private review changed")
    finally:
        os.close(file_fd)


def save_private_review(
    directory: str | Path, html: str, source_receipt: dict[str, Any],
    verify_original_source: Callable[[], dict[str, Any]],
) -> None:
    """Publish a complete two-file private review in a new directory.

    A review is considered complete only with both source-bound artifacts.
    Every file is individually published without overwrite, then read back.
    """
    payloads = _payloads(html, source_receipt)
    if len(payloads["history.html"]) > _MAX_HTML or len(payloads["source_receipt.json"]) > _MAX_BINDING:
        raise ValueError("private report exceeds size limit")
    root = _private_output_directory(directory)
    fd = _private_dir_fd(root)
    created: list[tuple[str, tuple[int, int]]] = []
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        try:
            for name in _FILES:
                data = payloads[name]
                temporary = "." + name + ".tmp"
                output_fd = os.open(temporary, flags, 0o600, dir_fd=fd)
                try:
                    with os.fdopen(output_fd, "wb") as output:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                    source = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                    original = source.st_dev, source.st_ino
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd,
                            follow_symlinks=False)
                    created.append((name, original))
                    os.unlink(temporary, dir_fd=fd)
                    _check_saved(fd, name, data, original)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
            if set(os.listdir(fd)) != set(_FILES):
                raise ValueError("unrecognized private review entry")
            # Original evidence can mutate *during* HTML/report publication.
            # Re-check its private receipt binding after both saved artifacts
            # were written, before reporting a successful review. On failure
            # the surrounding handler removes only our own linked inodes.
            if verify_original_source() != source_receipt:
                raise ValueError("original evidence changed during publication")
            os.fsync(fd)
        except Exception:
            for name, original in reversed(created):
                try:
                    entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if (entry.st_dev, entry.st_ino) == original:
                        os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    pass
            raise
    finally:
        os.close(fd)


def verify_private_review(
    directory: str | Path, html: str, source_receipt: dict[str, Any],
    verify_original_source: Callable[[], dict[str, Any]],
) -> None:
    """Recompare both private files with fresh original-source verification."""
    expected = _payloads(html, source_receipt)
    fd = _private_dir_fd(directory)
    try:
        if set(os.listdir(fd)) != set(_FILES):
            raise ValueError("incomplete or unexpected review files")
        for name in _FILES:
            _check_saved(fd, name, expected[name])
        if set(os.listdir(fd)) != set(_FILES):
            raise ValueError("review changed during readback")
        # Evidence may change while either saved report file is inspected.
        # A pre-read source binding alone could return a false VERIFIED.
        if verify_original_source() != source_receipt:
            raise ValueError("original evidence changed during review verification")
        for name in _FILES:
            _check_saved(fd, name, expected[name])
    finally:
        os.close(fd)
