"""Source-bound owner-private transferable HUMAN HOLD reviewer package.

This package contains ONLY verified first-party synthetic original transports
and already-admitted HUMAN follow-ups. Its local hash receipt does not confer
original identity, independent review, consent, remediation or authorization.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from .lab_score_action_batch import select_all_original_holds
from .lab_score_focus_workroom import (
    _paths, publish_private_focus, read_private_batch_selection, verify_private_focus,
)
from .lab_score_inspect import _artifact_fd, _private_dir_fd
from .lab_score_queue_workroom import _check_file
from .lab_score_review_actions import build_review_actions
from .lab_score_review_delta import compare_portable_review_transports
from .lab_score_suite import _private_output_directory

_ZIP = "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"
_FORMATS = {"actions-batch-json": "batch.json",
            "actions-batch-markdown": "batch.md",
            "actions-batch-html": "batch.html",
            "actions-batch-csv": "batch.csv"}
_FILES = set(_FORMATS.values()) | {"manifest.json"}
_MAX_ZIP_BYTES = 4 * 1024 * 1024


def _zip_bytes(path: Path) -> bytes:
    """Read one regular original ZIP, pinning its descriptor against substitution."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or not 1 <= before.st_size <= _MAX_ZIP_BYTES):
            raise ValueError("invalid bounded synthetic original source")
        data = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        if (len(data) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                    after.st_ctime_ns)):
            raise ValueError("original synthetic ZIP changed during private copy")
        return data
    finally:
        os.close(fd)


def _saved_zip(path: Path) -> bytes:
    fd = _private_dir_fd(path.parent)
    try:
        if set(os.listdir(fd)) != {_ZIP}:
            raise ValueError("unexpected private synthetic ZIP source inventory")
        reader = _artifact_fd(fd, _ZIP, _MAX_ZIP_BYTES)
        try:
            before = os.fstat(reader)
            data = os.pread(reader, before.st_size + 1, 0)
            after = os.fstat(reader)
            linked = os.stat(_ZIP, dir_fd=fd, follow_symlinks=False)
            stable = lambda s: (s.st_dev, s.st_ino, s.st_size,
                                s.st_mtime_ns, s.st_ctime_ns)
            if (not data or len(data) != before.st_size
                    or stable(before) != stable(after)
                    or stable(after) != stable(linked)):
                raise ValueError("untrusted local original ZIP changed")
        finally:
            os.close(reader)
        return data
    finally:
        os.close(fd)


def _receipt(comparison: dict, selector: str,
             source_bytes: dict[str, bytes], saved: dict[str, bytes]) -> bytes:
    if set(saved) != _FILES or comparison["review_status"] != "HOLD":
        raise ValueError("source-bound portable HUMAN bundle requires original HOLD")
    data = {
        "schema": "lightup.original-synthetic-human-hold-transfer.v1",
        "selector": selector,
        "source_zip_sha256": {key: hashlib.sha256(value).hexdigest()
                              for key, value in source_bytes.items()},
        "saved_sha256": {key: hashlib.sha256(value).hexdigest()
                         for key, value in saved.items()},
        "original_unsigned_transport_sha256": {
            key: comparison[key]["unsigned_transport_sha256"]
            for key in ("baseline", "candidate")},
        "global_review_status": "HOLD",
        "completion": "NOT_VERIFIED",
        "unsigned_consistency_only": True,
        "original_source_authenticated": False,
        "same_originals_proven": False,
        "authorization_granted": False,
        "remediation_verified": False,
        "deployment": False,
        "mandatory_independent_human_review": True,
    }
    return (json.dumps(data, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _private_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def publish_human_transfer(first: str, second: str, directory: str,
                           selection: str = "ALL") -> None:
    """Publish a new 0700 self-contained private folder. Never overwrite."""
    destination = _paths(first, second, directory)
    originals = {"baseline": Path(os.path.abspath(Path(first).expanduser())),
                 "candidate": Path(os.path.abspath(Path(second).expanduser()))}
    comparison = compare_portable_review_transports(first, second)
    actions = build_review_actions(comparison, first, second)
    if selection == "ALL":
        selection = select_all_original_holds(actions)
    # Resolve any explicit selection before creating any output directory.
    from .lab_score_action_batch import render_human_batch
    render_human_batch(actions, selection, "actions-batch-json")
    originals_bytes = {key: _zip_bytes(path) for key, path in originals.items()}
    root = _private_output_directory(destination)
    sources = root / "sources"
    sources.mkdir(mode=0o700)
    copied: dict[str, Path] = {}
    for key in ("baseline", "candidate"):
        folder = sources / key
        folder.mkdir(mode=0o700)
        output = folder / _ZIP
        _private_write(output, originals_bytes[key])
        copied[key] = output
    if (any(_zip_bytes(originals[key]) != originals_bytes[key]
            for key in ("baseline", "candidate"))):
        raise ValueError("original ZIP changed during source-bound transfer")
    saved_comparison = publish_private_focus(
        str(copied["baseline"]), str(copied["candidate"]), str(root / "review"), selection)
    verified, saved = verify_private_focus(
        str(copied["baseline"]), str(copied["candidate"]), str(root / "review"), selection)
    if verified != comparison or saved_comparison != comparison:
        raise ValueError("original synthetic transport changed before transfer finished")
    data = _receipt(verified, selection, originals_bytes, saved)
    _private_write(root / "bundle.json", data)
    # The reviewer uses only this saved folder to verify. No original outside
    # paths or names, source authority or secrets are emitted.
    verify_human_transfer(str(root), fmt="text")


def verify_human_transfer(directory: str, *, fmt: str = "text") -> str:
    """Verify *all* original source and review members before any view is returned."""
    if fmt not in ("text", *_FORMATS):
        raise ValueError("invalid offline HUMAN bundle output format")
    root = Path(directory).expanduser()
    root_fd = _private_dir_fd(root)
    try:
        if set(os.listdir(root_fd)) != {"sources", "review", "bundle.json"}:
            raise ValueError("untrusted HUMAN transfer root inventory")
        sources_fd = _private_dir_fd(root / "sources")
        try:
            if set(os.listdir(sources_fd)) != {"baseline", "candidate"}:
                raise ValueError("untrusted HUMAN transfer sources inventory")
        finally:
            os.close(sources_fd)
        originals = {key: root / "sources" / key / _ZIP
                     for key in ("baseline", "candidate")}
        originals_bytes = {key: _saved_zip(originals[key])
                           for key in ("baseline", "candidate")}
        selection = read_private_batch_selection(
            str(originals["baseline"]), str(originals["candidate"]), str(root / "review"))
        comparison, saved = verify_private_focus(
            str(originals["baseline"]), str(originals["candidate"]),
            str(root / "review"), selection)
        # Enforce v2 five-file contract, with no silent v1 downgrade.
        expected = _receipt(comparison, selection, originals_bytes, saved)
        _check_file(root_fd, "bundle.json", expected)
        if set(os.listdir(root_fd)) != {"sources", "review", "bundle.json"}:
            raise ValueError("HUMAN transfer changed during readback")
        # Read both source ZIPs twice, and verify all workroom bytes again.
        if any(_saved_zip(originals[key]) != originals_bytes[key]
               for key in ("baseline", "candidate")):
            raise ValueError("synthetic transfer original ZIP changed on reread")
    finally:
        os.close(root_fd)
    if fmt == "text":
        return "LightUp synthetic HUMAN bundle reverified: GLOBAL HOLD; NOT VERIFIED; no authorization.\n"
    return saved[_FORMATS[fmt]].decode("utf-8")
