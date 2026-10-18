"""Single-snapshot private LightUp human review workspace (DRAFT/HOLD).

Compose only already-admitted retrospective source data. Never contact a target,
issue a grant, persist consent, authenticate a report or dispatch a scanner.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

from board_html import render
from window_review import (
    AUTHORITY_FLAGS, ReviewHold, ensure_private_destination, ics,
    private_publish,
)

MAX_WORKSPACE_BYTES = 3 * 1024 * 1024


def _bytes(source: dict) -> bytes:
    payload = (json.dumps(source, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_WORKSPACE_BYTES:
        raise ReviewHold("private workspace artifact exceeds bounded size")
    return payload


def create_workspace(destination: Path, agenda: dict, *, original_bytes: bytes) -> dict:
    """Publish an all-from-one-source operator workspace, no final overwrite.

    The new, private 0700 directory is only considered complete when its
    last file, an exclusive 0600 manifest, exists. Any ordinary failure
    removes only own newly created artifacts and own directory.
    """
    destination = Path(destination)
    if destination.name in ("", ".", ".."):
        raise ReviewHold("invalid workspace directory")
    ensure_private_destination(destination)
    if (type(original_bytes) is not bytes or not 0 < len(original_bytes) <= 512 * 1024
            or sha256(original_bytes).hexdigest() != agenda["original_source_sha256"]):
        raise ReviewHold("exact original private Casebook bytes do not match source")
    files = {
        "original-private-casebook.json": original_bytes,
        "human-review-board.html": render(agenda),
        "human-review-agenda.json": _bytes(agenda),
        "human-review-calendar.ics": ics(agenda),
    }
    filenames = tuple(files)
    # The exact original source is in a separate private file, NEVER inside HTML.
    manifest = {
        "schema": "lightup.scope_window_workspace.v1",
        "status": agenda["status"],
        "source": "unsigned_original_casebook_retrospective",
        "as_of": agenda["as_of"],
        "prepared_at": agenda["prepared_at"],
        "original_source_sha256": agenda["original_source_sha256"],
        "notes": ("Human retrospective review only; source SHA binds bytes and "
                  "does not verify issuer, operator consent or revocation."),
        "files": {
            name: {"bytes": len(files[name]),
                   "sha256": sha256(files[name]).hexdigest()}
            for name in filenames
        },
        "declared_counts": agenda["declared_counts"],
        **dict.fromkeys(AUTHORITY_FLAGS, False),
    }
    files["human-review-manifest.json"] = _bytes(manifest)
    os.mkdir(destination, 0o700)
    written: list[Path] = []
    try:
        info = destination.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise ReviewHold("private workspace directory not admitted")
        for name, payload in files.items():
            path = destination / name
            private_publish(path, payload)
            written.append(path)
        dfd = os.open(destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return manifest
    except BaseException:
        for path in reversed(written):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            destination.rmdir()
        except OSError:
            # Any leftovers remain inside an owner-only 0700 directory.
            pass
        raise
