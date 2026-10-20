"""Owner-private atomic local delivery of one authenticated finding review packet.

Linux only. This optional HUMAN product cannot authorize reading a tenant;
the existing authenticated tenant service performs that admission first.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import re
import secrets
import stat

from .domain import AccessContext, DomainStore
from .finding_export_review import PrivateFindingReview, render_client_findings_review

_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z")
_HOLD_NOTICE = (
    "PRIVATE HUMAN REVIEW ONLY - DRAFT/HOLD.\n"
    "Never distribute without separate authenticated recipient disclosure approval.\n"
    "Finding stages and suggested fixes are reported claims, NOT verified remediation.\n"
    "CSV and HTML contain sensitive free text despite standard pattern redaction.\n"
    "No client/operator consent, trusted signature, active assessment or deployment.\n"
)


def _private_parent(parent: Path) -> int:
    if not parent.is_absolute():
        raise ValueError("PRIVATE output parent must be an absolute path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(parent, flags)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise ValueError("PRIVATE output parent must be owned and mode 0700")
    return fd


def _file(folder_fd: int, name: str, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    file_fd = os.open(name, flags, 0o600, dir_fd=folder_fd)
    try:
        os.fchmod(file_fd, 0o600)
        with os.fdopen(file_fd, "wb", closefd=False) as writer:
            writer.write(contents)
            writer.flush()
        os.fsync(file_fd)
    finally:
        os.close(file_fd)


def _publish_noreplace(parent_fd: int, source: str, destination: str) -> None:
    """Use the Linux atomic no-overwrite primitive; refuse any fallback."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ValueError("atomic Linux renameat2(NO_REPLACE) unavailable")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(source), parent_fd,
                 os.fsencode(destination), 1) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def publish_client_findings_review(
    store: DomainStore,
    ctx: AccessContext,
    client_id: str,
    *,
    output_parent: str | Path,
    output_name: str,
    engagement_id: str | None = None,
) -> Path:
    """Create a NEW 0700 directory with matched 0600 CSV, HTML, JSON counts and HOLD notice.

    Returns the published path, never overwrites existing files/directories,
    performs no uploads, grants, scans, or other target interactions.
    The complete authenticated selection is admitted before any output is made.
    """
    if type(output_name) is not str or _SAFE_NAME.fullmatch(output_name) is None:
        raise ValueError("output_name must be a simple new private directory name")
    packet: PrivateFindingReview = render_client_findings_review(
        store, ctx, client_id, engagement_id=engagement_id)
    parent = Path(output_parent)
    parent_fd = _private_parent(parent)
    staging = ".review-" + secrets.token_hex(12)
    stage_fd = -1
    created = False
    published = False
    names = ("findings.csv", "review.html", "summary.json", "REVIEW_ONLY.txt")
    try:
        # The parent descriptor is held open; publication cannot follow a link
        # substituted for a caller-provided child path.
        os.mkdir(staging, 0o700, dir_fd=parent_fd)
        created = True
        stage_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        os.fchmod(stage_fd, 0o700)
        _file(stage_fd, names[0], packet.csv_text.encode("utf-8", "strict"))
        _file(stage_fd, names[1], packet.html_text.encode("utf-8", "strict"))
        _file(stage_fd, names[2], packet.summary_json.encode("utf-8", "strict"))
        _file(stage_fd, names[3], _HOLD_NOTICE.encode("utf-8"))
        os.fsync(stage_fd)
        _publish_noreplace(parent_fd, staging, output_name)
        published = True
        os.fsync(parent_fd)
        return parent / output_name
    finally:
        if not published and created:
            # Only our newly allocated directory is eligible for cleanup.
            if stage_fd >= 0:
                for name in names:
                    try:
                        os.unlink(name, dir_fd=stage_fd)
                    except FileNotFoundError:
                        pass
            try:
                os.rmdir(staging, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(parent_fd)
