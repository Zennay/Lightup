"""Portable, source-free, scriptless HUMAN review of verified synthetic runs.

The portable ZIP is not a source receipt, signature, grant or live assessment.
Original archives and private three-file report stay outside this package.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any, Callable
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from .lab_score_portable_dashboard import render_portable_dashboard
from .lab_score_history_html import (
    build_history_review_summary, render_history_html, render_history_markdown,
)
from .lab_score_inspect import _private_dir_fd
from .lab_score_portable_html_safety import admit_inert_html
from .lab_score_suite import _private_output_directory

_SCHEMA = "lightup.lab-score-portable-human-review.v1"
_FILENAME = "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"
_MAX_ZIP_BYTES = 2 * 1024 * 1024


def _csv_bytes(summary: dict[str, Any]) -> bytes:
    text = io.StringIO()
    writer = csv.writer(text, lineterminator="\n")
    writer.writerow(("previous_index", "current_index", "status",
                     "independent_evaluations", "score_stable"))
    for pair in summary["pairs"]:
        writer.writerow((
            pair["previous_index"], pair["current_index"],
            "PASS" if pair["passed"] else "HOLD",
            pair["independent_evaluations"], pair["score_stable"],
        ))
    return text.getvalue().encode("utf-8")


def _files(report: dict[str, Any]) -> dict[str, bytes]:
    summary = build_history_review_summary(report)
    html = render_history_html(report).encode("utf-8")
    files = {
        "index.html": render_portable_dashboard(summary).encode("utf-8"),
        "history.html": html,
        "review.json": (
            json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n"
        ).encode("utf-8"),
        "review.csv": _csv_bytes(summary),
        "review.md": render_history_markdown(report).encode("utf-8"),
        "README.txt": (
            "LightUp synthetic fixed-loopback offline review, HUMAN only.\n"
            "Open index.html for global PASS/HOLD, priorities and pair navigation.\n"
            "Scriptless, offline, source-free display; no network/authorization.\n"
            "A PASS means only local consistency, NEVER external authority.\n"
            "HTML may show first-party allowlisted numeric scorer changes.\n"
            "CSV/JSON/Markdown omit raw numeric metric values.\n"
            "Private source archives, saved receipt bindings and source IDs "
            "are NOT included. ZIP hashes prove transport integrity only.\n"
        ).encode("utf-8"),
    }
    manifest = {
        "schema": _SCHEMA,
        "synthetic_localhost_only": True,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
        "passed": summary["passed"],
        "archives_checked": summary["archives_checked"],
        "pairs_checked": summary["pairs_checked"],
        "files": {name: hashlib.sha256(value).hexdigest()
                  for name, value in sorted(files.items())},
    }
    files["manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    return files


def save_portable_review(
    output_directory: str | Path,
    report: dict[str, Any],
    reverify_original_private_report: Callable[[], None],
) -> Path:
    """Create a no-overwrite owner-private ZIP only for an admitted review.

    Reverify original evidence and saved report both before and after writing;
    no partial package survives a refusal. ZIP contains strictly allowlisted
    anonymous exports, not original paths, hashes or private receipts.
    """
    reverify_original_private_report()
    files = _files(report)
    # A source-free ZIP must be inert at *creation*, not just on receipt.
    # Refuse renderer regressions before establishing any output directory.
    admit_inert_html(files["index.html"])
    admit_inert_html(files["history.html"])
    if len(files) != 7 or any(len(value) > 1024 * 1024 for value in files.values()):
        raise ValueError("portable review exceeds fixed allowlist or size bound")
    buffer = io.BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            entry = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o600 << 16
            archive.writestr(entry, content)
    data = buffer.getvalue()
    if len(data) > _MAX_ZIP_BYTES:
        raise ValueError("portable review archive too large")
    directory = _private_output_directory(output_directory)
    dirfd = _private_dir_fd(directory)
    temporary = "." + _FILENAME + ".tmp"
    published: tuple[int, int] | None = None
    try:
        # Do not make an incomplete ZIP observable under the final name.
        # The temporary inode is private, exclusive, and fsynced first.
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            source = os.stat(temporary, dir_fd=dirfd, follow_symlinks=False)
            original_inode = source.st_dev, source.st_ino
            reverify_original_private_report()
            # Atomic, no-overwrite publication. No reader can observe a
            # truncated or partially compressed archive at the final name.
            os.link(temporary, _FILENAME, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                    follow_symlinks=False)
            published = original_inode
            os.unlink(temporary, dir_fd=dirfd)
            temporary = ""
            reverify_original_private_report()
            readfd = os.open(_FILENAME, os.O_RDONLY | os.O_NOFOLLOW,
                             dir_fd=dirfd)
            try:
                before = os.fstat(readfd)
                actual = os.pread(readfd, _MAX_ZIP_BYTES + 1, 0)
                after = os.fstat(readfd)
                link = os.stat(_FILENAME, dir_fd=dirfd, follow_symlinks=False)
                if (actual != data
                        or (before.st_dev, before.st_ino) != published
                        or (before.st_dev, before.st_ino, before.st_size,
                            before.st_mtime_ns, before.st_ctime_ns) !=
                           (after.st_dev, after.st_ino, after.st_size,
                            after.st_mtime_ns, after.st_ctime_ns)
                        or (link.st_dev, link.st_ino) != published):
                    raise ValueError("portable review changed during publication")
            finally:
                os.close(readfd)
            if set(os.listdir(dirfd)) != {_FILENAME}:
                raise ValueError("unexpected portable review files")
            os.fsync(dirfd)
        except Exception:
            if published is not None:
                try:
                    entry = os.stat(_FILENAME, dir_fd=dirfd,
                                    follow_symlinks=False)
                    if (entry.st_dev, entry.st_ino) == published:
                        os.unlink(_FILENAME, dir_fd=dirfd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=dirfd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(dirfd)
    return directory / _FILENAME
