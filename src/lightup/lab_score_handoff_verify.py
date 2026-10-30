"""Read-only transport integrity check for a portable synthetic HUMAN review.

A passing ZIP hash check does not authenticate the original private archive,
its author, independent reviewer, consent, target, grant or assessment result.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile, BadZipFile

from .lab_score_inspect import _artifact_fd, _private_dir_fd

_SCHEMA = "lightup.lab-score-portable-human-review.v1"
_SUMMARY_SCHEMA = "lightup.lab-score-private-review-summary.v1"
_FILES = frozenset(("index.html", "history.html", "review.json",
                    "review.csv", "review.md", "README.txt", "manifest.json"))
_MAX_ARCHIVE = 2 * 1024 * 1024
_MAX_FILE = 1024 * 1024


def _unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _decode_json(content: bytes) -> dict[str, Any]:
    result = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_pairs,
                        parse_constant=_reject_constant)
    if not isinstance(result, dict):
        raise ValueError("invalid JSON object")
    return result


def _validate_summary(summary: dict[str, Any]) -> None:
    n, count = summary.get("archives_checked"), summary.get("pairs_checked")
    if (summary.get("schema") != _SUMMARY_SCHEMA
            or type(n) is not int or not 2 <= n <= 8
            or type(count) is not int or count != n * (n - 1) // 2
            or type(summary.get("passed")) is not bool
            or len(summary.get("pairs", [])) != count):
        raise ValueError("invalid anonymous summary")
    seen = set()
    for item in summary["pairs"]:
        if not isinstance(item, dict):
            raise ValueError("invalid anonymous pair")
        i, j = item.get("previous_index"), item.get("current_index")
        independence, stable, passed = (
            item.get("independent_evaluations"), item.get("score_stable"),
            item.get("passed"))
        if (type(i) is not int or type(j) is not int or not 1 <= i < j <= n
                or (i, j) in seen or type(independence) is not bool
                or type(stable) is not bool or type(passed) is not bool
                or passed != (independence and stable)):
            raise ValueError("contradictory pair metadata")
        seen.add((i, j))
    if (len(seen) != count or
            summary["passed"] != all(p["passed"] for p in summary["pairs"])):
        raise ValueError("contradictory global result")
    if any(summary.get(field) is not False
           for field in ("authorization_granted", "external_targets_contacted",
                         "deployment")):
        raise ValueError("unsafe portable review authority fields")


def verify_portable_review(path: str | Path) -> dict[str, Any]:
    """No-network, no-write ZIP integrity verification; never original identity."""
    path = Path(path).expanduser()
    if ".." in path.parts or not path.name or path.name != "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip":
        raise ValueError("invalid portable review path")
    parent = _private_dir_fd(path.parent)
    try:
        fd = _artifact_fd(parent, path.name, _MAX_ARCHIVE)
        try:
            first = os.fstat(fd)
            blob = os.pread(fd, _MAX_ARCHIVE + 1, 0)
            second = os.fstat(fd)
            link = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (len(blob) != first.st_size
                    or (first.st_dev, first.st_ino, first.st_size,
                        first.st_mtime_ns, first.st_ctime_ns) !=
                       (second.st_dev, second.st_ino, second.st_size,
                        second.st_mtime_ns, second.st_ctime_ns)
                    or (link.st_dev, link.st_ino) != (second.st_dev, second.st_ino)):
                raise ValueError("portable review changed during read")
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    payloads: dict[str, bytes] = {}
    with ZipFile(io.BytesIO(blob)) as archive:
        entries = archive.infolist()
        if (len(entries) != len(_FILES)
                or {entry.filename for entry in entries} != _FILES):
            raise ValueError("unexpected ZIP entries")
        if any((entry.is_dir() or entry.compress_type != ZIP_DEFLATED
                or entry.flag_bits & 1 or entry.file_size > _MAX_FILE
                or entry.file_size < 1 or entry.compress_size > _MAX_ARCHIVE
                or ((entry.external_attr >> 16) & 0o777) != 0o600)
               for entry in entries):
            raise ValueError("unsafe ZIP entry")
        if sum(entry.file_size for entry in entries) > _MAX_ARCHIVE:
            raise ValueError("oversized portable review")
        for entry in entries:
            with archive.open(entry) as stream:
                data = stream.read(_MAX_FILE + 1)
                if len(data) != entry.file_size or stream.read(1):
                    raise ValueError("changed portable member size")
                payloads[entry.filename] = data
    manifest = _decode_json(payloads["manifest.json"])
    summary = _decode_json(payloads["review.json"])
    _validate_summary(summary)
    if (manifest.get("schema") != _SCHEMA
            or type(manifest.get("passed")) is not bool
            or manifest["passed"] is not summary["passed"]
            or type(manifest.get("archives_checked")) is not int
            or manifest["archives_checked"] != summary["archives_checked"]
            or type(manifest.get("pairs_checked")) is not int
            or manifest["pairs_checked"] != summary["pairs_checked"]
            or any(manifest.get(field) is not False
                   for field in ("authorization_granted", "external_targets_contacted",
                                 "deployment"))
            or manifest.get("synthetic_localhost_only") is not True):
        raise ValueError("contradictory portable manifest")
    hashes = manifest.get("files")
    if (not isinstance(hashes, dict) or set(hashes) != _FILES - {"manifest.json"}):
        raise ValueError("invalid file digest inventory")
    for name, recorded in hashes.items():
        actual = hashlib.sha256(payloads[name]).hexdigest()
        if (type(recorded) is not str or len(recorded) != 64
                or not hmac.compare_digest(actual, recorded)):
            raise ValueError("modified portable export")
    return {
        "schema": _SCHEMA,
        "transport_integrity": True,
        "original_source_authenticated": False,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
        "synthetic_localhost_only": True,
        "review_status": "PASS" if summary["passed"] else "HOLD",
        "archives_checked": summary["archives_checked"],
        "pairs_checked": summary["pairs_checked"],
    }
