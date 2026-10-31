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
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo, BadZipFile

from .lab_score_inspect import _artifact_fd, _private_dir_fd
from .lab_score_portable_html_safety import admit_inert_html
from .lab_score_portable_dashboard import render_portable_dashboard
from .lab_score_portable_history import render_portable_history
from .lab_score_portable_legacy_triage import legacy_triage
from .lab_score_portable_queue import build_portable_queue
from .lab_score_portable_focus import (
    InvalidPortableSelection, build_portable_focus, build_portable_pair,
)
from .lab_score_portable_text_safety import admit_text_exports
from .lab_score_compare import _SCORE_FIELDS
from .lab_score_suite import _EXPECTED_FINDINGS

_SCHEMA = "lightup.lab-score-portable-human-review.v3"
_LEGACY_SCHEMA = "lightup.lab-score-portable-human-review.v1"
_PREVIOUS_SCHEMA = "lightup.lab-score-portable-human-review.v2"
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
    # Admission is a source-free schema, not just a handful of flags. Refuse
    # hidden original source paths, keys, identities or misleading sidecars.
    if set(summary) != {
        "schema", "passed", "archives_checked", "pairs_checked", "pairs",
        "archive_review_queue", "capability_hotspots",
        "authorization_granted", "external_targets_contacted", "deployment",
    }:
        raise ValueError("unexpected private review summary metadata")
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
        if set(item) != {"previous_index", "current_index", "passed",
                            "independent_evaluations", "score_stable"}:
            raise ValueError("unexpected anonymous pair metadata")
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
    # Unsigned metadata cannot turn attacker-controlled values into review priorities
    # or Markdown/CSV active payloads. Re-derive the archive HOLD queue from pairs.
    expected: dict[int, dict[str, int]] = {
        idx: {"pairs": 0, "reuse": 0, "drift": 0}
        for idx in range(1, n + 1)
    }
    for pair in summary["pairs"]:
        if pair["passed"]:
            continue
        for idx in (pair["previous_index"], pair["current_index"]):
            expected[idx]["pairs"] += 1
            expected[idx]["reuse"] += not pair["independent_evaluations"]
            expected[idx]["drift"] += not pair["score_stable"]
    queue = [
        {"index": idx, "hold_pairs": counts["pairs"],
         "reused_evidence_pairs": counts["reuse"],
         "score_drift_pairs": counts["drift"]}
        for idx, counts in sorted(
            expected.items(), key=lambda p: (-p[1]["pairs"], p[0]))
        if counts["pairs"]
    ]
    if summary.get("archive_review_queue") != queue:
        raise ValueError("contradictory anonymous archive priorities")
    hotspots = summary.get("capability_hotspots")
    if not isinstance(hotspots, list) or len(hotspots) > len(_EXPECTED_FINDINGS):
        raise ValueError("invalid scorer hotspots")
    used = set()
    for item in hotspots:
        if not isinstance(item, dict):
            raise ValueError("invalid scorer hotspot")
        if set(item) != {"capability", "affected_pairs", "metrics"}:
            raise ValueError("unexpected scorer hotspot metadata")
        capability = item.get("capability")
        metrics = item.get("metrics")
        affected = item.get("affected_pairs")
        if (type(capability) is not str or capability not in _EXPECTED_FINDINGS
                or capability in used or type(affected) is not int
                or not 1 <= affected <= sum(not p["passed"] for p in summary["pairs"])
                or not isinstance(metrics, list) or not metrics
                or metrics != sorted(set(metrics))
                or any(type(metric) is not str or metric not in _SCORE_FIELDS
                       for metric in metrics)):
            raise ValueError("untrusted scorer label or hotspot")
        used.add(capability)
    if any(summary.get(field) is not False
           for field in ("authorization_granted", "external_targets_contacted",
                         "deployment")):
        raise ValueError("unsafe portable review authority fields")


def _validated_portable_review(path: str | Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Admit a complete immutable ZIP snapshot once, without unpacking."""
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
    # Python's ZIP reader tolerates arbitrary bytes before or after the
    # central directory. Such bytes are NOT listed in manifest.json and may
    # carry unreviewed material while the old checker said TRANSPORT VERIFIED.
    # Require the exact bounded, deterministic first-party ZIP encoding,
    # including header, timestamps, file order, metadata and trailer.
    canonical = io.BytesIO()
    with ZipFile(canonical, mode="w", compression=ZIP_DEFLATED) as writer:
        for name in sorted(payloads):
            member = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            member.compress_type = ZIP_DEFLATED
            member.external_attr = 0o600 << 16
            writer.writestr(member, payloads[name])
    if canonical.getvalue() != blob:
        raise ValueError("non-canonical portable ZIP bytes")

    manifest = _decode_json(payloads["manifest.json"])
    summary = _decode_json(payloads["review.json"])
    _validate_summary(summary)
    if payloads["review.json"] != (
        json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8"):
        raise ValueError("non-canonical anonymous JSON review")
    if set(manifest) != {
        "schema", "synthetic_localhost_only", "authorization_granted",
        "external_targets_contacted", "deployment", "passed",
        "archives_checked", "pairs_checked", "files",
    }:
        raise ValueError("unexpected portable manifest metadata")
    if (manifest.get("schema") not in (_SCHEMA, _PREVIOUS_SCHEMA, _LEGACY_SCHEMA)
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
    # v3 binds both human-facing HTML documents to the same admitted
    # anonymous pair flags, rather than trusting forged unsigned digests.
    # Old v1/v2 source-free handoffs remain inspectable but fail closed to
    # global HOLD, since private original chronology cannot be authenticated.
    is_v3 = manifest["schema"] == _SCHEMA
    has_dashboard_binding = manifest["schema"] in (_SCHEMA, _PREVIOUS_SCHEMA)
    if has_dashboard_binding and payloads["index.html"] != render_portable_dashboard(summary).encode("utf-8"):
        raise ValueError("offline HUMAN dashboard does not match verified summary")
    if is_v3 and payloads["history.html"] != render_portable_history(summary).encode("utf-8"):
        raise ValueError("offline HUMAN history does not match verified summary")
    result = {
        "schema": manifest["schema"],
        "dashboard_content_validated": has_dashboard_binding,
        "history_content_validated": is_v3,
        "transport_integrity": True,
        # Digest exact descriptor-pinned immutable source-free ZIP snapshot,
        # never private original evidence IDs, paths or evidence SHA.
        "portable_transport_sha256": hashlib.sha256(blob).hexdigest(),
        "original_source_authenticated": False,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
        "synthetic_localhost_only": True,
        # v1/v2 can be opened but cannot certify all visible human review.
        # Downgrade cannot promote a forged headline into PASS.
        "review_status": "PASS" if (summary["passed"] and is_v3) else "HOLD",
        "archives_checked": summary["archives_checked"],
        "pairs_checked": summary["pairs_checked"],
        "legacy_read_only_triage": "" if is_v3 else legacy_triage(summary),
    }
    # Unsigned transport digests are attacker-recomputable. Independently
    # enforce inert, local-only HTML for the files a HUMAN will open.
    admit_inert_html(payloads["index.html"])
    admit_inert_html(payloads["history.html"])
    admit_text_exports(summary, payloads, schema=manifest['schema'])
    return result, payloads


def verify_portable_review(
    path: str | Path, *, focus_archive_index: int | None = None,
    focus_pair: tuple[int, int] | None = None,
    review_queue: bool = False
) -> dict[str, Any]:
    """No-network, no-write ZIP integrity and optional original-pair focus."""
    result, files = _validated_portable_review(path)
    if sum((focus_archive_index is not None, focus_pair is not None, review_queue)) > 1:
        raise ValueError("choose only one portable focus/queue")
    if review_queue:
        # Full canonical ZIP admission already completed before any projection.
        result["review_queue"] = build_portable_queue(_decode_json(files["review.json"]))
    if focus_pair is not None or focus_archive_index is not None:
        try:
            if focus_pair is not None:
                result["focused_pair"] = build_portable_pair(
                    _decode_json(files["review.json"]), *focus_pair)
            else:
                result["focused_archive"] = build_portable_focus(
                    _decode_json(files["review.json"]), focus_archive_index)
        except InvalidPortableSelection:
            # An invalid operator ordinal is NOT corrupted ZIP transport.
            # Preserve verified immutable transport identity while failing
            # selection closed, with no local PASS or auth promoted.
            result["selection_valid"] = False
            result["review_status"] = "HOLD"
        else:
            result["selection_valid"] = True
    return result
