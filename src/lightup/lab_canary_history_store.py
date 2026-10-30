"""Offline source-free HUMAN history snapshots: private no-overwrite writer/reader.

Unsigned SHA256 manifests ensure local byte consistency only, never source
authenticity, permission, consent or reviewer identity.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat

from .lab_canary_handoff import _private_write, _strict_json
from .lab_canary_history import METRICS, SCORERS, render_private_canary_history_html

SCHEMA = "lightup.m1.synthetic-private-canary-history.v1"
MANIFEST = "lightup.m1.synthetic-private-history-snapshot-manifest.v1"
VERIFICATION = "lightup.m1.synthetic-private-history-snapshot-verification.v1"


def _validate_history(result: dict) -> dict:
    required = {
        "schema", "baseline_status", "candidate_status", "review_status",
        "input_integrity", "selection_valid", "metric_changes", "regressions",
        "synthetic_loopback_only", "source_authenticated", "consent_authenticated",
        "authorization_granted", "external_target_authorized", "deployment",
        "human_review_only",
    }
    if type(result) is not dict or set(result) != required or result["schema"] != SCHEMA:
        raise ValueError("invalid saved history schema")
    for key in ("source_authenticated", "consent_authenticated",
                "authorization_granted", "external_target_authorized", "deployment"):
        if result[key] is not False:
            raise ValueError("unsafe history authority flag")
    for key in ("input_integrity", "selection_valid",
                "synthetic_loopback_only", "human_review_only"):
        if result[key] is not True:
            raise ValueError("invalid or incomplete original history")
    states = (result["baseline_status"], result["candidate_status"],
              result["review_status"])
    if any(state not in ("PASS", "HOLD") for state in states):
        raise ValueError("invalid synthetic review state")
    changes = result["metric_changes"]
    regressions = result["regressions"]
    if (type(changes) is not list or type(regressions) is not list
            or len(changes) > len(SCORERS) * len(METRICS)):
        raise ValueError("unbounded metric history")
    allowed = {f"{scorer}_{suffix}": direction
               for scorer in SCORERS for suffix, direction in METRICS}
    seen = set()
    canonical_changes = []
    for row in changes:
        if type(row) is not dict or set(row) != {
            "metric", "previous", "current", "regression"
        }:
            raise ValueError("invalid metric row")
        metric = row["metric"]
        if type(metric) is not str or metric not in allowed or metric in seen:
            raise ValueError("unrecognized/duplicate metric")
        seen.add(metric)
        for key in ("previous", "current"):
            value = row[key]
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not 0 <= value <= 1_000_000):
                raise ValueError("invalid metric number")
            if metric.endswith("_findings") and type(value) is not int:
                raise ValueError("invalid integer findings")
            if not metric.endswith("_findings") and value > 1:
                raise ValueError("invalid metric fraction")
        if row["previous"] == row["current"]:
            raise ValueError("unchanged metric listed")
        unfavorable = allowed[metric]
        regressed = (row["current"] < row["previous"]
                     if unfavorable == "decrease" else
                     row["current"] > row["previous"])
        if row["regression"] is not regressed:
            raise ValueError("forged metric regression label")
        canonical_changes.append(row)
    order = list(allowed)
    if [row["metric"] for row in canonical_changes] != sorted(
        [row["metric"] for row in canonical_changes], key=order.index
    ):
        raise ValueError("history metric order changed")
    expected_regressions = [row for row in canonical_changes if row["regression"]]
    if result["baseline_status"] == "PASS" and result["candidate_status"] == "HOLD":
        expected_regressions.append({
            "metric": "synthetic_canary", "change": "PASS_TO_HOLD"
        })
    if states[:2] != ("PASS", "PASS") and canonical_changes:
        raise ValueError("unavailable metric history projected")
    if regressions != expected_regressions:
        raise ValueError("history regression summary inconsistent")
    expected_status = (
        "PASS" if states[:2] == ("PASS", "PASS") and not regressions else "HOLD"
    )
    if result["review_status"] != expected_status:
        raise ValueError("forged global HOLD/PASS")
    return result


def save_private_history_snapshot(destination: str, result: dict) -> Path:
    """New 0700 directory with only admitted JSON, scriptless HTML and digest."""
    _validate_history(result)
    raw = Path(destination).expanduser()
    if ".." in raw.parts or raw.name in ("", ".", ".."):
        raise ValueError("unsafe snapshot destination")
    root = raw.parent.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("snapshot parent unavailable")
    target = root / raw.name
    sources = {
        "history.json": (json.dumps(result, sort_keys=True, allow_nan=False,
                                   separators=(",", ":")) + "\n").encode(),
        "history.html": render_private_canary_history_html(result).encode(),
    }
    manifest = {
        "schema": MANIFEST, "signed": False, "source_authenticated": False,
        "files": {key: hashlib.sha256(value).hexdigest()
                  for key, value in sorted(sources.items())},
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode()
    os.mkdir(target, 0o700)
    try:
        for name, payload in sorted(sources.items()):
            _private_write(target, name, payload)
        _private_write(target, "manifest.json", manifest_bytes)
        folder = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    except BaseException:
        for name in ("history.json", "history.html", "manifest.json"):
            try:
                (target / name).unlink()
            except FileNotFoundError:
                pass
        target.rmdir()
        raise
    return target


def _read_private_history_snapshot(directory: str) -> tuple[dict, dict[str, bytes], tuple[int, int]]:
    """Read verified original files from pinned descriptors, without TOCTOU reread."""
    raw = Path(directory).expanduser()
    if ".." in raw.parts:
        raise ValueError("parent traversal in snapshot")
    fd = os.open(raw, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root = os.fstat(fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != os.getuid()
                or root.st_mode & 0o777 != 0o700):
            raise ValueError("not owner-private")
        names = {"history.json", "history.html", "manifest.json"}
        if set(os.listdir(fd)) != names:
            raise ValueError("unexpected private files")
        files = {}
        for name in sorted(names):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                metadata = os.fstat(child)
                if (not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != os.getuid()
                        or metadata.st_mode & 0o777 != 0o600
                        or not 0 < metadata.st_size <= 32_768):
                    raise ValueError("invalid private snapshot file")
                with os.fdopen(child, "rb", closefd=False) as stream:
                    data = stream.read(32_769)
                if len(data) != metadata.st_size:
                    raise ValueError("modified snapshot file")
                files[name] = data
            finally:
                os.close(child)
        manifest = _strict_json(files["manifest.json"])
        if (type(manifest) is not dict or set(manifest) != {
            "schema", "signed", "source_authenticated", "files"
        } or manifest["schema"] != MANIFEST or manifest["signed"] is not False
                or manifest["source_authenticated"] is not False
                or type(manifest["files"]) is not dict
                or set(manifest["files"]) != {"history.json", "history.html"}):
            raise ValueError("invalid source-free snapshot manifest")
        for name, digest in manifest["files"].items():
            if type(digest) is not str or hashlib.sha256(files[name]).hexdigest() != digest:
                raise ValueError("private snapshot digest mismatch")
        result = _validate_history(_strict_json(files["history.json"]))
        if files["history.html"] != render_private_canary_history_html(result).encode():
            raise ValueError("forged passive HTML even with rehashed manifest")
        receipt = {
            "schema": VERIFICATION, "transport_integrity": True,
            "review_status": result["review_status"],
            "synthetic_loopback_only": True, "source_authenticated": False,
            "consent_authenticated": False, "authorization_granted": False,
            "external_target_authorized": False, "deployment": False,
        }
        return receipt, files, (root.st_dev, root.st_ino)
    finally:
        os.close(fd)


def verify_private_history_snapshot(directory: str) -> dict:
    """Read-only owner-private validated metadata without original content."""
    return _read_private_history_snapshot(directory)[0]
