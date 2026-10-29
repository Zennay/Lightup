"""Read-only, offline verification of a persisted three-capability loopback score run.

No fixture, worker, target, provider, writable SQLite connection, or grant is opened.
Output is bounded to fixed labels, counts and SHA-256 digests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

from .lab_score_suite import (
    SCHEMA as SCORE_SCHEMA,
    _EXPECTED_FINDINGS,
    _PUBLIC_CHECKS,
    _public_identifier,
    _summarize_result,
)

INSPECT_SCHEMA = "lightup.lab-score-inspect.v1"
_SCENARIOS = {
    "service_inventory": "lab-service-inventory-loopback",
    "tls_baseline": "lab-tls-baseline-self-signed-loopback",
    "http_baseline": "lab-web-baseline-security-headers-loopback",
}
_FILES = {"report.json", *(name + ".sqlite3" for name in _EXPECTED_FINDINGS)}
_TEMP_ROOTS = {"/tmp", "/var/tmp", "/dev/shm"}
_MAX_REPORT = 1024 * 1024
_MAX_DB = 64 * 1024 * 1024


def _no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _json_object(raw: bytes, *, canonical: str) -> dict[str, Any]:
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_no_duplicates,
        parse_constant=_invalid_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    if canonical == "report":
        encoded = (json.dumps(value, sort_keys=True, indent=2,
                              allow_nan=False) + "\n").encode("utf-8")
    else:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    if encoded != raw:
        raise ValueError("non-canonical JSON bytes")
    return value


def _private_dir_fd(raw: str | Path) -> int:
    path = Path(raw).expanduser()
    if ".." in path.parts:
        raise ValueError("path traversal rejected")
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.parts[1:]:
        raise PermissionError("filesystem root is not a private score run")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            current = current / part
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            sticky_root = (
                str(current) in _TEMP_ROOTS
                and info.st_uid == 0 and bool(mode & stat.S_ISVTX)
            )
            if mode & 0o022 and not sticky_root:
                raise PermissionError("untrusted writable directory ancestor")
        info = os.fstat(fd)
        if (info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise PermissionError("score directory must be owner-private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _artifact_fd(directory: int, name: str, maximum: int) -> int:
    fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
    )
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_size < 1 or info.st_size > maximum
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise PermissionError("unsafe private artifact")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _verify_database(fd: int, name: str, summary: dict[str, Any]) -> dict[str, Any]:
    # Reopen the pinned descriptor as read-only/immutable. This never initializes
    # StateStore's schema or creates writable SQLite journal/SHM sidecars.
    before = os.fstat(fd)
    database_uri = f"file:/proc/self/fd/{fd}?mode=ro&immutable=1"
    with closing(sqlite3.connect(database_uri, uri=True, timeout=2)) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        integrity = con.execute("PRAGMA integrity_check(1)").fetchone()
        if not integrity or integrity[0] != "ok":
            raise ValueError("SQLite integrity failed")
        if con.execute("SELECT COUNT(*) FROM lab_evaluations").fetchone()[0] != 1:
            raise ValueError("unexpected evaluation count")
        record_id = summary.get("evaluation_record_id")
        if _public_identifier(record_id) is None:
            raise ValueError("invalid evaluation identifier")
        row = con.execute(
            "SELECT record_id,scenario_id,run_id,record_json,record_sha256 "
            "FROM lab_evaluations WHERE record_id=?", (record_id,)
        ).fetchone()
        if row is None:
            raise ValueError("missing persisted evaluation")
        raw = row["record_json"].encode("utf-8")
        if len(raw) > _MAX_REPORT:
            raise ValueError("oversized evaluation")
        digest = hashlib.sha256(raw).hexdigest()
        if digest != row["record_sha256"]:
            raise ValueError("evaluation checksum mismatch")
        record = _json_object(raw, canonical="compact")
        if (record.get("record_id") != row["record_id"]
                or record.get("scenario_id") != row["scenario_id"]
                or record.get("run_id") != row["run_id"]
                or record.get("scenario_id") != _SCENARIOS[name]):
            raise ValueError("persisted evaluation identity mismatch")
        evidence_ids = record.get("evidence_ids")
        if not isinstance(evidence_ids, list):
            raise ValueError("invalid evidence references")
        if con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] != len(evidence_ids):
            raise ValueError("unexpected persisted evidence rows")
        for evidence_id in evidence_ids:
            if _public_identifier(evidence_id) is None:
                raise ValueError("unsafe evidence identifier")
            evidence = con.execute(
                "SELECT run_id,sha256,metadata_json FROM evidence WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            if (evidence is None or evidence["run_id"] != row["run_id"]
                    or not isinstance(evidence["sha256"], str)
                    or len(evidence["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in evidence["sha256"])):
                raise ValueError("broken persisted evidence lineage")
            metadata = evidence["metadata_json"].encode("utf-8")
            if len(metadata) > 65536:
                raise ValueError("oversized evidence metadata")
            _json_object(metadata, canonical="compact")
        recomputed = _summarize_result(
            name,
            name + ".sqlite3",
            {
                "passed": True,
                "scenario_id": record["scenario_id"],
                "run_id": record["run_id"],
                "evaluation_record_id": record["record_id"],
                "checks": summary.get("checks"),
                "evaluation": record,
            },
        )
        if (set(summary.get("checks", {})) != _PUBLIC_CHECKS[name]
                or not recomputed["passed"]
                or json.dumps(summary, sort_keys=True, allow_nan=False)
                != json.dumps(recomputed, sort_keys=True, allow_nan=False)):
            raise ValueError("stored evaluation differs from score report")
        result = {"record_sha256": digest, "evidence_count": len(evidence_ids)}
    # immutable=1 tells SQLite not to acquire a write lock. It does not prevent
    # another process from changing this file; catch that without making writes.
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns
    ):
        raise ValueError("persisted evidence changed while being inspected")
    return result


def inspect_score_run(directory: str | Path) -> dict[str, Any]:
    fd = _private_dir_fd(directory)
    try:
        before = os.fstat(fd)
        if set(os.listdir(fd)) != _FILES:
            raise ValueError("unexpected score artifact set")
        report_fd = _artifact_fd(fd, "report.json", _MAX_REPORT)
        with os.fdopen(report_fd, "rb") as stream:
            report = _json_object(stream.read(_MAX_REPORT + 1), canonical="report")
        if (set(report) != {"schema", "passed", "failure_reasons",
                            "scorers", "safety", "artifact_directory"}
                or report["schema"] != SCORE_SCHEMA
                or report["passed"] is not True
                or report["failure_reasons"] != []
                or report["artifact_directory"] != "."
                or not isinstance(report["scorers"], dict)
                or set(report["scorers"]) != set(_EXPECTED_FINDINGS)
                or report["safety"] != {
                    "fixture_scope": "fixed 127.0.0.1 loopback fixtures only",
                    "external_target_interaction": False,
                    "authorization_grants_issued": False,
                    "worker_dispatch": False,
                    "remediation_or_retest": False,
                    "deployment": False,
                }):
            raise ValueError("score report is not an accepted calibration")
        verified: dict[str, dict[str, Any]] = {}
        identities: dict[str, set[str]] = {
            key: set() for key in ("scenario_id", "run_id", "evaluation_record_id")
        }
        for name in _EXPECTED_FINDINGS:
            summary = report["scorers"][name]
            if not isinstance(summary, dict) or summary.get("passed") is not True:
                raise ValueError("missing successful capability")
            for key, seen in identities.items():
                value = summary.get(key)
                if _public_identifier(value) is None or value in seen:
                    raise ValueError("aliased or invalid capability identity")
                seen.add(value)
            database_fd = _artifact_fd(fd, name + ".sqlite3", _MAX_DB)
            try:
                verified[name] = _verify_database(database_fd, name, summary)
            finally:
                os.close(database_fd)
        after = os.fstat(fd)
        if (set(os.listdir(fd)) != _FILES
                or (before.st_dev, before.st_ino, before.st_mtime_ns,
                    before.st_ctime_ns) !=
                   (after.st_dev, after.st_ino, after.st_mtime_ns,
                    after.st_ctime_ns)):
            raise ValueError("score directory changed during inspection")
        return {
            "schema": INSPECT_SCHEMA,
            "passed": True,
            "capabilities": verified,
            "authorization_granted": False,
            "external_targets_contacted": False,
            "deployment": False,
        }
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-score-inspect",
        description="Verify one persisted private loopback score run without executing it.",
    )
    parser.add_argument("--output-dir", required=True, help="existing private score directory")
    args = parser.parse_args(argv)
    try:
        result = inspect_score_run(args.output_dir)
    except Exception as exc:
        print(json.dumps({
            "schema": INSPECT_SCHEMA,
            "passed": False,
            "error_type": type(exc).__name__,
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
