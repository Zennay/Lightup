#!/usr/bin/env python3
"""Reopen one owner-private LAB_ONLY launch handoff without executing anything.

Private source integrity (unsigned) and original domain validation only.
This is a product handoff reader, not a QA harness or authorization gate.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

from build import Hold, admit, admit_studio, _FLAGS, _SCHEMA

_BOUNDS = {
    "targets.txt": 16_384,
    "private-launchpad.html": 131_072,
    "START-HERE.txt": 16_384,
    "private-plan.json": 32_768,
    "studio-catalog.json": 262_144,
}
_BASE = frozenset(("targets.txt", "private-launchpad.html",
                   "START-HERE.txt", "private-plan.json"))
_FIELDS = frozenset((
    "schema", "status", "source_count", "manifest_sha256",
    "source_identity_authenticated", "preview_only", "planning_not_permission",
    "studio_design_bound", "studio_catalog_sha256", "studio_scenario_id",
    "declared_ground_truth_used", "artifact_sha256", *_FLAGS,
))


def _read_private(dirfd: int, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=dirfd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.getuid()
                or not 0 < before.st_size <= _BOUNDS[name]):
            raise Hold("not an owner-private ordinary packet file")
        data = stream.read(_BOUNDS[name] + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size
                or before.st_size != after.st_size
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise Hold("private packet changed during inspection")
    return data


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Hold("duplicate packet metadata key")
        result[key] = value
    return result


def reopen(directory: str) -> tuple[int, bool]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    dirfd = os.open(directory, flags)
    try:
        directory_info = os.fstat(dirfd)
        if (not stat.S_ISDIR(directory_info.st_mode)
                or stat.S_IMODE(directory_info.st_mode) != 0o700
                or directory_info.st_uid != os.getuid()):
            raise Hold("not an owner-private packet directory")

        names = set(os.listdir(dirfd))
        if not names.issubset(_BASE | {"studio-catalog.json"}) or not _BASE.issubset(names):
            raise Hold("missing or unexpected private packet files")
        artifacts = {name: _read_private(dirfd, name) for name in names}
        doc = json.loads(
            artifacts["private-plan.json"].decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(Hold("nonfinite packet metadata")),
        )
        if (type(doc) is not dict or set(doc) != _FIELDS or doc["schema"] != _SCHEMA
                or doc["status"] != "DRAFT_HOLD"
                or doc["preview_only"] is not True
                or doc["planning_not_permission"] is not True
                or doc["source_identity_authenticated"] is not False
                or doc["declared_ground_truth_used"] is not False
                or type(doc["studio_design_bound"]) is not bool
                or any(doc[flag] is not False for flag in _FLAGS)):
            raise Hold("packet metadata does not remain a private, non-authorizing draft")
        studio = doc["studio_design_bound"]
        if ("studio-catalog.json" in names) != studio:
            raise Hold("Studio source membership changed")
        expected_names = names - {"private-plan.json"}
        sha_map = doc["artifact_sha256"]
        if type(sha_map) is not dict or set(sha_map) != expected_names:
            raise Hold("incomplete source fingerprint coverage")
        if any(sha_map[name] != sha256(artifacts[name]).hexdigest()
               for name in expected_names):
            raise Hold("original private packet bytes changed")
        manifest = artifacts["targets.txt"]
        if sha256(manifest).hexdigest() != doc["manifest_sha256"]:
            raise Hold("original lab manifest revision mismatch")
        decoded = manifest.decode("utf-8")
        lines = decoded.splitlines()
        if not lines or decoded != "\n".join(lines) + "\n":
            raise Hold("noncanonical private lab manifest")
        selected = admit(lines)
        if (type(doc["source_count"]) is not int
                or doc["source_count"] != len(selected)):
            raise Hold("private endpoint count changed")
        if studio:
            source = artifacts["studio-catalog.json"]
            if sha256(source).hexdigest() != doc["studio_catalog_sha256"]:
                raise Hold("Studio catalog fingerprint changed")
            if type(doc["studio_scenario_id"]) is not str:
                raise Hold("missing original Studio selection")
            selected_studio, reread = admit_studio(
                str(Path(directory) / "studio-catalog.json"),
                doc["studio_scenario_id"], selected,
            )
            if (source != reread or selected_studio["catalog_sha256"] !=
                    doc["studio_catalog_sha256"]):
                raise Hold("Studio source or declared lab IPs changed")
        elif (doc["studio_catalog_sha256"] is not None
              or doc["studio_scenario_id"] is not None):
            raise Hold("contradictory absent Studio metadata")
        # Hashes provide unsigned change-detection only, never independent
        # producer authentication or current consent/release authority.
        return len(selected), studio
    finally:
        os.close(dirfd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read private source-bound lab packet; never execute a lab")
    parser.add_argument("--packet", required=True, help="existing owner-private launch packet directory")
    args = parser.parse_args(argv)
    try:
        n, studio = reopen(args.packet)
        print("PRIVATE_LAB_PACKET_REOPENED — REVIEW_ONLY DRAFT/HOLD; "
              f"endpoints={n} studio_draft={'present' if studio else 'absent'}; "
              "UNSIGNED SOURCE BYTES ONLY, NO AUTHORITY")
        return 2
    except (Hold, OSError, KeyError, ValueError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        print("PRIVATE_LAB_PACKET_HOLD — incomplete, changed or unbound private source",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
