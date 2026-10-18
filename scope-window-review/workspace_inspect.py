"""Inspect a private LightUp human-review workspace without authorizing anything.

Integrity of unsigned files is not provenance, current consent or verification
that grant/STOP state is current. No scanner, network or database access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = "lightup.scope_window_workspace.v1"
ARTIFACTS = {
    "original-private-casebook.json": 512 * 1024,
    "human-review-board.html": 1024 * 1024,
    "human-review-agenda.json": 3 * 1024 * 1024,
    "human-review-calendar.ics": 1024 * 1024,
}
MANIFEST = "human-review-manifest.json"
FLAGS = (
    "source_authenticated", "client_consent_verified",
    "operator_consent_verified", "authorization_granted",
    "execution_allowed", "release_approved",
)


class WorkspaceHold(ValueError):
    pass


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise WorkspaceHold("duplicate manifest field")
        obj[key] = value
    return obj


def reject_nonfinite(_: str) -> None:
    raise WorkspaceHold("non-finite manifest value")


def _private_dir(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise WorkspaceHold("original workspace must be owned, regular and 0700")
    return fd


def _private_file(directory_fd: int, name: str, max_bytes: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > max_bytes):
            raise WorkspaceHold("unsafe or oversized private workspace artifact")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) != info.st_size or len(raw) > max_bytes:
            raise WorkspaceHold("workspace artifact size changed during read")
        return raw
    finally:
        os.close(fd)


def inspect(path: Path) -> dict:
    directory_fd = _private_dir(path)
    try:
        present = set(os.listdir(directory_fd))
        if present != set(ARTIFACTS) | {MANIFEST}:
            raise WorkspaceHold("missing or unexpected private workspace artifacts")
        payload = _private_file(directory_fd, MANIFEST, 16384)
        try:
            info = json.loads(payload.decode("utf-8"),
                              object_pairs_hook=unique_keys,
                              parse_constant=reject_nonfinite)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise WorkspaceHold("invalid workspace manifest") from exc
        if (type(info) is not dict or info.get("schema") != SCHEMA
                or info.get("source") != "unsigned_original_casebook_retrospective"
                or info.get("status") not in ("REVIEW_ONLY", "HOLD")
                or any(info.get(k) is not False for k in FLAGS)):
            raise WorkspaceHold("workspace source, status or authority flags invalid")
        files = info.get("files")
        if type(files) is not dict or set(files) != set(ARTIFACTS):
            raise WorkspaceHold("declared artifact collection incomplete")
        source_sha = info.get("original_source_sha256")
        if type(source_sha) is not str or not re.fullmatch(r"[0-9a-f]{64}", source_sha):
            raise WorkspaceHold("original source digest absent")
        for name, limit in ARTIFACTS.items():
            declared = files[name]
            if (type(declared) is not dict
                    or set(declared) != {"bytes", "sha256"}
                    or type(declared.get("bytes")) is not int
                    or not 1 <= declared["bytes"] <= limit
                    or type(declared.get("sha256")) is not str
                    or not re.fullmatch(r"[0-9a-f]{64}", declared["sha256"])):
                raise WorkspaceHold("invalid private artifact declaration")
            raw = _private_file(directory_fd, name, limit)
            digest = hashlib.sha256(raw).hexdigest()
            if len(raw) != declared["bytes"] or digest != declared["sha256"]:
                raise WorkspaceHold("private workspace artifact changed")
            if name == "original-private-casebook.json" and digest != source_sha:
                raise WorkspaceHold("original source sidecar not bound to manifest")
        totals = info.get("declared_counts")
        if (type(totals) is not dict or
                any(type(totals.get(key)) is not int or totals[key] < 0
                    for key in ("items", "hold", "review_only")) or
                totals["items"] != totals["hold"] + totals["review_only"]):
            raise WorkspaceHold("declared workspace human review counts contradictory")
        return {
            "status": info["status"], "files": len(ARTIFACTS),
            "human_review_items": totals["items"], "human_hold": totals["hold"],
            "source_attestation": False, "authorization_granted": False,
            "execution_allowed": False,
        }
    finally:
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = inspect(args.workspace)
        print(f"{report['status']}: {report['files']} intact PRIVATE workspace artifacts; "
              f"{report['human_review_items']} human items; "
              f"{report['human_hold']} HOLD; unsigned source; NO AUTHORIZATION.")
        return 3 if report["status"] == "HOLD" else 2
    except (WorkspaceHold, OSError, ValueError) as exc:
        print(f"HOLD: private workspace not admitted ({type(exc).__name__}); "
              "no permission or execution inferred.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
