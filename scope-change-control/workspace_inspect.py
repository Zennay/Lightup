"""Read-only offline inspection of a *previously created* LightUp private workspace.

Uses only locally provided bounded regular files and unsigned SHA-256 binding.
Refuses incomplete/tampered packages; never treats a valid private source as
authorization, authentication, STOP clearance, remediation or runtime evidence.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys

from lightup.auth_casebook import AUTHORITY
from refresh import ReviewHold, _admit, _diff, _duplicate_pairs
from workspace import FILES, AUTHORITY as WORKSPACE_AUTHORITY

MAX_SIZE = 512 * 1024


def read_private_file(fd: int, name: str) -> bytes:
    try:
        item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(item)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or not 1 <= info.st_size <= MAX_SIZE):
                raise ReviewHold("private workspace file metadata invalid")
            with os.fdopen(item, "rb", closefd=False) as file:
                data = file.read(MAX_SIZE + 1)
            if len(data) > MAX_SIZE:
                raise ReviewHold("private workspace file exceeds bound")
            return data
        finally:
            os.close(item)
    except OSError:
        raise ReviewHold("private workspace file missing or inaccessible") from None


def parsed_json(data: bytes) -> dict:
    try:
        document = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ReviewHold("nonfinite private source")),
        )
        if type(document) is not dict:
            raise ReviewHold("invalid private source structure")
        return document
    except (UnicodeError, ValueError):
        raise ReviewHold("invalid private source JSON") from None


def inspect_workspace(path: str) -> dict:
    work_fd = None
    try:
        work_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(work_fd)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077):
            raise ReviewHold("private workspace directory not owner-only")
        original = {name: read_private_file(work_fd, name) for name in FILES}
    except OSError:
        raise ReviewHold("private workspace unavailable") from None
    finally:
        if work_fd is not None:
            os.close(work_fd)
    manifest = parsed_json(original["manifest.json"])
    if (manifest.get("schema") != "lightup.casebook_change_private_workspace.v1"
            or manifest.get("disposition") != "HOLD_HUMAN_REVIEW"
            or manifest.get("source_snapshots_atomic_together") is not False
            or manifest.get("source_hashes_unsigned") is not True
            or any(manifest.get(k) is not False for k in WORKSPACE_AUTHORITY)):
        raise ReviewHold("private workspace manifest authority fields invalid")
    entries = manifest.get("files")
    if type(entries) is not dict or set(entries) != set(FILES) - {"manifest.json"}:
        raise ReviewHold("private workspace manifest membership invalid")
    for name in FILES:
        if name == "manifest.json":
            continue
        entry = entries.get(name)
        if (type(entry) is not dict
                or entry.get("bytes") != len(original[name])
                or entry.get("sha256_unsigned") != sha256(original[name]).hexdigest()):
            raise ReviewHold("private workspace file does not match unsigned manifest")
    old = parsed_json(original["OLDER-ORIGINAL.json"])
    new = parsed_json(original["NEWER-ORIGINAL.json"])
    # Exact native original source shape and source lineage, no claim about live rights.
    _admit(old)
    _admit(new)
    projected = _diff(old, new, sha256(original["OLDER-ORIGINAL.json"]).hexdigest())
    projected["source_sha256_unsigned"][1] = sha256(original["NEWER-ORIGINAL.json"]).hexdigest()
    review = parsed_json(original["PRIVATE-review.json"])
    if review != projected:
        raise ReviewHold("private review differs from exact original source records")
    anonymous = parsed_json(original["aggregate.json"])
    required = {
        "schema": "lightup.casebook_change_aggregate.v1",
        "disposition": "HOLD_HUMAN_REVIEW",
        "snapshot_count": 2,
        **WORKSPACE_AUTHORITY,
        **projected["aggregate_without_original_ids"],
    }
    if anonymous != required:
        raise ReviewHold("anonymous aggregate differs from exact source changes")
    if (not original["standalone.html"].startswith(b"<!doctype html>")
            or b"script-src 'sha256-" not in original["standalone.html"]
            or b"connect-src 'none'" not in original["standalone.html"]):
        raise ReviewHold("packaged offline viewer is not the expected CSP form")
    # This is a technical offline integrity disposition. No positive authority even
    # if the bytes are all consistent. Avoid printing tenant, IDs, raw paths/digests.
    return {
        "disposition": "HOLD_HUMAN_REVIEW",
        "workspace_file_count": len(FILES),
        "private_source_membership_consistent": True,
        "unsigned_file_integrity_consistent": True,
        "changed_original_record_count": len(projected["changes"]),
        "urgent_human_attention_count": projected["aggregate_without_original_ids"]["urgent_review_count"],
        "authentic_issuer_verified": False,
        "action_time_revocation_verified": False,
        **AUTHORITY,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect private LightUp Casebook workspace without granting any authority.")
    parser.add_argument("--workspace", required=True, help="existing private workspace directory")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(inspect_workspace(args.workspace), sort_keys=True))
        return 2
    except (ReviewHold, OSError, ValueError, TypeError, KeyError):
        print("HOLD: private workspace sources or manifest unavailable/inconsistent", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
