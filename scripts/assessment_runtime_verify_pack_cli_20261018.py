"""Read an existing private lab review ZIP without models, network or scans.

This checks unsigned content fingerprints and source formatting only.
Exit 2 means locally INTACT but never approved; exit 3 means HOLD.
"""
from __future__ import annotations
from hashlib import sha256
from io import BytesIO
import json
import os
import stat
import sys
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZIP_DEFLATED

from assessment_runtime_compare_cli_1513 import _dict_no_duplicates, _reject_nonfinite
from assessment_runtime_review_handoff_cli_20261018 import (
    LANDING_SHA256, REVIEW_DESK_SHA256, REVIEW_DESK_SOURCE_COMMIT,
)

ARCHIVE_LIMIT = 1_500_000
CAPS = {
    "index.html": 16_384,
    "START-HERE.txt": 4_096,
    "review.html": 1_048_576,
    "review-desk.html": 65_536,
    "review-desk.json": 262_144,
    "human-worklist.csv": 131_072,
    "manifest.json": 8_192,
}
DENY_KEYS = (
    "authorized", "consent_verified", "dispatch_allowed",
    "release_allowed", "source_authenticated", "approval_granted",
)
DIGEST_MEMBERS = {
    "review_desk_sha256": "review-desk.html",
    "landing_sha256": "index.html",
    "printable_review_sha256": "review.html",
    "review_desk_json_sha256": "review-desk.json",
    "human_worklist_sha256": "human-worklist.csv",
}
MANIFEST_KEYS = frozenset((
    "format", "comparison_type", "source_fingerprint_kind",
    "baseline_sha256", "candidate_sha256", "status",
    "review_desk_source_commit", *DENY_KEYS, *DIGEST_MEMBERS,
))


def _json(raw: bytes):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_dict_no_duplicates,
                      parse_constant=_reject_nonfinite)


def _hex(value):
    return type(value) is str and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value
    )


def inspect(path):
    fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("not a regular file")
        raw = source.read(ARCHIVE_LIMIT + 1)
    if not raw or len(raw) > ARCHIVE_LIMIT:
        raise ValueError("archive over limit")
    with ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) != len(CAPS) or set(member.filename for member in entries) != set(CAPS):
            raise ValueError("unexpected archive members")
        content = {}
        for member in entries:
            if (member.is_dir() or member.flag_bits & 1
                    or member.compress_type != ZIP_DEFLATED
                    or not 0 < member.file_size <= CAPS[member.filename]):
                raise ValueError("unsupported archive member")
            data = archive.read(member)
            if len(data) != member.file_size:
                raise ValueError("member size mismatch")
            content[member.filename] = data
    manifest = _json(content["manifest.json"])
    if type(manifest) is not dict or set(manifest) != MANIFEST_KEYS:
        raise ValueError("unexpected manifest")
    if (manifest["format"] != "lightup.private_lab_review_pack.v1"
            or manifest["status"] not in ("HOLD", "REVIEW_ONLY")
            or manifest["comparison_type"] not in ("cohort", "single_case")
            or manifest["source_fingerprint_kind"] not in (
                "original_input_file_bytes", "canonical_case_set")
            or manifest["review_desk_source_commit"] != REVIEW_DESK_SOURCE_COMMIT):
        raise ValueError("unsupported source identity")
    if any(manifest[key] is not False for key in DENY_KEYS):
        raise ValueError("authority flag not false")
    if not _hex(manifest["baseline_sha256"]) or not _hex(manifest["candidate_sha256"]):
        raise ValueError("invalid source fingerprints")
    for key, name in DIGEST_MEMBERS.items():
        if not _hex(manifest[key]) or manifest[key] != sha256(content[name]).hexdigest():
            raise ValueError("invalid member digest")
    if (manifest["review_desk_sha256"] != REVIEW_DESK_SHA256
            or manifest["landing_sha256"] != LANDING_SHA256):
        raise ValueError("unrecognized original offline app")
    comparison = _json(content["review-desk.json"])
    if type(comparison) is not dict or comparison.get("status") != manifest["status"]:
        raise ValueError("mismatched result")
    if any(comparison.get(key) is not False for key in DENY_KEYS[:4]):
        raise ValueError("source result claims permission")
    return manifest["status"]


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("PRIVATE_LAB_PACK_HOLD")
        return 3
    try:
        status = inspect(args[0])
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError, RuntimeError, EOFError,
            NotImplementedError, BadZipFile, LargeZipFile):
        print("PRIVATE_LAB_PACK_HOLD")
        return 3
    print("PRIVATE_LAB_PACK_INTACT — " + status + "; UNSIGNED; NOT AUTHORIZED")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
