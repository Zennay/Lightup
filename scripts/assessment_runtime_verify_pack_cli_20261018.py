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

ARCHIVE_LIMIT = 1_700_000
CAPS = {
    "index.html": 16_384,
    "START-HERE.txt": 4_096,
    "review.html": 1_048_576,
    "review-desk.html": 65_536,
    "review-desk.json": 262_144,
    "human-worklist.csv": 131_072,
    "manifest.json": 8_192,
}
ANNOTATED_CAPS = dict(CAPS, **{
    "saved-human-review.json": 131_072,
    "human-summary.html": 131_072,
    "review-followup.html": 16_384,
})
ANNOTATED_KEYS = frozenset((
    "saved_human_review_sha256", "saved_human_review_source_sha256",
    "human_summary_sha256", "followup_landing_sha256",
))

FOLLOWUP_CAPS = {
    "READ-ME.txt": 4_096,
    "human-summary.html": 131_072,
    "human-worklist.csv": 131_072,
    "manifest.json": 8_192,
}
FOLLOWUP_KEYS = frozenset((
    "format", "comparison_status", "case_count", "human_stages",
    "human_summary_sha256", "human_worklist_sha256",
    "source_authenticated", "authorized", "consent_verified",
    "dispatch_allowed", "release_allowed",
))

BRIEF_CAPS = {
    "READ-ME.txt": 4_096,
    "review.html": 1_048_576,
    "human-worklist.csv": 131_072,
    "manifest.json": 8_192,
}
BRIEF_KEYS = frozenset((
    "format", "status", "case_count", "reported_regressions",
    "printable_review_sha256", "human_worklist_sha256",
    "source_authenticated", "authorized", "consent_verified",
    "dispatch_allowed", "release_allowed",
))

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


def _inspect_brief(content):
    manifest = _json(content["manifest.json"])
    if type(manifest) is not dict or set(manifest) != BRIEF_KEYS:
        raise ValueError("invalid brief manifest")
    if (manifest["format"] != "lightup.ordinal_review_brief.v1"
            or manifest["status"] not in ("REVIEW_ONLY", "HOLD")
            or type(manifest["case_count"]) is not int
            or not 1 <= manifest["case_count"] <= 64
            or type(manifest["reported_regressions"]) is not int
            or not 0 <= manifest["reported_regressions"] <= 960):
        raise ValueError("invalid brief status")
    if any(manifest[key] is not False for key in (
            "authorized", "consent_verified", "dispatch_allowed",
            "release_allowed", "source_authenticated")):
        raise ValueError("brief claims authority")
    for key, filename in (("printable_review_sha256", "review.html"),
                          ("human_worklist_sha256", "human-worklist.csv")):
        if not _hex(manifest[key]) or manifest[key] != sha256(content[filename]).hexdigest():
            raise ValueError("brief content mismatch")
    if not content["human-worklist.csv"].startswith(b"case,priority,"):
        raise ValueError("invalid human worklist")
    return manifest["status"]


def _inspect_followup(content):
    manifest = _json(content["manifest.json"])
    if type(manifest) is not dict or set(manifest) != FOLLOWUP_KEYS:
        raise ValueError("invalid follow-up manifest")
    counts = manifest["human_stages"]
    stage_names = ("todo", "investigating", "waiting", "planned", "reviewed")
    if (manifest["format"] != "lightup.ordinal_human_followup.v1"
            or manifest["comparison_status"] not in ("REVIEW_ONLY", "HOLD")
            or type(manifest["case_count"]) is not int
            or not 1 <= manifest["case_count"] <= 64
            or type(counts) is not dict or set(counts) != set(stage_names)
            or any(type(counts[key]) is not int or counts[key] < 0 for key in stage_names)
            or sum(counts.values()) != manifest["case_count"]):
        raise ValueError("invalid human planning counts")
    if any(manifest[key] is not False for key in (
            "authorized", "consent_verified", "dispatch_allowed",
            "release_allowed", "source_authenticated")):
        raise ValueError("follow-up claims authority")
    for key, name in (("human_summary_sha256", "human-summary.html"),
                      ("human_worklist_sha256", "human-worklist.csv")):
        if not _hex(manifest[key]) or manifest[key] != sha256(content[name]).hexdigest():
            raise ValueError("follow-up member mismatch")
    if not content["human-worklist.csv"].startswith(b"case,priority,"):
        raise ValueError("invalid source worklist")
    return manifest["comparison_status"]


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
    return inspect_bytes(raw)


def inspect_bytes(raw: bytes):
    """Admit exactly the bytes already privately snapshotted by a caller."""
    if type(raw) is not bytes or not raw or len(raw) > ARCHIVE_LIMIT:
        raise ValueError("archive over limit")
    with ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = set(member.filename for member in entries)
        caps = (CAPS if names == set(CAPS) else
                ANNOTATED_CAPS if names == set(ANNOTATED_CAPS) else
                BRIEF_CAPS if names == set(BRIEF_CAPS) else
                FOLLOWUP_CAPS if names == set(FOLLOWUP_CAPS) else None)
        if caps is None or len(entries) != len(caps):
            raise ValueError("unexpected archive members")
        content = {}
        for member in entries:
            if (member.is_dir() or member.flag_bits & 1
                    or member.compress_type != ZIP_DEFLATED
                    or not 0 < member.file_size <= caps[member.filename]):
                raise ValueError("unsupported archive member")
            data = archive.read(member)
            if len(data) != member.file_size:
                raise ValueError("member size mismatch")
            content[member.filename] = data
    if caps is BRIEF_CAPS:
        return _inspect_brief(content)
    if caps is FOLLOWUP_CAPS:
        return _inspect_followup(content)
    manifest = _json(content["manifest.json"])
    annotated = caps is ANNOTATED_CAPS
    expected_keys = MANIFEST_KEYS | (ANNOTATED_KEYS if annotated else frozenset())
    expected_format = ("lightup.private_lab_review_pack.v2" if annotated
                       else "lightup.private_lab_review_pack.v1")
    if type(manifest) is not dict or set(manifest) != expected_keys:
        raise ValueError("unexpected manifest")
    if (manifest["format"] != expected_format
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
    if annotated:
        from assessment_runtime_attach_triage_cli_20261018 import _validate_plan
        base_hash = sha256(content["review-desk.json"]).hexdigest()
        attached = _json(content["saved-human-review.json"])
        _validate_plan(attached, comparison, base_hash)
        for key, filename in (("saved_human_review_sha256", "saved-human-review.json"),
                              ("human_summary_sha256", "human-summary.html")):
            if not _hex(manifest[key]) or manifest[key] != sha256(content[filename]).hexdigest():
                raise ValueError("annotated review member changed")
        if (manifest["followup_landing_sha256"] !=
                "7aafc195b3ed5d4f748c61ac6a846925124355db44a36a43c06835eca5295dcb"
                or manifest["followup_landing_sha256"] !=
                sha256(content["review-followup.html"]).hexdigest()):
            raise ValueError("unrecognized offline follow-up screen")
        if manifest["saved_human_review_source_sha256"] != base_hash:
            raise ValueError("source-bound human review mismatch")
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
