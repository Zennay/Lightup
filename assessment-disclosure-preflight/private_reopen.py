"""Read-only reopen of an already PRIVATE received HUMAN browser handoff.

No source evidence proof, grant, identity, consent, scan or network activity.
Unsigned local SHA identities are only a source-change guard. The original
HUMAN reopener remains the final source-bound admission boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys

from human_review import source_bytes
import private_intake as inbox
import reconcile


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate original PRIVATE inventory key")
        result[key] = value
    return result


def reviewer_role(files: set[str], role: str) -> tuple[str, str]:
    expected = [("csv", ".csv"), ("vault", ".luhd"), ("bundle", ".luhb")]
    matches = [(fmt, "PRIVATE-original-reviewer-" + role.upper() + suffix)
               for fmt, suffix in expected
               if "PRIVATE-original-reviewer-" + role.upper() + suffix in files]
    if len(matches) != 1:
        raise ValueError("not exactly one original HUMAN reviewer for this role")
    return matches[0]


def exact_manifest(room_path: str, dir_fd: int) -> tuple[dict, list[str]]:
    original = source_bytes(os.path.join(room_path, inbox.INVENTORY))
    if len(original) > 16 * 1024:
        raise ValueError("PRIVATE source inventory exceeds size limit")
    info = json.loads(original.decode("utf-8", "strict"),
                      object_pairs_hook=no_duplicate_keys)
    expected = {
        "schema", "status", "human_reopened", "transfer_mode", "minimum_cohort",
        "source_authenticated", "independent_review_verified",
        "client_consent_verified", "operator_consent_verified",
        "authorization_granted", "release_allowed", "signed", "files",
    }
    if (type(info) is not dict or set(info) != expected or
        info["schema"] != "lightup.private_offline_human_intake.v1" or
        info["status"] != "REVIEW_ONLY" or info["human_reopened"] is not True or
        info["transfer_mode"] not in ("PRIVATE_ENCRYPTED_BUNDLE", "PRIVATE_PLAINTEXT_CSV") or
        type(info["minimum_cohort"]) is not int or
        not 5 <= info["minimum_cohort"] <= 12 or
        any(info[k] is not False for k in (
            "source_authenticated", "independent_review_verified",
            "client_consent_verified", "operator_consent_verified",
            "authorization_granted", "release_allowed", "signed"
        ))):
        raise ValueError("unsigned PRIVATE manifest authority claim refused")
    rows = info["files"]
    if type(rows) is not list or len(rows) != 6:
        raise ValueError("expected exactly six original HUMAN source roles")
    names = []
    for row in rows:
        if (type(row) is not dict or set(row) != {"role", "bytes", "sha256"} or
            type(row["role"]) is not str or
            type(row["bytes"]) is not int or not 0 < row["bytes"] <= inbox.MAX_DOWNLOAD or
            type(row["sha256"]) is not str or
            not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])):
            raise ValueError("invalid original PRIVATE inventory member")
        names.append(row["role"])
    if len(set(names)) != len(names):
        raise ValueError("duplicate original private member")
    kinds = set(names)
    a_kind, a_name = reviewer_role(kinds, "a")
    b_kind, b_name = reviewer_role(kinds, "b")
    encrypted = inbox.RESULT_BUNDLE in kinds
    result_name = inbox.RESULT_BUNDLE if encrypted else inbox.RESULT_CSV
    allowed = {inbox.RECEIPT, inbox.DECISIONS, inbox.COUNTS,
               a_name, b_name, result_name}
    if (kinds != allowed or
        (info["transfer_mode"] == "PRIVATE_ENCRYPTED_BUNDLE") != encrypted or
        set(os.listdir(dir_fd)) != kinds | {inbox.INVENTORY}):
        raise ValueError("PRIVATE room differs from exact received file set")
    for row in rows:
        raw = source_bytes(os.path.join(room_path, row["role"]))
        if (len(raw) != row["bytes"] or not hmac.compare_digest(
                hashlib.sha256(raw).hexdigest(), row["sha256"])):
            raise ValueError("source byte identity changed after PRIVATE receipt")
    return info, [a_kind, a_name, b_kind, b_name, result_name]


def reopen(parent: str, name: str) -> None:
    if not inbox.ROOM_PATTERN.fullmatch(name):
        raise ValueError("invalid original PRIVATE room name")
    parent_fd, original_parent = inbox.user_private_parent(parent)
    room_fd = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        room_fd = os.open(name, flags, dir_fd=parent_fd)
        metadata = os.fstat(room_fd)
        if (not stat.S_ISDIR(metadata.st_mode) or
            metadata.st_uid != os.geteuid() or
            stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError("old PRIVATE room is not owner-only")
        room = os.path.join(original_parent, name)
        manifest, roles = exact_manifest(room, room_fd)
        a_mode, a_file, b_mode, b_file, result_name = roles
        argv = [
            "reopen", "--receipt", os.path.join(room, inbox.RECEIPT),
            "--a-" + a_mode, os.path.join(room, a_file),
            "--b-" + b_mode, os.path.join(room, b_file),
            "--decisions", os.path.join(room, inbox.DECISIONS),
            "--private-output-dir", room,
            "--received-counts", os.path.join(room, inbox.COUNTS),
            "--minimum-cohort", str(manifest["minimum_cohort"]),
        ]
        if result_name == inbox.RESULT_BUNDLE:
            argv.extend(["--encrypt-result", "--received-bundle",
                         os.path.join(room, result_name)])
        else:
            argv.extend(["--received-csv", os.path.join(room, result_name)])
        if reconcile.main(argv) != 2:
            raise ValueError("original source-bound HUMAN byte reopening refused")
        print("REVIEW_ONLY: unchanged local PRIVATE source bytes and full HUMAN reopening matched")
        print("This proves neither customer identity, reviewer independence, consent nor release")
    finally:
        if room_fd is not None:
            os.close(room_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only original PRIVATE HUMAN inbox reopening; always REVIEW_ONLY/HOLD")
    parser.add_argument("--private-parent", required=True,
                        help="existing owner-only 0700 local room parent")
    parser.add_argument("--room", required=True,
                        help="existing exact PRIVATE room name (no path separators)")
    args = parser.parse_args()
    try:
        reopen(args.private_parent, args.room)
    except (OSError, ValueError, TypeError, UnicodeError, MemoryError, json.JSONDecodeError):
        print("HOLD: original PRIVATE HUMAN room/reviewer/byte contents refused", file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
