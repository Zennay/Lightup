"""Deterministic software-only offline assessment kit builder (NO CLIENT DATA).

This static package never runs a scanner, imports customer evidence,
authenticates a sender, changes grants, claims review or confers release.
It only copies allowlisted bounded Git source assets into an unsigned ZIP.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile

SOFTWARE_FILES = (
    "README.md", "preflight.py", "human_review.py", "vault_native.py",
    "reconcile.py", "requirements-native.txt", "review-studio.html",
    "review-studio.css", "review-studio.js", "review-vault.js", "package.py",
    "standalone.html", "reconcile-studio.html", "reconcile-studio.css",
    "reconcile-studio.js", "reconcile_package.py", "reconcile-standalone.html",
    "kit-home.html", "kit-home.css", "private_install.py", "private_intake.py", "private_intake_wizard.py",
    "private_reopen.py", "private_inbox_board.py", "PRIVATE-INBOX-PORTFOLIO.md",
    "private_inbox_actions.py", "PRIVATE-INBOX-ACTIONS.md", "private_inbox_workroom.py",
    "private_inbox_history.py", "PRIVATE-INBOX-HISTORY.md",
    "private_inbox_interval.py",
    "private_inbox_interval_matrix.py",
    "private-inbox-history-studio.html", "private-inbox-history-studio.css",
    "private-inbox-history-studio.js", "private-inbox-history-compose.js",
    "private_inbox_history_package.py", "private-inbox-history-standalone.html",
    "private-inbox-action-studio.html", "private-inbox-action-studio.css",
    "private-inbox-action-studio.js",
    "PRIVATE-BROWSER-INBOX.md", "software_bundle.py",
)
MAX_ASSET = 512 * 1024
ARCHIVE_NAME = "LightUp-PRIVATE-Assessment-Offline-Kit.zip"
PREFIX = "assessment-disclosure-preflight/"
TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def admit_asset(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ASSET:
            raise ValueError("source-only asset not admitted")
        with os.fdopen(fd, "rb", closefd=False) as reader:
            raw = reader.read(MAX_ASSET + 1)
        after = os.fstat(fd)
        if not 0 < len(raw) <= MAX_ASSET or before.st_size != len(raw):
            raise ValueError("source asset changed or exceeds limit")
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("source asset changed during read")
        raw.decode("utf-8", "strict")
        if b"\x00" in raw:
            raise ValueError("binary customer material refused")
        return raw
    finally:
        os.close(fd)


def compose(assets: dict[str, bytes]) -> bytes:
    if set(assets) != set(SOFTWARE_FILES):
        raise ValueError("only the fixed source-only software inventory is accepted")
    for name, data in assets.items():
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_ASSET:
            raise ValueError("unsafe source-only software entry")
        if b"\x00" in data:
            raise ValueError("binary/unexpected content refused")
        data.decode("utf-8", "strict")
    manifest = {
        "schema": "lightup.private_assessment_offline_software.v1",
        "status": "REVIEW_ONLY",
        "software_only": True,
        "source_authenticated": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "release_allowed": False,
        "signed": False,
        "original_lab_inspector_included": False,
        "files": [
            {"path": PREFIX + name, "size": len(assets[name]),
             "sha256": hashlib.sha256(assets[name]).hexdigest()}
            for name in sorted(SOFTWARE_FILES)
        ],
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, strict_timestamps=True) as archive:
        for name, data in sorted(
            [(PREFIX + n, assets[n]) for n in SOFTWARE_FILES] +
            [(PREFIX + "MANIFEST.json", manifest_bytes)]
        ):
            entry = zipfile.ZipInfo(name, date_time=TIMESTAMP)
            entry.create_system = 3
            entry.external_attr = (0o100644 << 16)
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    result = output.getvalue()
    if not 0 < len(result) <= 1024 * 1024:
        raise ValueError("static software-only package outside limit")
    return result



def inspect_unsigned_software(path: str) -> dict:
    """Read-only software ZIP custody: exact bounded members, no extraction.

    Integrity against the embedded unsigned manifest is NOT producer identity,
    a trusted signature, independent approval, evidence provenance or consent.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1024 * 1024:
            raise ValueError("software archive file not admitted")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            original = stream.read(1024 * 1024 + 1)
        final = os.fstat(fd)
        if not 0 < len(original) <= 1024 * 1024 or info.st_size != len(original):
            raise ValueError("software ZIP outside bounded size")
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns) != (final.st_dev, final.st_ino, final.st_size,
                                  final.st_mtime_ns, final.st_ctime_ns):
            raise ValueError("software ZIP changed while reading")
    finally:
        os.close(fd)

    expected_names = sorted([PREFIX + n for n in SOFTWARE_FILES] +
                            [PREFIX + "MANIFEST.json"])
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous duplicate manifest key")
            result[key] = value
        return result
    with zipfile.ZipFile(io.BytesIO(original), "r") as archive:
        infos = archive.infolist()
        if [item.filename for item in infos] != expected_names:
            raise ValueError("unknown/duplicate/out-of-order software package entry")
        for item in infos:
            if (item.date_time != TIMESTAMP or
                item.create_system != 3 or
                item.external_attr != (0o100644 << 16) or
                item.compress_type != zipfile.ZIP_DEFLATED or
                not 0 < item.file_size <= MAX_ASSET or
                not 0 <= item.compress_size <= 1024 * 1024 or
                item.is_dir()):
                raise ValueError("unsafe or noncanonical software ZIP metadata")
        manifest_raw = archive.read(PREFIX + "MANIFEST.json")
        manifest = json.loads(manifest_raw.decode("utf-8", "strict"),
                              object_pairs_hook=unique)
        if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "status", "software_only", "source_authenticated",
            "client_consent_verified", "operator_consent_verified",
            "authorization_granted", "release_allowed", "signed",
            "original_lab_inspector_included", "files"
        }:
            raise ValueError("software manifest schema mismatch")
        if not (manifest["schema"] == "lightup.private_assessment_offline_software.v1"
                and manifest["status"] == "REVIEW_ONLY"
                and manifest["software_only"] is True
                and all(manifest[flag] is False for flag in (
                    "source_authenticated", "client_consent_verified",
                    "operator_consent_verified", "authorization_granted",
                    "release_allowed", "signed", "original_lab_inspector_included"))):
            raise ValueError("authority or manifest claims refused")
        rows = manifest["files"]
        if type(rows) is not list or len(rows) != len(SOFTWARE_FILES):
            raise ValueError("software manifest member mismatch")
        assets = {}
        for index, name in enumerate(sorted(SOFTWARE_FILES)):
            row = rows[index]
            full_name = PREFIX + name
            if (type(row) is not dict or set(row) != {"path", "size", "sha256"} or
                row["path"] != full_name or type(row["size"]) is not int or
                not 0 < row["size"] <= MAX_ASSET or
                type(row["sha256"]) is not str or len(row["sha256"]) != 64):
                raise ValueError("software file inventory mismatch")
            content = archive.read(full_name)
            if (len(content) != row["size"] or
                hashlib.sha256(content).hexdigest() != row["sha256"]):
                raise ValueError("software file content mismatch")
            assets[name] = content
        if compose(assets) != original:
            raise ValueError("software ZIP differs from canonical deterministic package")
    return {"software_files": len(SOFTWARE_FILES),
            "sha256": hashlib.sha256(original).hexdigest(),
            "signed": False, "release_allowed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic unsigned PRIVATE offline software kit")
    parser.add_argument("--output", default=ARCHIVE_NAME)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--inspect", metavar="EXISTING_ZIP",
                       help="read-only inspect exact unsigned ZIP; no extraction")
    group.add_argument("--verify-current", action="store_true",
                       help="compare bundled ZIP with every exact current source file; REVIEW_ONLY or HOLD")
    args = parser.parse_args()
    if args.verify_current:
        if args.output != ARCHIVE_NAME:
            parser.error("--output cannot be used with --verify-current")
        root = Path(__file__).resolve().parent
        try:
            original = inspect_unsigned_software(str(root / ARCHIVE_NAME))
            current = compose({name: admit_asset(root / name) for name in SOFTWARE_FILES})
            if hashlib.sha256(current).hexdigest() != original["sha256"]:
                raise ValueError("bundled software differs from current source")
        except (OSError, ValueError, UnicodeError, MemoryError, zipfile.BadZipFile):
            print("HOLD: bundled ZIP is stale, altered, or differs from local source; no release")
            return 3
        print("REVIEW_ONLY: unsigned ZIP equals all exact local software source bytes")
        print("Software entries:", original["software_files"], "ZIP SHA-256:", original["sha256"])
        print("No sender authentication, customer authority, consent, CI approval or release")
        return 2
    if args.inspect is not None:
        if args.output != ARCHIVE_NAME:
            parser.error("--output cannot be used with --inspect")
        try:
            result = inspect_unsigned_software(args.inspect)
        except (OSError, ValueError, UnicodeError, MemoryError, zipfile.BadZipFile):
            print("HOLD: software ZIP/manifest/content not admitted; no permission or release")
            return 3
        print("REVIEW_ONLY: local unsigned software content matched deterministic manifest; "
              "NOT original identity, security approval, CI or release")
        print("Software entries:", result["software_files"], "ZIP SHA-256:", result["sha256"])
        return 0
    if args.output != ARCHIVE_NAME:
        parser.error("only the fixed software kit filename is admitted")
    root = Path(__file__).resolve().parent
    archive = compose({name: admit_asset(root / name) for name in SOFTWARE_FILES})
    fd, staging = tempfile.mkstemp(prefix=".lightup-software-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(archive)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staging, root / ARCHIVE_NAME)
        dirfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(staging)
        except FileNotFoundError:
            pass
    print("REVIEW_ONLY: unsigned source-only offline software package published exclusively")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
