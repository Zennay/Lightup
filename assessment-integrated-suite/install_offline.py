#!/usr/bin/env python3
"""Receive a verified software-only LightUp ZIP into a new owner-private offline room.

No original assessment source, target, grant, network, execution or client data.
A local digest is NOT authentication or release consent.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from zipfile import ZipFile

from verify_offline import (
    Hold, MAX_ARCHIVE, MAX_MEMBERS, MAX_MEMBER, MAX_TOTAL,
    PACKAGE_ASSETS, digest, reject_symlink_components, safe_member,
    verify,
)

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z")
RECEIPT = "PRIVATE-INSTALL-RECEIPT.json"
REVIEW = "PRIVATE-INSTALL-REVIEW.html"
SCHEMA = "lightup.private_offline_kit_install.v2"
LEGACY = "lightup.private_offline_kit_install.v1"
NO_AUTHORITY = {
    "authenticated_client": False, "authenticated_operator": False,
    "consent_verified": False, "dispatch_allowed": False,
    "release_allowed": False, "deploy_allowed": False,
}


def render_private_review(zip_sha: str, apps: int, scripts: int) -> bytes:
    """No raw source, filename, notes or client text enters this local document."""
    if (not isinstance(zip_sha, str) or re.fullmatch("[a-f0-9]{64}", zip_sha) is None or
            type(apps) is not int or not 1 <= apps <= 100 or
            type(scripts) is not int or not 0 <= scripts <= 100):
        raise Hold("HOLD: printable software inventory is malformed")
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>LightUp | PRIVATE offline kit intake</title></head><body><main>
<h1>LightUp | PRIVATE software intake</h1>
<p><strong>INCUBATE M3/M7 - REVIEW_ONLY / DRAFT-HOLD.</strong></p>
<p>Local software receipt only. No customer material, scan, consent, grant, execution,
real approval, vulnerability verification or deployment is contained here.</p>
<h2>Unsigned installed software inventory</h2>
<p>Original offline HTML studios: """ + str(apps) + """</p>
<p>Local supporting JS files: """ + str(scripts) + """</p>
<p>Original ZIP SHA-256 (unsigned, local-byte comparison only):
<code>""" + zip_sha + """</code></p>
<h2>Independent HUMAN review checklist</h2><ol>
<li>Separately authenticate the original package source and expected whole ZIP
digest through an independent trusted channel. A bundled checksum is not a signature.</li>
<li>Open START-HERE.html from disk on a suitably private local computer; do not serve publicly.</li>
<li>Before real use require the original owner, security/privacy/browser and CI approvals,
genuine separately authenticated current client/operator consent, action-time revocation
checks and explicit HUMAN GO. This app does none of these checks.</li>
<li>Use the native inspect-kit command to inspect local software continuity before
further offline human review. Missing, modified or unexpected files require HOLD.</li>
</ol><p>AUTHENTICATED=false | CONSENT_VERIFIED=false |
DISPATCH_ALLOWED=false | RELEASE_ALLOWED=false | DEPLOY_ALLOWED=false</p>
</main></body></html>\n""").encode("utf-8")


def private_directory(path: Path) -> Path:
    path = reject_symlink_components(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) & 0o077):
        raise Hold("HOLD: PRIVATE room/parent must be an owner-owned 0700 directory")
    return path


def bytes_snapshot(path: Path) -> bytes:
    """Read a stable bounded ordinary archive without following symlinks."""
    path = reject_symlink_components(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        identity = (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        pathname = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                not 0 < before.st_size <= MAX_ARCHIVE or
                (pathname.st_dev, pathname.st_ino) != identity[:2]):
            raise Hold("HOLD: package must be a stable bounded, ordinary single-link file")
        content = stream.read(MAX_ARCHIVE + 1)
        after = os.fstat(stream.fileno())
        pathname_after = path.lstat()
        if (len(content) != before.st_size or len(content) > MAX_ARCHIVE or
                identity != (after.st_dev, after.st_ino, after.st_size,
                             after.st_mtime_ns, after.st_ctime_ns) or
                (pathname_after.st_dev, pathname_after.st_ino) != identity[:2]):
            raise Hold("HOLD: package changed during private read")
        return content


def exact_private_file(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def publish_without_replace(staging: Path, destination: Path) -> None:
    """Linux renameat2 RENAME_NOREPLACE; never replace an existing directory."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise Hold("HOLD: atomic no-overwrite directory publication unavailable")
    renameat2.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(staging), -100, os.fsencode(destination), 1):
        problem = ctypes.get_errno()
        if problem in (errno.EEXIST, errno.ENOTEMPTY):
            raise Hold("HOLD: PRIVATE destination already exists")
        raise Hold("HOLD: atomic PRIVATE publication refused")


def install(package: Path, parent: Path, folder: str,
            expected_sha256: str = "", sidecar: Path | None = None,
            source_root: Path | None = None) -> int:
    if not NAME.fullmatch(folder) or folder in {".", ".."}:
        raise Hold("HOLD: use a literal 1-48 character safe PRIVATE room name")
    parent = private_directory(parent)
    if parent == ROOT or ROOT in parent.parents:
        raise Hold("HOLD: PRIVATE installed software must stay outside repository checkout")
    destination = parent / folder
    if destination.exists() or destination.is_symlink():
        raise Hold("HOLD: PRIVATE destination already exists")
    snapshot = bytes_snapshot(package)
    actual_sha = digest(snapshot)
    if expected_sha256 and actual_sha != expected_sha256:
        raise Hold("HOLD: separately supplied ZIP digest does not match")
    # Original unchanged native verifier admits exact archive bytes, schema,
    # complete v2 manifest and optional local checkout parity before publication.
    manifest = verify(package, actual_sha, sidecar, source_root, return_manifest=True)
    if manifest["schema"] != "lightup.assessment_offline_software_kit.v2":
        raise Hold("HOLD: safe installer requires fully inventoried v2 package")
    members = [*manifest["files"], *manifest["package_assets"]]
    listed = {item["filename"]: {
        "filename": item["filename"], "bytes": item["bytes"],
        "sha256_unsigned": item["sha256_unsigned"],
    } for item in members}
    raw_manifest = None
    with ZipFile(io.BytesIO(snapshot), "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS or len(infos) != len(listed) + 1:
            raise Hold("HOLD: unexpected software archive members")
        for info in infos:
            name = safe_member(info)
            if name != "manifest.json" and name not in listed:
                raise Hold("HOLD: unexpected software archive entry")
        raw_manifest = archive.read("manifest.json")
        listed["manifest.json"] = {
            "filename": "manifest.json", "bytes": len(raw_manifest),
            "sha256_unsigned": digest(raw_manifest),
        }
        staging = Path(tempfile.mkdtemp(prefix=".lightup-private-stage-", dir=parent))
        published = False
        try:
            os.chmod(staging, 0o700)
            for name in sorted(listed):
                item = listed[name]
                if (name != "manifest.json" and name not in PACKAGE_ASSETS and
                        not name.startswith("studios/")):
                    raise Hold("HOLD: unrecognized software member path")
                bits = name.split("/")
                directory = staging
                for segment in bits[:-1]:
                    directory = directory / segment
                    if not directory.exists():
                        directory.mkdir(mode=0o700)
                content = archive.read(name)
                if (len(content) != item["bytes"] or
                        digest(content) != item["sha256_unsigned"] or
                        len(content) > MAX_MEMBER):
                    raise Hold("HOLD: software bytes changed since manifest admission")
                exact_private_file(staging / name, content)
            review_html = render_private_review(
                actual_sha, manifest["original_app_count"], manifest["support_asset_count"])
            exact_private_file(staging / REVIEW, review_html)
            receipt = {
                "schema": SCHEMA, "review_sha256_unsigned": digest(review_html),
                "package_sha256_unsigned": actual_sha,
                "package_schema": manifest["schema"], "files": [
                    listed[name] for name in sorted(listed)
                ], "authority": dict(NO_AUTHORITY),
            }
            raw = (json.dumps(receipt, indent=2, sort_keys=True,
                              ensure_ascii=True) + "\n").encode("utf-8")
            exact_private_file(staging / RECEIPT, raw)
            for subdir in sorted(staging.rglob("*"), reverse=True):
                if subdir.is_dir():
                    fd = os.open(subdir, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            publish_without_replace(staging, destination)
            published = True
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if not published and staging.exists():
                shutil.rmtree(staging)
    print("INSTALLED PRIVATE SOFTWARE ONLY / REVIEW_ONLY: " + str(destination))
    print("OPEN OFFLINE LOCALLY: " + str(destination / "START-HERE.html"))
    print("PRIVATE HUMAN REVIEW: " + str(destination / REVIEW))
    print("Unsigned ZIP SHA-256: " + actual_sha)
    print("No source authentication, consent, grant, assessment, execution or release.")
    return 2


def inspect(room: Path) -> int:
    room = private_directory(room)
    receipt_path = room / RECEIPT
    raw = read_private(room, receipt_path, 256 * 1024)
    try:
        data = json.loads(raw.decode("utf-8"))
        current = data.get("schema") == SCHEMA
        expected_fields = {"schema", "package_sha256_unsigned", "package_schema",
                           "files", "authority"} | ({"review_sha256_unsigned"} if current else set())
        if (set(data) != expected_fields or
                data.get("schema") not in {SCHEMA, LEGACY} or
                data["package_schema"] != "lightup.assessment_offline_software_kit.v2" or
                data["authority"] != NO_AUTHORITY or
                not isinstance(data["package_sha256_unsigned"], str) or
                not re.fullmatch("[a-f0-9]{64}", data["package_sha256_unsigned"]) or
                (json.dumps(data, indent=2, sort_keys=True,
                            ensure_ascii=True) + "\n").encode("utf-8") != raw):
            raise Hold("HOLD: PRIVATE installer receipt is malformed")
        members = data["files"]
        if not isinstance(members, list) or not 1 <= len(members) <= MAX_MEMBERS:
            raise Hold("HOLD: PRIVATE software inventory is malformed")
        names = set()
        total = 0
        for item in members:
            if not isinstance(item, dict) or set(item) != {"filename", "bytes", "sha256_unsigned"}:
                raise Hold("HOLD: PRIVATE software file descriptor is malformed")
            name, size, sha = item["filename"], item["bytes"], item["sha256_unsigned"]
            if (not isinstance(name, str) or name in names or name == RECEIPT or
                    name not in PACKAGE_ASSETS | {"manifest.json"} and
                    not name.startswith("studios/") or
                    type(size) is not int or not 0 < size <= MAX_MEMBER or
                    not isinstance(sha, str) or not re.fullmatch("[a-f0-9]{64}", sha)):
                raise Hold("HOLD: PRIVATE software entry is unsafe or duplicated")
            if name not in PACKAGE_ASSETS | {"manifest.json"} and (
                    len(name.split("/")) != 2 or not NAME.fullmatch(name.split("/")[1])):
                # Real studio names can contain periods and hyphens, but never path traversal.
                if len(name.split("/")) != 2 or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name.split("/")[1]):
                    raise Hold("HOLD: PRIVATE studio path cannot be safely admitted")
            names.add(name)
            total += size
            if total > MAX_TOTAL:
                raise Hold("HOLD: PRIVATE software bytes exceed bound")
            file_path = reject_symlink_components(room / name)
            if file_path.parent != room:
                private_directory(file_path.parent)
            content = read_private(room, file_path, size)
            if len(content) != size or digest(content) != sha:
                raise Hold("HOLD: installed PRIVATE software differs from receipt")
        if not PACKAGE_ASSETS.issubset(names) or "manifest.json" not in names:
            raise Hold("HOLD: required offline launcher/manifest absent")
        if current:
            expected_page = render_private_review(
                data["package_sha256_unsigned"],
                sum(x.startswith("studios/") and x.endswith(".html") for x in names),
                sum(x.startswith("studios/") and not x.endswith(".html") for x in names))
            page = read_private(room, room / REVIEW, 16 * 1024)
            if (not isinstance(data["review_sha256_unsigned"], str) or
                    data["review_sha256_unsigned"] != digest(expected_page) or
                    page != expected_page):
                raise Hold("HOLD: printable PRIVATE intake review differs from original receipt")
        real_files = set()
        for candidate in room.rglob("*"):
            candidate = reject_symlink_components(candidate)
            relative = candidate.relative_to(room).as_posix()
            kind = candidate.lstat()
            if stat.S_ISDIR(kind.st_mode):
                private_directory(candidate)
                if relative != "studios":
                    raise Hold("HOLD: unexpected PRIVATE subdirectory")
            elif stat.S_ISREG(kind.st_mode):
                real_files.add(relative)
            else:
                raise Hold("HOLD: unsafe PRIVATE room entry")
        if real_files != names | ({RECEIPT, REVIEW} if current else {RECEIPT}):
            raise Hold("HOLD: missing or unexpected PRIVATE installed software file")
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise Hold("HOLD: malformed PRIVATE installer receipt") from None
    print("INSPECTED LOCAL PRIVATE SOFTWARE / REVIEW_ONLY: " + str(room))
    print("Matched " + str(len(names)) + " original installed software files against unsigned receipt.")
    if current:
        print("PRINTABLE PRIVATE REVIEW: " + str(room / REVIEW))
    print("SHA receipt establishes local byte continuity only, never identity or consent.")
    return 2


def read_private(room: Path, path: Path, maximum: int) -> bytes:
    path = reject_symlink_components(path)
    if room not in path.parents:
        raise Hold("HOLD: PRIVATE read must remain within the installed room")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        stat_path = path.lstat()
        identity = (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.geteuid() or
                stat.S_IMODE(before.st_mode) & 0o077 or
                before.st_size > maximum or
                (stat_path.st_dev, stat_path.st_ino) != identity[:2]):
            raise Hold("HOLD: PRIVATE software file is unsafe or not owner-only")
        content = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(content) != before.st_size or len(content) > maximum or
                identity != (after.st_dev, after.st_ino, after.st_size,
                             after.st_mtime_ns, after.st_ctime_ns)):
            raise Hold("HOLD: PRIVATE software changed while reading")
        return content


def main() -> int:
    parser = argparse.ArgumentParser(description="Install/inspect verified LightUp software, offline only")
    sub = parser.add_subparsers(dest="command", required=True)
    installing = sub.add_parser("install", help="verify, then install to a new private 0700 directory")
    installing.add_argument("--package", required=True)
    installing.add_argument("--private-parent", required=True)
    installing.add_argument("--folder", required=True)
    installing.add_argument("--expected-sha256", default="")
    installing.add_argument("--sha256-file", default="")
    installing.add_argument("--source-root", default="")
    installing.add_argument("--human-confirm", required=True,
                            help="exactly INSTALL PRIVATE OFFLINE KIT")
    opening = sub.add_parser("inspect", help="reopen private files without original ZIP")
    opening.add_argument("--room", required=True)
    args = parser.parse_args()
    try:
        if args.command == "install":
            if args.human_confirm != "INSTALL PRIVATE OFFLINE KIT":
                raise Hold("HOLD: explicit private installation confirmation required")
            return install(Path(args.package).absolute(),
                           Path(args.private_parent).absolute(), args.folder,
                           args.expected_sha256,
                           Path(args.sha256_file).absolute() if args.sha256_file else None,
                           Path(args.source_root).absolute() if args.source_root else None)
        return inspect(Path(args.room).absolute())
    except (Hold, OSError, ValueError, TypeError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: offline PRIVATE installation refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
