#!/usr/bin/env python3
"""Build and inspect a source-only PRIVATE offline LightUp remediation suite.

No user input, tenant files, live endpoints, consent, grants, or scanning.
A source lock and unkeyed hashes are local consistency only, NEVER provenance.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "remediation-integrated-workspace" / "source-lock.json"
KIND = "lightup.private_offline_remediation_suite"
ROOTS = frozenset((
    "casework", "remediation-artifact-ledger", "remediation-evidence-reuse",
    "remediation-evidence-bundle-integrity", "remediation-recipient-trend",
    "remediation-portfolio", "remediation-human-handoff",
))
WARNING = ("PRIVATE HUMAN-only offline software. No original producer authentication, "
           "consent, grant, security finding, remediation, verified retest or HUMAN GO. "
           "INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD.")
MAX_SOURCE = 4_000_000
MAX_TOTAL = 15_000_000

class Hold(ValueError):
    pass

def require(ok: bool, message: str) -> None:
    if not ok:
        raise Hold(message)

def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")

def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "Duplicate JSON member")
        result[key] = value
    return result

def parse(raw: bytes) -> dict:
    require(len(raw) <= 350_000, "JSON descriptor too large")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold("Nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Hold("Invalid JSON descriptor") from exc
    require(type(obj) is dict and canonical(obj) == raw, "Noncanonical descriptor")
    return obj

def read_checkout_source(path: Path, ceiling: int = MAX_SOURCE) -> bytes:
    """Admit a fixed local software file via one no-follow descriptor.

    Reject linked components, partial/changed reads and mutable file identity.
    This checks local bytes, not ownership of the upstream producer.
    """
    require(path.is_absolute() and ROOT in path.parents and
            path != ROOT and 0 < ceiling <= MAX_TOTAL,
            "Source must be an exact file beneath the current checkout")
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode), "Linked checkout path refused")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 <= before.st_size <= ceiling, "Unsafe or oversized checkout source")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        current = os.fstat(fd)
        identity = (current.st_dev, current.st_ino, current.st_size,
                    current.st_mtime_ns, current.st_ctime_ns)
        require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                and identity == (before.st_dev, before.st_ino, before.st_size,
                                 before.st_mtime_ns, before.st_ctime_ns),
                "Checkout source changed during admission")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(ceiling + 1)
        after = os.fstat(fd)
        post = path.lstat()
        require((after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) == identity
                and (post.st_dev, post.st_ino, post.st_size,
                     post.st_mtime_ns, post.st_ctime_ns) == identity
                and stat.S_ISREG(post.st_mode) and post.st_nlink == 1
                and len(raw) == current.st_size and len(raw) <= ceiling,
                "Checkout source changed while reading")
        return raw
    finally:
        os.close(fd)


def safe_name(name: str) -> bool:
    if type(name) is not str or not 1 <= len(name) <= 190:
        return False
    p = PurePosixPath(name)
    return (not p.is_absolute() and len(p.parts) >= 2
            and p.parts[0] in ROOTS
            and all(part not in (".", "..") and not part.startswith(".") for part in p.parts)
            and p.suffix in (".py", ".md", ".html", ".js", ".css")
            and all(ord(c) < 128 and (c.isalnum() or c in "/_.-") for c in name))

def catalog() -> tuple[bytes, dict]:
    raw = read_checkout_source(LOCK, 350_000)
    obj = parse(raw)
    require(obj is not None and set(obj) == {"kind", "version", "source_heads", "files"}
            and obj["kind"] == "lightup.integrated_offline_source_lock"
            and type(obj["version"]) is int and obj["version"] == 1, "Invalid source inventory")
    entries = obj["files"]
    require(type(entries) is dict and 50 <= len(entries) <= 160, "Incomplete source inventory")
    require(sum(v.get("bytes", MAX_TOTAL) for v in entries.values() if type(v) is dict) <= MAX_TOTAL,
            "Oversized source inventory")
    for name, descriptor in entries.items():
        require(safe_name(name), "Unsafe source name")
        require(type(descriptor) is dict and set(descriptor) == {"sha256", "bytes"}
                and type(descriptor["bytes"]) is int
                and 0 <= descriptor["bytes"] <= MAX_SOURCE
                and type(descriptor["sha256"]) is str
                and len(descriptor["sha256"]) == 64
                and all(ch in "0123456789abcdef" for ch in descriptor["sha256"]),
                "Invalid source descriptor")
    return raw, obj

def owner_dir(folder: Path) -> None:
    require(folder.is_absolute() and not folder.is_symlink()
            and folder.parent == folder.parent.resolve(strict=True),
            "Directory must be absolute, literal, non-symlink path")
    s = folder.stat(follow_symlinks=False)
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid()
            and s.st_mode & 0o077 == 0, "Directory must be owner-only 0700")

def read_owner_file(path: Path) -> bytes:
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid()
            and s.st_nlink == 1 and s.st_mode & 0o077 == 0, "Not an owner-only single-link file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fs = os.fstat(fd)
        require(fs.st_ino == s.st_ino and fs.st_dev == s.st_dev
                and fs.st_size <= MAX_SOURCE + 1_000_000, "File replaced or too large")
        return os.read(fd, fs.st_size + 1)
    finally:
        os.close(fd)

def write_file(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    finally:
        os.close(fd)

def home() -> bytes:
    # Single source-of-truth for the complete PRIVATE scriptless entry page.
    import landing
    return landing.render()

def exclusive_publish(stage: Path, destination: Path) -> None:
    """Linux renameat2(NO_REPLACE), as original native PRIVATE workspace publisher.

    Never fall back to a replace-capable rename if exclusive publication
    is unsupported; an independently created target must remain untouched.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, "renameat2", None)
    require(operation is not None, "Exclusive Linux recipient publication unavailable")
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    at_fdcwd = getattr(os, "AT_FDCWD", -100)
    rc = operation(at_fdcwd, os.fsencode(stage), at_fdcwd,
                   os.fsencode(destination), 1)
    if rc:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(destination))
    fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def build(dest: Path) -> None:
    lock_raw, lock = catalog()
    require(dest.is_absolute() and not dest.exists() and not dest.is_symlink()
            and dest.parent == dest.parent.resolve(strict=True), "Choose a new literal absolute destination")
    owner_dir(dest.parent)
    require(dest != ROOT and ROOT not in dest.parents and dest not in ROOT.parents,
            "Output must be separate from the original source checkout")
    stage = dest.parent / (".lightup-suite-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        written = {}
        entries = {}
        for name, descriptor in sorted(lock["files"].items()):
            original = ROOT / name
            raw = read_checkout_source(original)
            require(len(raw) == descriptor["bytes"] and
                    digest(raw) == descriptor["sha256"],
                    "Original source bytes differ from the pinned source inventory")
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_file(target, raw)
            written[name] = raw
            entries[name] = descriptor
        # Make the archive independently inspectable on a second offline
        # authorized device: carry this CLI and its operator guide too.
        for name in ("remediation-integrated-workspace/install.py",
                     "remediation-integrated-workspace/private_desk.py",
                     "remediation-integrated-workspace/operator_console.py",
                     "remediation-integrated-workspace/landing.py",
                     "remediation-integrated-workspace/operator_ui.js",
                     "remediation-integrated-workspace/fingerprint_ui.js",
                     "remediation-integrated-workspace/packet_fingerprint.py",
                     "remediation-integrated-workspace/packet_brief.py",
                     "remediation-integrated-workspace/operator_ui.css",
                     "remediation-integrated-workspace/receiver.py",
                     "remediation-integrated-workspace/workflow.py",
                     "remediation-integrated-workspace/portable_cockpit.py",
                     "remediation-integrated-workspace/single_review.py",
                     "remediation-integrated-workspace/single_review.js",
                     "remediation-integrated-workspace/single_brief.py",
                     "remediation-integrated-workspace/SINGLE_REVIEW.md",
                     "remediation-integrated-workspace/archive_workflow.py",
                     "remediation-integrated-workspace/encrypted_cockpit.py",
                     "remediation-integrated-workspace/journal_vault.py",
                     "remediation-integrated-workspace/journal_encrypt.js",
                     "remediation-integrated-workspace/journal_open.js",
                     "remediation-integrated-workspace/review_package.py",
                     "remediation-integrated-workspace/REVIEW_PACKAGE.md",
                     "remediation-integrated-workspace/JOURNAL_VAULT.md",
                     "remediation-integrated-workspace/README.md"):
            data = read_checkout_source(ROOT / name)
            dest_file = stage / name
            dest_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_file(dest_file, data)
            written[name] = data
            entries[name] = {"sha256": digest(data), "bytes": len(data)}
        import operator_console
        operator_page = operator_console.render()
        landing = home()
        written["operator.html"] = operator_page
        written["index.html"] = landing
        written["source-lock.json"] = lock_raw
        for name in ("index.html", "operator.html", "source-lock.json"):
            write_file(stage / name, written[name])
            entries[name] = {"sha256": digest(written[name]), "bytes": len(written[name])}
        archive = stage / "software-only.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=8) as z:
            for name, data in sorted(written.items()):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                info.create_system = 3
                z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=8)
        os.chmod(archive, 0o600)
        entries["software-only.zip"] = {"sha256": digest(archive.read_bytes()),
                                         "bytes": archive.stat().st_size}
        receipt = {"kind": KIND, "version": 1, "disposition": "HUMAN_ONLY_DRAFT_HOLD",
                   "authority_granted": False, "scan_authorized": False,
                   "verified_remediation": False, "client_consent": False,
                   "source_heads": lock["source_heads"], "files": entries,
                   "warning": WARNING}
        write_file(stage / "manifest.json", canonical(receipt))
        # Re-admit the immutable pinned sources and the assembled software tools
        # immediately before publication; never publish a source-mixed workspace.
        require(read_checkout_source(LOCK, 350_000) == lock_raw,
                "Source lock changed during build")
        for name, descriptor in lock["files"].items():
            fresh = read_checkout_source(ROOT / name)
            require(len(fresh) == descriptor["bytes"] and
                    digest(fresh) == descriptor["sha256"],
                    "Pinned source changed during build")
        for name in written:
            if name.startswith("remediation-integrated-workspace/"):
                require(read_checkout_source(ROOT / name) == written[name],
                        "Installer software changed during build")
        require(not dest.exists(), "Destination appeared during build")
        exclusive_publish(stage, dest)
        print("PRIVATE offline integrated workspace:", dest)
        print("Open locally:", dest / "index.html")
        print("Software-only archive:", dest / "software-only.zip")
        print("REVIEW_ONLY / NO AUTHORITY; original release gates remain held.")
    finally:
        if stage.exists():
            shutil.rmtree(stage)

def verify(folder: Path) -> None:
    owner_dir(folder)
    receipt = parse(read_owner_file(folder / "manifest.json"))
    require(set(receipt) == {"kind", "version", "disposition", "authority_granted",
                            "scan_authorized", "verified_remediation", "client_consent",
                            "source_heads", "files", "warning"}
            and receipt["kind"] == KIND and type(receipt["version"]) is int
            and receipt["version"] == 1 and receipt["disposition"] == "HUMAN_ONLY_DRAFT_HOLD"
            and all(receipt[k] is False for k in
                    ("authority_granted", "scan_authorized", "verified_remediation", "client_consent"))
            and receipt["warning"] == WARNING, "Not a canonical HUMAN-only suite")
    files = receipt["files"]
    require(type(files) is dict and len(files) >= 53, "Incomplete package manifest")
    require(receipt["source_heads"] == catalog()[1]["source_heads"],
            "Source snapshot identities do not match installed review")
    expected = set(files) | {"manifest.json"}
    present = set()
    for directory, dirnames, filenames in os.walk(folder, followlinks=False):
        current = Path(directory)
        owner_dir(current)
        for dirname in dirnames:
            require(not (current / dirname).is_symlink(), "Unexpected linked directory")
        for filename in filenames:
            name = (current / filename).relative_to(folder).as_posix()
            present.add(name)
    require(present == expected, "Package files missing or extra")
    verified = {}
    for name, descriptor in files.items():
        require(safe_name(name) or name in ("index.html", "operator.html", "software-only.zip", "source-lock.json",
                                             "remediation-integrated-workspace/install.py",
                     "remediation-integrated-workspace/private_desk.py",
                     "remediation-integrated-workspace/operator_console.py",
                     "remediation-integrated-workspace/landing.py",
                     "remediation-integrated-workspace/operator_ui.js",
                     "remediation-integrated-workspace/fingerprint_ui.js",
                     "remediation-integrated-workspace/packet_fingerprint.py",
                     "remediation-integrated-workspace/packet_brief.py",
                     "remediation-integrated-workspace/operator_ui.css",
                                             "remediation-integrated-workspace/receiver.py",
                                             "remediation-integrated-workspace/workflow.py",
                                             "remediation-integrated-workspace/portable_cockpit.py",
                                             "remediation-integrated-workspace/single_review.py",
                                             "remediation-integrated-workspace/single_review.js",
                                             "remediation-integrated-workspace/single_brief.py",
                                             "remediation-integrated-workspace/SINGLE_REVIEW.md",
                                             "remediation-integrated-workspace/archive_workflow.py",
                     "remediation-integrated-workspace/encrypted_cockpit.py",
                     "remediation-integrated-workspace/journal_vault.py",
                     "remediation-integrated-workspace/journal_encrypt.js",
                     "remediation-integrated-workspace/journal_open.js",
                     "remediation-integrated-workspace/review_package.py",
                     "remediation-integrated-workspace/REVIEW_PACKAGE.md",
                     "remediation-integrated-workspace/JOURNAL_VAULT.md",
                                             "remediation-integrated-workspace/README.md"),
                "Unexpected package name")
        require(type(descriptor) is dict and set(descriptor) == {"sha256", "bytes"}
                and type(descriptor["bytes"]) is int and descriptor["bytes"] >= 0
                and type(descriptor["sha256"]) is str and len(descriptor["sha256"]) == 64,
                "Invalid package descriptor")
        raw = read_owner_file(folder / name)
        require(digest(raw) == descriptor["sha256"] and len(raw) == descriptor["bytes"],
                "Package file bytes changed")
        verified[name] = raw
    require(verified["index.html"] == home(), "Launcher differs from pinned local renderer")
    import operator_console
    require(verified["operator.html"] == operator_console.render(),
            "Operator studio differs from original native offline renderer")
    installed_lock = parse(verified["source-lock.json"])
    require(installed_lock == catalog()[1], "Source inventory changed")
    for name, descriptor in installed_lock["files"].items():
        require(name in verified and digest(verified[name]) == descriptor["sha256"],
                "Installed source not pinned")
    with zipfile.ZipFile(folder / "software-only.zip") as z:
        require(z.namelist() == sorted(name for name in verified if name != "software-only.zip"),
                "Archive file inventory mismatch")
        for name in z.namelist():
            require(z.getinfo(name).file_size <= MAX_SOURCE, "Archive item oversized")
            require(z.read(name) == verified[name], "Archive does not match installed source")
    print("REVIEW_ONLY: offline suite and software archive locally consistent.")
    print("Local hashes are not signatures, authenticated consent or release approval.")

def main() -> int:
    parser = argparse.ArgumentParser(description="Install or inspect source-only offline HUMAN workroom")
    sub = parser.add_subparsers(dest="action", required=True)
    p_build = sub.add_parser("build", help="Publish a fresh PRIVATE 0700 software-only offline suite")
    p_build.add_argument("--output-dir", required=True, type=Path)
    p_verify = sub.add_parser("inspect", help="Inspect a locally installed PRIVATE suite without any network")
    p_verify.add_argument("--workspace", required=True, type=Path)
    p_recv = sub.add_parser("receive", help="Safely reconstruct pinned software-only ZIP offline")
    p_recv.add_argument("--archive", required=True, type=Path)
    p_recv.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "build":
            build(args.output_dir)
        elif args.action == "receive":
            from receiver import receive
            receive(args.archive, args.output_dir)
        else:
            verify(args.workspace)
        return 2  # REVIEW_ONLY; not a release success signal.
    except (Hold, OSError, KeyError, TypeError, zipfile.BadZipFile, ValueError) as exc:
        print("HOLD:", str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
