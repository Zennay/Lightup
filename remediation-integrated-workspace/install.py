#!/usr/bin/env python3
"""Build and inspect a source-only PRIVATE offline LightUp remediation suite.

No user input, tenant files, live endpoints, consent, grants, or scanning.
A source lock and unkeyed hashes are local consistency only, NEVER provenance.
"""
from __future__ import annotations

import argparse
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
    raw = LOCK.read_bytes()
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
    apps = [
        ("Original finding casework", "casework/index.html",
         "Manual, source-local remediation planning; self-declared HUMAN inputs only."),
        ("Original evidence artifact ledger", "remediation-artifact-ledger/standalone.html",
         "Review owner-declared evidence and prepare separate owner handoffs."),
        ("HUMAN portfolio studio", "remediation-portfolio/studio.html",
         "Offline aggregate capacity and routing drafts."),
        ("Encrypted HUMAN handoff studio", "remediation-human-handoff/browser.html",
         "Password-protected HUMAN-only local work sessions and selective handoffs."),
    ]
    cards = "".join(
        "<article><h2><a href='" + html.escape(link) + "'>" + html.escape(title) +
        "</a></h2><p>" + html.escape(desc) + "</p></article>"
        for title, link, desc in apps
    )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · PRIVATE offline remediation workspace</title>
<style>body{font:16px system-ui;background:#f4f6fa;color:#14253b;margin:0}
main{max-width:1050px;margin:2rem auto;padding:0 1.4rem}
h1{font-size:2rem}article,aside,section{background:#fff;padding:1.3rem;border-radius:12px;margin:1rem 0}
article{border:1px solid #e2e6ef}article p{margin:.5rem 0 0}
aside{border-left:6px solid #ba7b16}a{color:#0751a4}
small{display:block;line-height:1.5}</style>
<main><h1>LightUp · PRIVATE HUMAN Remediation Workspace</h1>
<aside><strong>LOCAL OFFLINE · DRAFT/HOLD · NEVER EXECUTION AUTHORITY.</strong>
 This software bundles two original source-pinned held workstreams. Original evidence, owner notes, private client IDs and plaintext workspaces are never added by this installer. An encrypted file cannot prove source authenticity or client consent. No scan, retest, grant, native Apply or verified fix.</aside>
<section><h2>Start at the source owner</h2><p>Open the original Casework and Evidence Ledger locally for human review, then use the offline HUMAN Portfolio and the encrypted selective handoff when a private recipient actually needs it. Do not copy a full private workspace when only a selected human follow-up is appropriate.</p></section>
""" + cards + """
<section><h2>Private receiving desk and timeline</h2>
<p>For independently delivered <em>source-free</em> Cockpit packets, use the bundled native <code>remediation-recipient-trend/receiver_desk.py</code> commands described in <a href="remediation-recipient-trend/README.md">the receiving guide</a>. Those outputs remain private and are not automatically linked or uploaded. Original evidence source admission and HUMAN revisions are explained in <a href="remediation-evidence-bundle-integrity/README.md">the Evidence Workroom guide</a>.</p>
<p>Unkeyed package checksums establish local file consistency only. Owner permissions, current authenticated client/operator consent, revocation-at-use, exact-head CI, source-owner and independent privacy/security review, and explicit HUMAN GO remain independent requirements for any genuine release.</p></section>
<small>Software-only, pinned original source snapshots. Operator-selectable steps are HUMAN-only; downloaded plaintext artifacts can be sensitive. No network, browser storage, script, account login or target activity is added by this launcher.</small></main></html>
""").encode("utf-8")

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
            s = original.lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                    and s.st_size == descriptor["bytes"], "Original source file changed")
            raw = original.read_bytes()
            require(digest(raw) == descriptor["sha256"], "Original source digest mismatch")
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_file(target, raw)
            written[name] = raw
            entries[name] = descriptor
        # Make the archive independently inspectable on a second offline
        # authorized device: carry this CLI and its operator guide too.
        for name in ("remediation-integrated-workspace/install.py",
                     "remediation-integrated-workspace/receiver.py",
                     "remediation-integrated-workspace/workflow.py",
                     "remediation-integrated-workspace/portable_cockpit.py",
                     "remediation-integrated-workspace/single_review.py",
                     "remediation-integrated-workspace/single_review.js",
                     "remediation-integrated-workspace/single_brief.py",
                     "remediation-integrated-workspace/SINGLE_REVIEW.md",
                     "remediation-integrated-workspace/archive_workflow.py",
                     "remediation-integrated-workspace/encrypted_cockpit.py",
                     "remediation-integrated-workspace/README.md"):
            data = (ROOT / name).read_bytes()
            require(len(data) <= MAX_SOURCE, "Installer asset oversized")
            dest_file = stage / name
            dest_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_file(dest_file, data)
            written[name] = data
            entries[name] = {"sha256": digest(data), "bytes": len(data)}
        landing = home()
        written["index.html"] = landing
        written["source-lock.json"] = lock_raw
        for name in ("index.html", "source-lock.json"):
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
        # Recheck checked-out original bytes immediately before publication.
        for name, descriptor in lock["files"].items():
            require(digest((ROOT / name).read_bytes()) == descriptor["sha256"],
                    "Source changed during build")
        require(not dest.exists(), "Destination appeared during build")
        os.rename(stage, dest)
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
        require(safe_name(name) or name in ("index.html", "software-only.zip", "source-lock.json",
                                             "remediation-integrated-workspace/install.py",
                                             "remediation-integrated-workspace/receiver.py",
                                             "remediation-integrated-workspace/workflow.py",
                                             "remediation-integrated-workspace/portable_cockpit.py",
                                             "remediation-integrated-workspace/single_review.py",
                                             "remediation-integrated-workspace/single_review.js",
                                             "remediation-integrated-workspace/single_brief.py",
                                             "remediation-integrated-workspace/SINGLE_REVIEW.md",
                                             "remediation-integrated-workspace/archive_workflow.py",
                     "remediation-integrated-workspace/encrypted_cockpit.py",
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
