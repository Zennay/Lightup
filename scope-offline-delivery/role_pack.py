#!/usr/bin/env python3
"""Prepare or inspect an offline PRIVATE least-disclosure source-only reviewer bundle.

NO authentication, access grant, scan, live target, release or consent issuance.
For real transfers, authenticate the recipient in a separate trusted channel.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import zipfile

SOURCE_HEAD = "0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc"
FORMAT = "lightup.scope_private_role_handoff.v1"
POSTURE = "INCUBATE_M3_M7_DRAFT_HOLD"
AUTHORITY = dict.fromkeys(("client_consent", "operator_consent", "grant", "scan", "deploy", "release"), False)
SOURCE_PINS = {
    "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip": "60f9086490ecb00d725ae00da173ee6eb843de9d346d4c39b5f4a51a359703de",
    "workspace/SOURCE-MANIFEST.json": "dc1aa82f9d335e07e142466b1e144b31f97239af4339b5b56279ee1a28235f63",
    "workspace/DIST-MANIFEST.json": "c8cb4d972d4822939bc542c6b292f72e5e246d772ed32587d3a9ed4fed1f629d",
    "workspace/verify.html": "d1d0d2ca5a53599d2dc85589c58a4af6eddf7528cb519498185943a5718723c5",
    "courier/PRIVATE-encrypted-courier.html": "55cbef56f7ca0df32ad5fe65ea6868efc4c7ac2f1abf01ecb1e4d97b7e327edf",
    "privacy/disclosure-preflight.html": "d23b51b73b39c994edbb681e20b7e501bd037be366488870470bfe68ef34bb24",
    "privacy/disclosure-recipient-verify.html": "a3b48236e0b297f1a903f2d02ba8fdedf4ea63b03109089a96f116cab1011483",
}
PROFILES = {
    "privacy-recipient": ("courier/PRIVATE-encrypted-courier.html", "privacy/disclosure-recipient-verify.html"),
    "privacy-editor": ("courier/PRIVATE-encrypted-courier.html", "privacy/disclosure-preflight.html", "privacy/disclosure-recipient-verify.html"),
    "scope-reviewer": ("workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip", "workspace/SOURCE-MANIFEST.json", "workspace/DIST-MANIFEST.json", "workspace/verify.html"),
}
NAME = "PRIVATE-ROLE-START-HERE.html"
DOC = "PRIVATE-ROLE-README.txt"
RECEIPT = "PRIVATE-ROLE-RECEIPT.json"
SELF = "tools/role_pack.py"
COMMON = {NAME, DOC, RECEIPT, SELF}

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def strict_json(data: bytes) -> dict:
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("Ambiguous repeated JSON key")
            d[k] = v
        return d
    obj = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    if type(obj) is not dict:
        raise ValueError("Unexpected JSON root")
    return obj

def source_exact(values: dict[str, bytes], profile: str) -> None:
    if profile not in PROFILES or set(values) != set(PROFILES[profile]):
        raise ValueError("HOLD: original profile file membership mismatch")
    for name, payload in values.items():
        if sha(payload) != SOURCE_PINS[name]:
            raise ValueError("HOLD: immutable original source SHA mismatch: " + name)

def note(profile: str) -> bytes:
    return (f"LightUp PRIVATE HUMAN scope handoff — {profile}\n"
            "INCUBATE M3/M7 PLAN/LAB ONLY — DRAFT/HOLD — REVIEW ONLY.\n"
            "This bundle contains unchanged ORIGINAL source tools for exactly one human role,\n"
            "not access credentials, a signed receipt, proof of privacy, or permission.\n"
            "No bundled tool automatically contacts assets, grants work or performs scans.\n"
            "First verify this ENTIRE original ZIP against a SHA-256 you obtained through an\n"
            "authenticated, independent channel: python3 tools/role_pack.py inspect\n"
            "  /path/to/received.zip --expected-sha256 <64-lowercase-hex>\n"
            "Only then run: python3 tools/role_pack.py unpack RECEIVED.zip\n"
            "  PRIVATE_PARENT/NEW_DIR --expected-sha256 ROLE-ZIP-SHA256\n"
            "Use only a user-owned private parent; open the offline start page manually.\n"
            "The encrypted HUMAN courier needs a strong unique passphrase exchanged separately.\n"
            "A matching digest and encryption do not authenticate a sender or recipient.\n"
            "Human review, consent and all LightUp original release/CI/security gates remain.\n").encode()

def landing(profile: str) -> bytes:
    items = "".join("<li><a href='" + html.escape(path, quote=True) + "'>" +
                    html.escape(path) + "</a></li>" for path in PROFILES[profile])
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
            "style-src 'unsafe-inline';connect-src 'none';object-src 'none';"
            "frame-src 'none';form-action 'none';base-uri 'none'\">"
            "<title>LightUp PRIVATE role handoff · DRAFT/HOLD</title>"
            "<style>body{font:1rem/1.65 system-ui,sans-serif;max-width:760px;"
            "margin:3rem auto;padding:1rem;background:#101b2a;color:#f2f6ff}"
            "section{padding:1rem;border:1px solid #75839a;border-radius:10px}"
            "a{color:#8fdaff}strong{color:#ffd09a}</style></head><body>"
            "<h1>LightUp PRIVATE HUMAN handoff — " + html.escape(profile) + "</h1>"
            "<p><strong>INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.</strong></p>"
            "<p>Verify the entire package against a separately authenticated expected "
            "SHA-256 before extracting anything. This receipt is unsigned and proves "
            "no sender identity, client/operator approval, recipient access or authority.</p>"
            "<section><h2>Source-pinned original components</h2><ul>" + items + "</ul>"
            "<p>The original files are not modified or executed automatically. "
            "Share each only with its independently authenticated, intended reviewer.</p></section>"
            "<p>Manual private sharing, independent client/operator consent, original "
            "security reviews, approved scope and HUMAN GO are required before any real assessment.</p>"
            "</body></html>").encode()

def receipt(profile: str, source_sha: str, parts: dict[str, bytes]) -> bytes:
    fields = {
        "format": FORMAT, "posture": POSTURE, "profile": profile,
        "source_head": SOURCE_HEAD, "source_outer_sha256": source_sha,
        "authenticated_sender": False, "release": False,
        "authority": AUTHORITY,
        "files": [{"path": name, "bytes": len(data), "sha256": sha(data)}
                  for name, data in sorted(parts.items())],
        "note": "UNSIGNED PRIVATE REVIEW ONLY; no client or operator consent or release.",
    }
    return (json.dumps(fields, sort_keys=True, indent=2) + "\n").encode()

def read_archive_snapshot(path: Path) -> bytes:
    # Open once without following a last-component symlink. Never revisit the
    # pathname between digest admission and local original-file publication.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or not 1 <= meta.st_size <= 2_000_000:
            raise ValueError("HOLD: oversized or unsafe private source file")
        content = stream.read(2_000_001)
    if len(content) != meta.st_size:
        raise ValueError("HOLD: private source bytes changed while reading")
    return content


def inspect_role(path: Path, expected_sha256: str | None, snapshot: bytes | None = None) -> dict:
    if expected_sha256 is None or re.fullmatch("[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("HOLD: externally authenticated exact lowercase SHA-256 is required")
    data = read_archive_snapshot(path) if snapshot is None else snapshot
    if not 1 <= len(data) <= 2_000_000:
        raise ValueError("HOLD: invalid role ZIP snapshot size")
    digest = sha(data)
    if digest != expected_sha256:
        raise ValueError("HOLD: independently supplied role-package SHA-256 differs")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if not 5 <= len(infos) <= 8:
            raise ValueError("HOLD: unusual role-package member count")
        if any(x.is_dir() or x.compress_type != zipfile.ZIP_STORED or
               x.flag_bits & 1 or x.file_size > 1_000_000 or
               x.filename.startswith("/") or "\\" in x.filename or
               any(part in ("", ".", "..") for part in x.filename.split("/")) or
               stat.S_IFMT(x.external_attr >> 16) != stat.S_IFREG
               for x in infos):
            raise ValueError("HOLD: unsupported ZIP member")
        names = [x.filename for x in infos]
        if len(set(names)) != len(names) or RECEIPT not in names:
            raise ValueError("HOLD: missing or duplicate ZIP names")
        blobs = {name: z.read(name) for name in names}
    r = strict_json(blobs[RECEIPT])
    if (set(r) != {"format", "posture", "profile", "source_head", "source_outer_sha256",
                   "authenticated_sender", "release", "authority", "files", "note"} or
        r["format"] != FORMAT or r["posture"] != POSTURE or
        r["profile"] not in PROFILES or r["source_head"] != SOURCE_HEAD or
        type(r["source_outer_sha256"]) is not str or
        re.fullmatch("[0-9a-f]{64}", r["source_outer_sha256"]) is None or
        r["authenticated_sender"] is not False or r["release"] is not False or
        type(r["authority"]) is not dict or r["authority"] != AUTHORITY or
        any(r["authority"][k] is not False for k in AUTHORITY)):
        raise ValueError("HOLD: invalid non-authorizing role receipt")
    profile = r["profile"]
    expected = COMMON | set(PROFILES[profile])
    if set(blobs) != expected:
        raise ValueError("HOLD: role package includes unexpected or missing original files")
    originals = {key: blobs[key] for key in PROFILES[profile]}
    source_exact(originals, profile)
    entries = [{"path": key, "bytes": len(value), "sha256": sha(value)}
               for key, value in sorted(blobs.items()) if key != RECEIPT]
    if (r["files"] != entries or blobs[DOC] != note(profile) or
        blobs[NAME] != landing(profile) or blobs[SELF] != Path(__file__).read_bytes()):
        raise ValueError("HOLD: role packet instructions or exact file records changed")
    return {"status": "REVIEW_ONLY", "profile": profile, "bytes": len(data),
            "sha256": digest, "original_components": len(originals),
            "separately_supplied_sha256_match": True,
            "authenticated_sender": False, "release": False}

def build_role(outer: Path, destination: Path, profile: str, outer_sha: str) -> dict:
    # Imports the existing, unchanged original integrated delivery admission and
    # requires a separately authenticated SHA match on that complete source file.
    from package import inspect as inspect_original
    original = inspect_original(outer, outer_sha)
    if original["separate_expected_sha256_match"] is not True:
        raise ValueError("HOLD: missing original out-of-band byte receipt")
    if profile not in PROFILES:
        raise ValueError("Invalid recipient profile")
    parent = destination.absolute().parent
    if (not parent.is_dir() or parent.is_symlink() or
        parent.stat().st_uid != os.getuid() or (parent.stat().st_mode & 0o077)):
        raise ValueError("HOLD: output parent must be operator-owned PRIVATE 0700")
    if destination.exists() or destination.is_symlink():
        raise ValueError("HOLD: destination exists; never overwrite")
    outer_snapshot = read_archive_snapshot(outer)
    if sha(outer_snapshot) != outer_sha:
        raise ValueError("HOLD: source ZIP changed since original byte admission")
    with zipfile.ZipFile(io.BytesIO(outer_snapshot)) as z:
        originals = {n: z.read(n) for n in PROFILES[profile]}
    source_exact(originals, profile)
    parts = dict(originals)
    parts.update({DOC: note(profile), NAME: landing(profile), SELF: Path(__file__).read_bytes()})
    parts[RECEIPT] = receipt(profile, original["outer_sha256"], parts)
    fd, tmp = tempfile.mkstemp(prefix=".private-role-", suffix=".zip", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            with zipfile.ZipFile(stream, "w", allowZip64=False) as z:
                for name, payload in sorted(parts.items()):
                    info = zipfile.ZipInfo(name, (2026, 10, 20, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    info.compress_type = zipfile.ZIP_STORED
                    z.writestr(info, payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Refuse existing destination, even if it appears after initial preflight.
        os.link(tmp, destination, follow_symlinks=False)
        os.unlink(tmp)
        result = inspect_role(destination, sha(destination.read_bytes()))
        return result
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def unpack_role(archive: Path, destination: Path, expected_sha256: str) -> dict:
    snapshot = read_archive_snapshot(archive)
    result = inspect_role(archive, expected_sha256, snapshot)
    parent = destination.absolute().parent
    if (not parent.is_dir() or parent.is_symlink() or
        parent.stat().st_uid != os.getuid() or (parent.stat().st_mode & 0o077)):
        raise ValueError("HOLD: output parent must be operator-owned PRIVATE 0700")
    if destination.exists() or destination.is_symlink():
        raise ValueError("HOLD: destination already exists")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise ValueError("HOLD: Linux atomic no-replace publication unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    stage = Path(tempfile.mkdtemp(prefix=".lightup-role-stage-", dir=parent))
    try:
        os.chmod(stage, 0o700)
        with zipfile.ZipFile(io.BytesIO(snapshot)) as z:
            for name in sorted(z.namelist()):
                current = stage.joinpath(*name.split("/"))
                current.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(current, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(z.read(name))
                    output.flush()
                    os.fsync(output.fileno())
        if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(destination))
        result["private_destination"] = str(destination.absolute())
        return result
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE non-authorizing role handoff")
    commands = parser.add_subparsers(dest="action", required=True)
    build = commands.add_parser("build", help="prepare exact source-pinned role ZIP")
    build.add_argument("original_outer_zip", type=Path)
    build.add_argument("new_private_role_zip", type=Path)
    build.add_argument("--profile", choices=PROFILES, required=True)
    build.add_argument("--expected-sha256", required=True,
                       help="independently authenticated SHA256 of original outer source ZIP")
    inspect = commands.add_parser("inspect", help="inspect delivered role ZIP")
    inspect.add_argument("private_role_zip", type=Path)
    inspect.add_argument("--expected-sha256", required=True,
                         help="independently authenticated SHA256 of this role ZIP")
    unpack = commands.add_parser("unpack", help="safely materialize received role into new private folder")
    unpack.add_argument("private_role_zip", type=Path)
    unpack.add_argument("new_private_directory", type=Path)
    unpack.add_argument("--expected-sha256", required=True,
                        help="separately authenticated SHA256 of this received role ZIP")
    args = parser.parse_args()
    try:
        if args.action == "build":
            result = build_role(args.original_outer_zip, args.new_private_role_zip,
                                args.profile, args.expected_sha256)
        elif args.action == "inspect":
            result = inspect_role(args.private_role_zip, args.expected_sha256)
        else:
            result = unpack_role(args.private_role_zip, args.new_private_directory,
                                 args.expected_sha256)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as err:
        print("HOLD: " + str(err), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
