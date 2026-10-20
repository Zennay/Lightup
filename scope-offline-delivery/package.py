#!/usr/bin/env python3
"""Source-pinned PRIVATE HUMAN LightUp scope delivery; never authorizes execution."""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
SRC = ROOT / "scope-current-bundle"
OUTPUT = "LightUp-PRIVATE-HUMAN-Transfer-DRAFT-HOLD.zip"
PARENT_SHA = "0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc"
COURIER_SHA = "55cbef56f7ca0df32ad5fe65ea6868efc4c7ac2f1abf01ecb1e4d97b7e327edf"
DISCLOSURE_HEAD = "91842b75d9965adca6448b19bf31346c48d1be5c"
PRIVACY_FILES = {
  "privacy/disclosure-preflight.html": ("disclosure-preflight.html", "d23b51b73b39c994edbb681e20b7e501bd037be366488870470bfe68ef34bb24"),
  "privacy/disclosure-recipient-verify.html": ("disclosure-recipient-verify.html", "a3b48236e0b297f1a903f2d02ba8fdedf4ea63b03109089a96f116cab1011483"),
}
ORIGINAL_ZIP_SHA = "60f9086490ecb00d725ae00da173ee6eb843de9d346d4c39b5f4a51a359703de"
ORIGINAL_SOURCE_SHA = "dc1aa82f9d335e07e142466b1e144b31f97239af4339b5b56279ee1a28235f63"
ORIGINAL_DIST_SHA = "c8cb4d972d4822939bc542c6b292f72e5e246d772ed32587d3a9ed4fed1f629d"
STATUS = "INCUBATE_M3_M7_DRAFT_HOLD"
AUTHORITY = dict.fromkeys(("client_consent", "operator_consent", "grant",
                           "scan", "deploy", "release"), False)
FILES = {
    "workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip": "LightUp-Scope-Offline-DRAFT-HOLD.zip",
    "workspace/SOURCE-MANIFEST.json": "SOURCE-MANIFEST.json",
    "workspace/DIST-MANIFEST.json": "DIST-MANIFEST.json",
    "workspace/verify.html": "verify.html",
    "courier/PRIVATE-encrypted-courier.html": "PRIVATE-encrypted-courier.html",
}
README = """LightUp PRIVATE HUMAN scope delivery — INCUBATE M3/M7 DRAFT/HOLD
1. Extract this complete outer ZIP to a local private folder.
2. Verify the entire ZIP: python3 package.py inspect ORIGINAL.zip
3. Open START-HERE.html locally; never host it publicly.
   For HUMAN text, redact first with privacy/disclosure-preflight.html.
   Then encrypt the redacted note with courier/PRIVATE-encrypted-courier.html.
   Recipient decrypts, opens privacy/disclosure-recipient-verify.html and
   checks redacted exact bytes/receipt. Matching SHA is not identity.
   Portable inspector: python3 tools/package.py inspect ORIGINAL.zip
4. Or run: python3 tools/unpack.py ORIGINAL.zip PRIVATE_PARENT/NEW_DIR
   Then open NEW_DIR/original-workspace/scope-unified-workspace/index.html.
5. Open the separate encrypted courier to encrypt the original ZIP or HUMAN notes.
6. Check recipient identity and exchange passwords through another trusted channel.
All hashes are unsigned. NO active target, authorization, grant, revoke, deployment,
verified remediation, fresh consent, independent review or HUMAN GO is implied.
"""
HOME = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';base-uri 'none';form-action 'none';connect-src 'none';object-src 'none'">
<title>LightUp · Private scope delivery</title><style>
body{font:1rem/1.6 system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1.4rem;background:#111c2b;color:#f5f7fc}
a{color:#9addff}section{padding:1.2rem;margin:1rem 0;border:1px solid #64748b;border-radius:12px}strong{color:#ffdb94}
</style></head><body><h1>LightUp · PRIVATE HUMAN scope delivery</h1>
<p><strong>INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD</strong></p>
<p>Extract this entire ZIP locally. All companion applications work offline and cannot authorize work or verify consent.</p>
<section><h2>1 · Original scope workspace</h2><p><a href="workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip" download>Save current complete original scope workspace ZIP</a></p><p>Extract that ZIP separately, then open its original index.html.</p><p>Using the PRIVATE CLI unpacker instead? <a href="original-workspace/scope-unified-workspace/index.html">Open the already-unpacked original workspace here</a> (available only after CLI unpack). No auto-launch.</p></section>
<section><h2>2 · Disclose only deliberately redacted HUMAN text</h2>
<p><a href="privacy/disclosure-preflight.html">Open pinned original private disclosure/redaction desk</a></p>
<p>Manually mask bounded HUMAN text, review every page and confirm export. This source-owner tool is unchanged, offline, and may HOLD on remaining credential hints. A redacted file is not automatically safe or approved to disclose.</p></section>
<section><h2>3 · Encrypted human courier</h2><p><a href="courier/PRIVATE-encrypted-courier.html">Open offline PRIVATE encryption courier</a></p><p>Choose original workspace ZIP or reviewer notes. Recipient and current permissions must be verified independently. Exchange the password separately.</p></section>
<section><h2>4 · Recipient redacted-byte review</h2>
<p><a href="privacy/disclosure-recipient-verify.html">Open pinned original recipient review desk</a></p>
<p>After separately receiving and decrypting redacted HUMAN text, compare the literal bytes to its original receipt. Human review is still required even if fingerprints match.</p></section>
<section><h2>5 · Bounded private unpack</h2><p>In a terminal with Python 3.11+, run <code>python3 tools/unpack.py /path/to/outer.zip /private-parent/new-workroom</code>. The parent folder must already be mode 0700, owned by you, and the destination must not exist. This command checks original bytes and opens source entries locally without scans or grants.</p></section>
<section><h2>6 · Browser-only recipient byte verification</h2>
<p><a href="PRIVATE-receive.html">Open local recipient SHA-256 comparator</a> to select a received file and paste a separately authenticated outer file digest. A BYTE MATCH is REVIEW ONLY, never proof of sender or consent.</p></section>
<section><h2>7 · Source byte records</h2><p><a href="workspace/verify.html">Open original offline ZIP-byte verifier</a> · <a href="manifest.json">Unsigned integrated byte receipt</a> · <a href="workspace/DIST-MANIFEST.json">Original workspace distribution receipt</a></p></section>
<p>No scans, network requests, browser storage, client approval, grants, automatic execution or deployment. Original source-owner + security/privacy review, exact-head hosted and named-VPS CI, real separately authenticated current client/operator consent with action-time revocation, and explicit HUMAN GO remain mandatory for any release.</p>
</body></html>"""

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read(path: Path, maximum=1_500_000) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise ValueError("Missing, symlinked or oversized source: " + path.name)
    return path.read_bytes()

def strict_json(data: bytes) -> dict:
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("Duplicate JSON field")
            result[k] = v
        return result
    obj = json.loads(data.decode("utf8", "strict"), object_pairs_hook=unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    if type(obj) is not dict:
        raise ValueError("Expected JSON object")
    return obj

def no_authority(obj: dict) -> bool:
    a = obj.get("authority")
    return type(a) is dict and set(a) == set(AUTHORITY) and all(a[k] is False for k in AUTHORITY)

def render_receiver() -> bytes:
    template = read(HERE / "recipient.template.html", 10000).decode("utf-8")
    js = read(HERE / "recipient.js", 10000).decode("utf-8")
    css = read(HERE / "recipient.css", 10000).decode("utf-8")
    for token in ("__SCRIPT_HASH__", "__STYLE_HASH__", "__SCRIPT__", "__STYLE__"):
        if template.count(token) != 1:
            raise ValueError("Portable receiver template ambiguity: " + token)
    if "</script" in js.lower() or "</style" in css.lower():
        raise ValueError("Unsafe inline receiver source")
    def sri(data: str) -> str:
        return base64.b64encode(hashlib.sha256(data.encode()).digest()).decode()
    for token, value in (("__SCRIPT_HASH__", sri(js)), ("__STYLE_HASH__", sri(css)),
                         ("__SCRIPT__", js), ("__STYLE__", css)):
        template = template.replace(token, value)
    return template.encode("utf-8")


def original_admission(workspace: bytes, source: bytes, dist: bytes) -> None:
    if (digest(workspace) != ORIGINAL_ZIP_SHA or digest(source) != ORIGINAL_SOURCE_SHA
            or digest(dist) != ORIGINAL_DIST_SHA):
        raise ValueError("Exact original source-derived artifact pin changed")
    a, b = strict_json(source), strict_json(dist)
    if a.get("format") != "lightup.scope_offline_bundle.v1" or a.get("posture") != STATUS:
        raise ValueError("Original workspace format/posture drift")
    if b.get("format") != "lightup.scope_offline_distribution.v1" or b.get("posture") != STATUS:
        raise ValueError("Original distribution format/posture drift")
    if not no_authority(a) or not no_authority(b):
        raise ValueError("Original scope source asserts authority")
    if b.get("authenticated_release") is not False or b.get("source_parent_sha") != PARENT_SHA:
        raise ValueError("Original source/release pin mismatch")
    rows = b.get("files")
    if type(rows) is not list or len(rows) != 5 or any(type(x) is not dict for x in rows):
        raise ValueError("Original file inventory malformed")
    by_name = {row.get("name"): row for row in rows}
    if len(by_name) != 5:
        raise ValueError("Original file names ambiguous")
    for name, data in [("LightUp-Scope-Offline-DRAFT-HOLD.zip", workspace),
                       ("SOURCE-MANIFEST.json", source)]:
        item = by_name.get(name, {})
        if item.get("bytes") != len(data) or item.get("sha256") != digest(data):
            raise ValueError("Original source bytes do not match original distribution")
    with zipfile.ZipFile(io.BytesIO(workspace)) as z:
        names = z.namelist()
        if len(names) < 60 or len(names) != len(set(names)):
            raise ValueError("Original workspace member inventory invalid")
        if z.read("scope-unified-workspace/SOURCE-MANIFEST.json") != source:
            raise ValueError("Original workspace embedded source receipt changed")

def receipt(blobs: dict[str, bytes]) -> bytes:
    item = {"format": "lightup.scope_private_delivery.v1", "posture": STATUS,
            "original_source_sha": PARENT_SHA, "disclosure_original_sha": DISCLOSURE_HEAD, "authenticated_release": False,
            "authority": AUTHORITY, "files": [
                {"path": n, "bytes": len(v), "sha256": digest(v)}
                for n, v in sorted(blobs.items())],
            "note": "Unsigned bytes / REVIEW_ONLY; no source owner authentication, consent, grant or release."}
    return (json.dumps(item, indent=2, sort_keys=True) + "\n").encode()

def verify_out_of_band(actual: str, expected: str | None) -> bool:
    if expected is None:
        return False
    if re.fullmatch(r"[0-9a-f]{64}", expected, flags=re.ASCII) is None:
        raise ValueError("Expected out-of-band SHA-256 must be exactly 64 lowercase hex characters")
    if actual != expected:
        raise ValueError("Separately supplied transfer SHA-256 does NOT match")
    return True


def inspect(path: Path, expected_sha256: str | None = None) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_500_000:
        raise ValueError("Unsafe or oversized transfer")
    expected = set(FILES) | set(PRIVACY_FILES) | {"PRIVATE-receive.html", "tools/recipient.js", "tools/recipient.css", "tools/recipient.template.html","tools/package.py", "tools/unpack.py", "START-HERE.html", "README.txt", "manifest.json"}
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) != len(expected) or {x.filename for x in infos} != expected:
            raise ValueError("Unexpected, duplicated or missing transfer members")
        if any(x.file_size > 1_500_000 or x.compress_type != zipfile.ZIP_STORED or
               x.is_dir() or x.flag_bits & 1 for x in infos):
            raise ValueError("Unexpected compressed or encrypted transfer member")
        m = strict_json(z.read("manifest.json"))
        data = {n: z.read(n) for n in sorted(expected - {"manifest.json"})}
    if (set(m) != {"format", "posture", "original_source_sha", "disclosure_original_sha",
                   "authenticated_release", "authority", "files", "note"} or
        m["format"] != "lightup.scope_private_delivery.v1" or m["posture"] != STATUS or
        m["original_source_sha"] != PARENT_SHA or m["disclosure_original_sha"] != DISCLOSURE_HEAD or m["authenticated_release"] is not False or
        not no_authority(m) or m["files"] != [
            {"path": n, "bytes": len(v), "sha256": digest(v)} for n, v in sorted(data.items())]):
        raise ValueError("Original delivery file receipt / HOLD flags mismatch")
    if (data["PRIVATE-receive.html"] != render_receiver() or
        data["tools/recipient.js"] != read(HERE / "recipient.js") or
        data["tools/recipient.css"] != read(HERE / "recipient.css") or
        data["tools/recipient.template.html"] != read(HERE / "recipient.template.html")):
        raise ValueError("Standalone recipient browser is not byte-identical to pinned source build")
    if data["START-HERE.html"] != HOME.encode() or data["README.txt"] != README.encode() or data["tools/package.py"] != read(Path(__file__)) or data["tools/unpack.py"] != read(HERE / "unpack.py"):
        raise ValueError("Built-in operator instructions changed")
    if any(digest(data[name]) != pin for name, (_path, pin) in PRIVACY_FILES.items()):
        raise ValueError("Pinned original disclosure or recipient preflight changed")
    if digest(data["courier/PRIVATE-encrypted-courier.html"]) != COURIER_SHA:
        raise ValueError("Original courier bytes changed")
    original_admission(data["workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip"],
                       data["workspace/SOURCE-MANIFEST.json"],
                       data["workspace/DIST-MANIFEST.json"])
    matched = verify_out_of_band(digest(path.read_bytes()), expected_sha256)
    return {"status": "REVIEW_ONLY", "separate_expected_sha256_match": matched, "bytes": path.stat().st_size,
            "outer_sha256": digest(path.read_bytes()),
            "workspace_sha256": digest(data["workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip"]),
            "courier_sha256": COURIER_SHA}

def publish_receiver_standalone(content: bytes) -> None:
    target = HERE / "PRIVATE-receive.html"
    if target.exists() or target.is_symlink():
        if read(target, 100000) != content:
            raise ValueError("Original standalone recipient already exists with different bytes")
        return
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def build() -> Path:
    # Existing original production packager, invoked as a build (not a QA suite).
    subprocess.run([sys.executable, str(SRC / "build.py")], cwd=ROOT, check=True, timeout=120)
    blobs = {dst: read(SRC / src) for dst, src in FILES.items()}
    for name, (filename, pin) in PRIVACY_FILES.items():
        original = read(HERE / filename)
        if digest(original) != pin:
            raise ValueError("Disclosure source-owner byte pin changed: " + filename)
        blobs[name] = original
    original_admission(blobs["workspace/LightUp-Scope-Offline-DRAFT-HOLD.zip"],
                       blobs["workspace/SOURCE-MANIFEST.json"],
                       blobs["workspace/DIST-MANIFEST.json"])
    if digest(blobs["courier/PRIVATE-encrypted-courier.html"]) != COURIER_SHA:
        raise ValueError("Original encrypted courier drift")
    receiver_html = render_receiver()
    blobs.update({"PRIVATE-receive.html": receiver_html,
                  "tools/recipient.js": read(HERE / "recipient.js"),
                  "tools/recipient.css": read(HERE / "recipient.css"),
                  "tools/recipient.template.html": read(HERE / "recipient.template.html"),
                  "START-HERE.html": HOME.encode(), "README.txt": README.encode(),
                  "tools/package.py": read(Path(__file__)),
                  "tools/unpack.py": read(HERE / "unpack.py")})
    blobs["manifest.json"] = receipt(blobs)
    fd, temp = tempfile.mkstemp(prefix=".scope-private-", suffix=".zip", dir=HERE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            with zipfile.ZipFile(f, "w", allowZip64=False) as z:
                for n, v in sorted(blobs.items()):
                    info = zipfile.ZipInfo(n, (2026, 10, 20, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = 0o100600 << 16
                    info.compress_type = zipfile.ZIP_STORED
                    z.writestr(info, v)
            f.flush()
            os.fsync(f.fileno())
        path = HERE / OUTPUT
        if path.exists():
            if read(path, 2_500_000) != read(Path(temp), 2_500_000):
                raise ValueError("Existing published package differs; no overwrite")
        else:
            os.link(temp, path)
        inspect(path)
        publish_receiver_standalone(receiver_html)
        return path
    finally:
        Path(temp).unlink(missing_ok=True)

def main() -> int:
    parser = argparse.ArgumentParser(description="Offline private scope delivery; HOLD only")
    parser.add_argument("action", choices=("build", "inspect"))
    parser.add_argument("archive", nargs="?", type=Path)
    parser.add_argument("--expected-sha256", help="Externally obtained trusted original outer ZIP SHA-256 (lowercase hex)")
    args = parser.parse_args()
    try:
        if args.action == "build" and args.archive is None and args.expected_sha256 is None:
            path = build()
            print(json.dumps({"built": str(path), **inspect(path)}, sort_keys=True))
        elif args.action == "inspect" and args.archive:
            print(json.dumps(inspect(args.archive, args.expected_sha256), sort_keys=True))
        else:
            raise ValueError("build takes no archive; inspect requires an archive")
        return 0
    except (ValueError, OSError, UnicodeError, zipfile.BadZipFile,
            KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print("HOLD: " + str(error), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
