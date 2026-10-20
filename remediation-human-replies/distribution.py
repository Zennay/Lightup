#!/usr/bin/env python3
"""Complete PRIVATE original-scheduler + HUMAN-return software-only distribution.

Builds unchanged pinned original software first. Adds only this separately
owned recipient reply companion, never patient/client files, passwords or
evidence. No network, scan, grant, execution authorization or release.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import io
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "remediation-recipient-scheduler"))
import bundle as parent_bundle
import bundle_receive as parent_receiver
import schedule

sys.path.insert(0, str(ROOT / "remediation-integrated-workspace"))
import install

KIND = "lightup.private_human_reply_full_software_only"
DISPOSITION = "REVIEW_ONLY_DRAFT_HOLD"
WARNING = ("PRIVATE offline software-only, unsigned and non-authorizing. No "
           "authenticated producer, consent, finding, fix, security review, "
           "scan, grant or HUMAN GO. INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD.")
COMPANION = ("README.md", "reply.py", "reply.js", "distribution.py")
FILES = frozenset("remediation-human-replies/" + n for n in COMPANION)
PORTABLE = "LightUp-PRIVATE-HUMAN-Reply-Software-DRAFT-HOLD.zip"
ORIGINAL_ZIP = "original-scheduler-software-only.zip"
ORIGINAL_MANIFEST = "original-scheduler-manifest.json"
MAX_MEMBERS = 200
MAX_BYTES = 22_000_000
MAX_ZIP = 6_000_000
MAX_PER_FILE = 4_000_000

def require(condition: bool, message: str) -> None:
    install.require(condition, message)

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def private_input(path: Path, maximum: int) -> bytes:
    return parent_receiver.read_private(path, maximum)

def portal() -> bytes:
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN recipient + reply suite · DRAFT/HOLD</title>
<style>body{font:16px/1.6 system-ui,sans-serif;background:#edf3f8;color:#102840;margin:0}
main{max-width:1000px;margin:1rem auto;padding:1rem}h1{font-size:1.9rem}
section,aside{padding:1rem 1.3rem;border-radius:10px;background:white;border:1px solid #d0dbe7;margin:1rem 0}
aside{border-left:6px solid #a77727}a{color:#165b9a}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f4f7;padding:1rem;border-radius:6px}
</style></head><body><main><h1>LightUp · PRIVATE HUMAN recipient reply</h1>
<aside><strong>INCUBATE · DRAFT/HOLD · OFFLINE ONLY</strong><p>""" +
        html.escape(WARNING) + """</p><p>Passwords and SHA-256 are not real client
consent, original source signatures or permission to act on targets. Only
separately authorized local HUMAN follow-up can be planned here.</p></aside>
<section><h2>1 · Unchanged original evidence-remediation suite</h2>
<p><a href="original-home.html">Open the pinned original PRIVATE evidence studio</a>
or <a href="remediation-recipient-scheduler/README.md">original source-free
recipient scheduler guide</a>. Original original-source admission remains intact.
Do not treat displayed counts as actual distinct cases or verified security findings.</p>
</section>
<section><h2>2 · Select HUMAN tasks in the original local planner</h2>
<p>Use the original private scheduler to select HUMAN-only follow-up. In the
scheduler choose <strong>Encrypt selected HUMAN-only handoff</strong>, generating an
original password encrypted <code>.luhq</code>. Original owner labels and notes
are not automatically included. Independently authorize any transfer.</p></section>
<section><h2>3 · Recipient replies to original selected HUMAN-only packet</h2>
<p>The original encrypted redacted handoff is accepted by original unchanged
<code>queue_handoff.decrypt/admit</code>. On an offline private terminal:</p>
<pre>python3 remediation-human-replies/reply.py prepare \
  --handoff "$HOME/lightup-private/selected-human.luhq" \
  --output-dir "$HOME/lightup-private/private-human-reply-01"</pre>
<p>Open the new private <code>index.html</code>, edit the local response fields,
and export a separately encrypted <code>.luhr</code>. Its reply data deliberately
omits original source and HUMAN owner/notes/deadline/action fields.</p>
</section>
<section><h2>4 · Strict original-bound HUMAN return or continuation</h2>
<pre>python3 remediation-human-replies/reply.py open \
  --handoff "$HOME/lightup-private/selected-human.luhq" \
  --reply "$HOME/lightup-private/lightup-private-human-reply.luhr" \
  --output-dir "$HOME/lightup-private/private-human-report-01"</pre>
<p>Use <code>resume</code> instead of <code>open</code> for a NEW editable offline
workroom continuing that exact encrypted HUMAN reply. Neither is remediation,
grant, a validated client finding, consent or verified fix.</p>
<p><a href="remediation-human-replies/README.md">Complete HUMAN reply
operator instructions</a>.</p></section>
<section><h2>Security and release fence</h2>
<p>Original exact-head hosted and permanently named VPS CI, source-owner,
independent privacy/security/browser/crypto reviews, #177/#182/#829,
authentic current separately authenticated client+operator consent with
action-time revocation and explicit HUMAN GO remain required. Not for active
targets, deployment, native Apply or main merge.</p></section>
</main></body></html>
""").encode("utf-8")

def source_files() -> dict[str, bytes]:
    originals = {}
    for name in FILES:
        p = ROOT / name
        stat_info = p.lstat()
        require(stat.S_ISREG(stat_info.st_mode) and stat_info.st_nlink == 1
                and 0 < stat_info.st_size <= MAX_PER_FILE,
                "HUMAN recipient software source must be bounded regular original file")
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            require(before.st_dev == stat_info.st_dev and
                    before.st_ino == stat_info.st_ino and
                    before.st_size == stat_info.st_size,
                    "Trusted HUMAN software source changed before read")
            raw = os.read(fd, MAX_PER_FILE + 1)
            after = os.fstat(fd)
            require(len(raw) == before.st_size and
                    after.st_size == before.st_size and
                    after.st_mtime_ns == before.st_mtime_ns,
                    "Trusted HUMAN software source changed during read")
            originals[name] = raw
        finally:
            os.close(fd)
    return originals

def zipped(files: dict[str, bytes]) -> bytes:
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=8, allowZip64=False) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, files[path],
                             compress_type=zipfile.ZIP_DEFLATED, compresslevel=8)
    value = memory.getvalue()
    require(len(value) <= MAX_ZIP, "Software-only recipient ZIP exceeds bound")
    return value

def admit_archives(original_manifest: bytes, original_zip: bytes,
                   manifest: bytes, archive: bytes) -> dict[str, bytes]:
    # Strict native verification of original pinned source, entire original
    # scheduler inventory and unmodified original application bytes.
    native = parent_receiver.admission(original_manifest, original_zip)
    expected = set(native) | FILES
    require(len(expected) <= MAX_MEMBERS and set(native).isdisjoint(FILES),
            "Original/private reply source path collision")
    receipt = install.parse(manifest)
    require(set(receipt) == {
        "kind", "version", "disposition", "warning", "authority_granted",
        "consent_verified", "source_authenticated", "remediation_verified",
        "scan_authorized", "original_source_manifest_sha256",
        "original_source_zip_sha256", "software_files",
        "portable_zip_sha256", "portable_zip_bytes"
    } and receipt["kind"] == KIND and type(receipt["version"]) is int
            and receipt["version"] == 1 and receipt["disposition"] == DISPOSITION
            and receipt["warning"] == WARNING
            and all(receipt[k] is False for k in (
                "authority_granted", "consent_verified", "source_authenticated",
                "remediation_verified", "scan_authorized"))
            and receipt["original_source_manifest_sha256"] == digest(original_manifest)
            and receipt["original_source_zip_sha256"] == digest(original_zip)
            and receipt["portable_zip_bytes"] == len(archive)
            and receipt["portable_zip_sha256"] == digest(archive),
            "Unexpected PRIVATE HUMAN reply source-only distribution")
    table = receipt["software_files"]
    require(type(table) is dict and set(table) == expected and
            1 <= len(archive) <= MAX_ZIP, "Untrusted merged software member inventory")
    trusted_own = source_files()
    data: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(archive), allowZip64=False) as reader:
        info = reader.infolist()
        require([i.filename for i in info] == sorted(expected) and
                len(info) == len(expected) <= MAX_MEMBERS,
                "Noncanonical, extra or duplicate merged software ZIP member")
        for entry in info:
            name = entry.filename
            meta = table[name]
            require(not entry.is_dir() and not name.startswith("/")
                    and all(x not in ("", ".", "..") for x in name.split("/"))
                    and (entry.external_attr >> 16) == 0o100600
                    and type(meta) is dict and set(meta) == {"sha256", "bytes"}
                    and type(meta["bytes"]) is int and
                    0 <= meta["bytes"] <= MAX_PER_FILE and
                    entry.file_size == meta["bytes"]
                    and entry.compress_size <= MAX_ZIP,
                    "Unsafe PRIVATE merged software file or compressed member")
            total += entry.file_size
            require(total <= MAX_BYTES, "Excessive inflated source-only bundle")
            raw = reader.read(entry)
            require(len(raw) == entry.file_size and digest(raw) == meta["sha256"],
                    "Original or HUMAN reply source byte digest differs")
            if name in FILES:
                require(raw == trusted_own[name], "HUMAN reply source differs from trusted code")
            elif name == "index.html":
                require(raw == portal(), "Recipient launcher differs from pinned renderer")
            else:
                require(raw == native[name], "Original source-owned software was modified")
            data[name] = raw
    return data

def release_root(destination: Path, stage: Path) -> None:
    require(not destination.exists() and not destination.is_symlink(),
            "Cannot overwrite any existing software folder")
    install.exclusive_publish(stage, destination)

def output_parent(output: Path) -> None:
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink() and
            ROOT not in output.parents and output != ROOT,
            "Choose a new literal private output outside software checkout")
    install.owner_dir(output.parent)

def build(destination: Path) -> None:
    output_parent(destination)
    stage = destination.parent / (".lightup-human-reply-software-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        parent_folder = stage / "pinned-original-scheduler"
        parent_bundle.build(parent_folder)
        parent_bundle.inspect(parent_folder)
        original_manifest = install.read_owner_file(parent_folder / "bundle-manifest.json")
        original_zip = install.read_owner_file(parent_folder / parent_bundle.ARCHIVE)
        original = parent_receiver.admission(original_manifest, original_zip)
        result = dict(original)
        require("index.html" in result, "Missing exact native scheduler portal")
        result["index.html"] = portal()
        result.update(source_files())
        require(sum(len(v) for v in result.values()) <= MAX_BYTES,
                "Merged private software exceeds total source size limit")
        software_zip = zipped(result)
        descriptor = {
            "kind": KIND, "version": 1, "disposition": DISPOSITION,
            "warning": WARNING, "authority_granted": False,
            "consent_verified": False, "source_authenticated": False,
            "remediation_verified": False, "scan_authorized": False,
            "original_source_manifest_sha256": digest(original_manifest),
            "original_source_zip_sha256": digest(original_zip),
            "software_files": {n: {"sha256": digest(raw), "bytes": len(raw)}
                               for n, raw in sorted(result.items())},
            "portable_zip_sha256": digest(software_zip),
            "portable_zip_bytes": len(software_zip),
        }
        receipt = install.canonical(descriptor)
        admit_archives(original_manifest, original_zip, receipt, software_zip)
        install.write_file(stage / PORTABLE, software_zip)
        install.write_file(stage / ORIGINAL_ZIP, original_zip)
        install.write_file(stage / ORIGINAL_MANIFEST, original_manifest)
        install.write_file(stage / "bundle-manifest.json", receipt)
        software = stage / "software"
        os.mkdir(software, 0o700)
        for name, raw in result.items():
            target = software / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            install.write_file(target, raw)
        # Keep native sub-artifacts as original source records; none replaced.
        inspect_staging(stage)
        release_root(destination, stage)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: full original PRIVATE scheduler + HUMAN reply software:", destination)
    print("Open local offline:", destination / "software" / "index.html")
    print("Portable full software ZIP:", destination / PORTABLE)

def inspect_staging(folder: Path) -> None:
    require({p.name for p in folder.iterdir()} == {
        "pinned-original-scheduler", "software", PORTABLE,
        ORIGINAL_ZIP, ORIGINAL_MANIFEST, "bundle-manifest.json"
    }, "Noncanonical PRIVATE distribution root inventory")
    native = folder / "pinned-original-scheduler"
    parent_bundle.inspect(native)
    source_manifest = install.read_owner_file(folder / ORIGINAL_MANIFEST)
    source_zip = install.read_owner_file(folder / ORIGINAL_ZIP)
    require(source_manifest == install.read_owner_file(native / "bundle-manifest.json")
            and source_zip == install.read_owner_file(native / parent_bundle.ARCHIVE),
            "Original trusted scheduler build drifted")
    data = admit_archives(source_manifest, source_zip,
                          install.read_owner_file(folder / "bundle-manifest.json"),
                          parent_receiver.read_private(folder / PORTABLE, MAX_ZIP))
    software = folder / "software"
    existing = set()
    for path in software.rglob("*"):
        if path.is_dir():
            install.owner_dir(path)
        else:
            existing.add(path.relative_to(software).as_posix())
    require(existing == set(data), "Generated runnable software has extra/missing assets")
    for name, raw in data.items():
        require(install.read_owner_file(software / name) == raw,
                "Generated PRIVATE runnable software bytes differ from receipt")

def inspect(folder: Path) -> None:
    require(folder.is_absolute() and not folder.is_symlink(), "PRIVATE software folder is absolute")
    install.owner_dir(folder)
    inspect_staging(folder)
    print("REVIEW_ONLY: complete PRIVATE HUMAN reply software source bytes consistent")

def receive(archive: Path, manifest: Path, parent_archive: Path,
            parent_manifest: Path, destination: Path) -> None:
    output_parent(destination)
    inputs = (archive, manifest, parent_archive, parent_manifest)
    require(len(set(inputs)) == len(inputs), "PRIVATE software inputs must be separate")
    for inp in inputs:
        require(inp != destination and destination not in inp.parents
                and inp not in destination.parents and inp.parent != destination,
                "PRIVATE software inputs may not overlap output")
    held_original_manifest = private_input(parent_manifest, 350_000)
    held_original_zip = private_input(parent_archive, parent_receiver.MAX_ARCHIVE)
    held_manifest = private_input(manifest, 350_000)
    held_archive = private_input(archive, MAX_ZIP)
    data = admit_archives(held_original_manifest, held_original_zip,
                          held_manifest, held_archive)
    stage = destination.parent / (".lightup-human-reply-receive-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        for name, raw in data.items():
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            install.write_file(target, raw)
        require(private_input(parent_manifest, 350_000) == held_original_manifest
                and private_input(parent_archive, parent_receiver.MAX_ARCHIVE) == held_original_zip
                and private_input(manifest, 350_000) == held_manifest
                and private_input(archive, MAX_ZIP) == held_archive,
                "PRIVATE original software or receipt changed during reception")
        require(not destination.exists(), "PRIVATE recipient folder appeared before publication")
        release_root(destination, stage)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: native original-bound software received:", destination)
    print("Open local offline HUMAN reply portal:", destination / "index.html")
    print("Unkeyed hashes and passwords are NOT authenticated sender or HUMAN GO.")

def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="action", required=True)
    p = sub.add_parser("build", help="Create original pinned full offline PRIVATE software distribution")
    p.add_argument("--output-dir", type=Path, required=True)
    p = sub.add_parser("inspect", help="Inspect a locally built private full software folder")
    p.add_argument("--workspace", type=Path, required=True)
    p = sub.add_parser("receive", help="Receive exact original and new unsigned software under 0600/0700")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--parent-archive", type=Path, required=True)
    p.add_argument("--parent-manifest", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    a = cli.parse_args()
    try:
        if a.action == "build":
            build(a.output_dir)
        elif a.action == "receive":
            receive(a.archive, a.manifest, a.parent_archive,
                    a.parent_manifest, a.output_dir)
        else:
            inspect(a.workspace)
        return 2
    except (install.Hold, OSError, ValueError, KeyError, TypeError,
            RuntimeError, zipfile.BadZipFile, OverflowError) as e:
        print("HOLD: private source-only HUMAN reply package:", e, file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
