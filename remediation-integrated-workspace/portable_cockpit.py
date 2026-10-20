#!/usr/bin/env python3
"""PRIVATE source-free Evidence Cockpit single-file transport, no network.

Unencrypted archive, not a trust/consent/security verdict or signed sender.
Uses unchanged original native read_cockpit admission both before packing
and before publishing an unpacked receiver folder.
"""
from __future__ import annotations
import argparse
import io
import os
from pathlib import Path
import secrets
import shutil
import sys
import zipfile

import install

ORIGINAL = install.ROOT / "remediation-evidence-bundle-integrity"
sys.path.insert(0, str(ORIGINAL))
import read_cockpit

review = read_cockpit.review
workspace = read_cockpit.workspace
triage = read_cockpit.triage
verify = read_cockpit.verify

MAX_ZIP = 12 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024

def require(ok: bool, reason: str) -> None:
    review.require(ok, reason)

def inventory(manifest: bytes) -> frozenset[str]:
    obj = verify.json_obj(manifest)
    require(type(obj) is dict and type(obj.get("original_packet_context_repeated")) is bool,
            "Unrecognized original source-free manifest history claim")
    members = read_cockpit.DEFAULT | (
        read_cockpit.HISTORY if obj["original_packet_context_repeated"] else frozenset()
    )
    return members | frozenset(("manifest.json",))

def zip_files(payloads: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=8) as archive:
        for name, raw in sorted(payloads.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=8)
    data = buffer.getvalue()
    require(len(data) <= MAX_ZIP, "PRIVATE source-free handoff exceeds transfer bound")
    return data

def pack(cockpit: Path, outfile: Path) -> None:
    require(outfile.is_absolute() and outfile.parent == outfile.parent.resolve(strict=True)
            and not outfile.is_symlink() and not outfile.exists()
            and cockpit != outfile.parent and cockpit not in outfile.parents
            and outfile not in cockpit.parents, "Transport cannot modify source cockpit")
    install.owner_dir(outfile.parent)
    prior = read_cockpit.inspect(cockpit)
    mb = review.private_read(cockpit / "manifest.json")
    names = inventory(mb)
    require({p.name for p in cockpit.iterdir()} == set(names),
            "Source-free Cockpit contains unexpected original/client material")
    files = {name: review.private_read(cockpit / name) for name in sorted(names)}
    require(sum(len(v) for v in files.values()) <= MAX_ZIP
            and all(len(v) <= MAX_MEMBER for v in files.values()),
            "Original source-free handoff too large")
    # Original renderer is re-run after collecting all bytes to prevent
    # silently transferring a changed/stale private owner packet.
    require(read_cockpit.inspect(cockpit) == prior and
            all(review.private_read(cockpit / name) == raw for name, raw in files.items()),
            "Original private source-free handoff changed during packing")
    archive = zip_files(files)
    review.private_publish(outfile, archive)
    print("REVIEW_ONLY: original canonical source-free Cockpit packed privately:", outfile)
    print("This .luhz is UNENCRYPTED. Share only with separately authorized recipient.")

def unpack_bytes(raw: bytes, output: Path, unchanged=None) -> None:
    """Native source-free receipt directly from memory (no plaintext ZIP on disk)."""
    require(type(raw) is bytes and output.is_absolute() and
            output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "New private receiver folder required")
    install.owner_dir(output.parent)
    require(len(raw) <= MAX_ZIP, "Incoming private handoff too large")
    with zipfile.ZipFile(io.BytesIO(raw)) as zip_reader:
        names = zip_reader.namelist()
        require(len(names) == len(set(names)) and
                "manifest.json" in names and
                set(names) <= set(read_cockpit.DEFAULT | read_cockpit.HISTORY | {"manifest.json"}),
                "Incoming handoff member name inventory unsafe")
        require(all(not f.is_dir() and f.filename.isascii()
                    and len(f.filename) <= 65 and "/" not in f.filename
                    and f.file_size <= MAX_MEMBER and f.compress_size <= MAX_MEMBER
                    and (f.external_attr >> 16) == 0o100600
                    for f in zip_reader.infolist())
                and sum(f.file_size for f in zip_reader.infolist()) <= MAX_ZIP,
                "Private Cockpit ZIP member type/permission/bound unsafe")
        contents = {name: zip_reader.read(name) for name in names}
    require(set(contents) == set(inventory(contents["manifest.json"])),
            "Recipient source-free member inventory differs from original schema")
    stage = output.parent / (".lightup-sourcefree-unpack-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        for name, data in sorted(contents.items()):
            install.write_file(stage / name, data)
        # This invokes original unchanged source-free admission, including
        # native HTML reconstruction, original human COUNT schema and disclaimers.
        read_cockpit.inspect(stage)
        if unchanged is not None:
            require(unchanged(), "Original received handoff changed during acceptance")
        require(not output.exists(), "Another recipient directory appeared")
        workspace.exclusive_dir_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: complete original source-free Cockpit received:", output)
    print("No signed source/client, real consent, verified fix or authority.")


def unpack(archive: Path, output: Path) -> None:
    require(archive.is_absolute() and archive.parent == archive.parent.resolve(strict=True),
            "Incoming source-free handoff needs a literal private path")
    install.owner_dir(archive.parent)
    require(output != archive.parent and output not in archive.parents,
            "A received Cockpit cannot overwrite original archive ancestors")
    raw = install.read_owner_file(archive)
    unpack_bytes(raw, output, lambda: install.read_owner_file(archive) == raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline single-file source-free HUMAN Cockpit transport")
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("pack", help="Package fully admitted PRIVATE Cockpit as single 0600 file")
    p.add_argument("--cockpit", type=Path, required=True)
    p.add_argument("--output-file", type=Path, required=True)
    p = sub.add_parser("unpack", help="Atomically receive full exact native PRIVATE Cockpit")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "pack":
            pack(args.cockpit, args.output_file)
        else:
            unpack(args.archive, args.output_dir)
        return 2
    except (review.Hold, OSError, ValueError, TypeError, KeyError,
            zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        print("HOLD: PRIVATE source-free transport rejected: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
