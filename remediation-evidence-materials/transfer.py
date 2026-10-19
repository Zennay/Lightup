#!/usr/bin/env python3
"""PRIVATE offline transport for locally indexed LightUp evidence material.

Source owners remain immutable. This transfers *bytes*, not security truth,
proof of provenance, client permission, verification or scanner authority.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "remediation-evidence-bridge"))
sys.path.insert(0, str(ROOT / "remediation-evidence-custody"))

import workspace as human
import merge as native
from open_current import _current_rows

ORIGINAL = human.bridge.original
KIND = "lightup.private_human_evidence_material_transfer"
LIMIT = 4 * 1024 * 1024
MAX_SELECTION = 32768
MAX_MATERIAL = 2 * 1024 * 1024
MAX_TOTAL = 2500 * 1024
MAX_FILES = 12
WARNING = ("Locally selected private evidence bytes and HUMAN file hashes are not "
           "proof of collection provenance, verified findings, repaired systems, "
           "authorized retests, client consent, grants or release.")
META = {"finding_id", "sha256", "file_name", "byte_length", "content_base64"}
FIELDS = {"kind", "schema_version", "disposition", "source_contract",
          "source_sha256", "source_csv_sha256", "source_count",
          "client_reference", "engagement_reference", "inventory_sha256",
          "materials", "warning", *human.FLAGS}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def required_private_file(path: Path, suffix: str, vault, limit: int) -> bytes:
    if path.suffix.lower() != suffix:
        raise ValueError("Incorrect PRIVATE source file type.")
    return vault._private_input(path.expanduser().absolute(), limit)


def current_human(args, vault) -> tuple[dict, dict, dict]:
    # Original DomainStore authentication and current exact tenant + engagement
    # are performed every time, before any material is accepted or disclosed.
    current = ORIGINAL._authorized_summary(db=args.db, email=args.email,
            client_id=args.client_id, engagement_id=args.engagement_id)
    raw = current.encode("utf-8", "strict")
    sha, count = ORIGINAL._strict_summary(current)
    original_bytes = required_private_file(args.human, ".ltv", vault, vault.MAX_VAULT)
    password = vault._password("Existing original PRIVATE HUMAN vault passphrase: ", fresh=False)
    decrypted, mime, _ = vault._open(original_bytes, password)
    if mime != "application/json":
        raise ValueError("Original vault content type is not HUMAN JSON.")
    envelope, source, human_bytes = human._admit_workspace(decrypted)
    if (source != raw or envelope["original_csv_sha256"] != sha
            or type(envelope["original_finding_count"]) is not int
            or envelope["original_finding_count"] != count
            or envelope["client_reference"] != args.client_id
            or envelope["engagement_reference"] != args.engagement_id):
        raise ValueError("Original encrypted workroom is not the CURRENT authorized source.")
    original_digest, n = human._native_digest(raw)
    if n != count:
        raise ValueError("Original CSV membership cannot be reconciled.")
    packet = human._packet(human_bytes, source_digest=original_digest,
                           count=count, client=args.client_id,
                           engagement=args.engagement_id)
    indexed = native._records(packet, _current_rows(raw))
    return envelope, packet, indexed["attachments"]


def parse_selection(raw: bytes) -> list[dict]:
    obj = human._json(raw, MAX_SELECTION)
    if set(obj) != {"kind", "schema_version", "items"} or (
            obj["kind"] != "lightup.private_local_material_selection"
            or type(obj["schema_version"]) is not int
            or obj["schema_version"] != 1):
        raise ValueError("Selection schema is not canonical.")
    items = obj["items"]
    if type(items) is not list or not 1 <= len(items) <= MAX_FILES:
        raise ValueError("Select between one and twelve indexed files.")
    seen = set()
    for rec in items:
        if type(rec) is not dict or set(rec) != {"finding_id", "sha256", "path"}:
            raise ValueError("Selection item shape is invalid.")
        if type(rec["finding_id"]) is not str or type(rec["sha256"]) is not str or (
                type(rec["path"]) is not str or not rec["path"].startswith("/")
                or len(rec["path"]) > 1024 or "\x00" in rec["path"]):
            raise ValueError("Selection requires literal absolute private paths.")
        key = (rec["finding_id"], rec["sha256"])
        if key in seen:
            raise ValueError("Repeated original finding/file selection.")
        seen.add(key)
    return items


def pack(args, vault) -> None:
    envelope, packet, indexed = current_human(args, vault)
    selection = parse_selection(required_private_file(
        args.selection, ".json", vault, MAX_SELECTION))
    all_material = []
    total = 0
    # All-or-nothing: admit native original exact attachment inventory and
    # independently hash the actual owner-private file bytes.
    for item in selection:
        record = indexed.get((item["finding_id"], item["sha256"]))
        if record is None:
            raise ValueError("Selected material has no current original HUMAN fingerprint.")
        source_path = Path(item["path"])
        if source_path.is_dir():
            raise ValueError("Only private regular evidence files are accepted.")
        raw = vault._private_input(source_path, MAX_MATERIAL)
        if not raw or len(raw) != record["byte_length"] or digest(raw) != record["sha256"]:
            raise ValueError("Local file bytes differ from existing original HUMAN fingerprint.")
        total += len(raw)
        if total > MAX_TOTAL:
            raise ValueError("Selected private material exceeds 2.5 MiB bound.")
        all_material.append({
            "finding_id": record["finding_id"], "sha256": record["sha256"],
            "file_name": record["file_name"], "byte_length": record["byte_length"],
            "content_base64": base64.b64encode(raw).decode("ascii")})
    body = {
        "kind": KIND, "schema_version": 1,
        "disposition": "PRIVATE_UNVERIFIED_HUMAN_MATERIAL_ONLY",
        "source_contract": "lightup.finding_export._COLUMNS_v1",
        "source_sha256": packet["source_sha256"],
        "source_csv_sha256": envelope["original_csv_sha256"],
        "source_count": packet["source_count"],
        "client_reference": args.client_id,
        "engagement_reference": args.engagement_id,
        "inventory_sha256": digest(canonical(packet["attachments"])),
        "materials": all_material, "warning": WARNING,
        **{name: False for name in human.FLAGS},
    }
    payload = canonical(body)
    if len(payload) > vault.MAX_PLAIN:
        raise ValueError("Original vault capacity exceeded; use a smaller material selection.")
    replacement = vault._password("NEW private transfer passphrase: ", fresh=True)
    ciphertext = vault._seal(vault._inner(payload, "application/json"), replacement)
    out = args.output.expanduser().absolute()
    if out.suffix.lower() != ".ltv" or out == args.human.expanduser().absolute():
        raise ValueError("New distinct .ltv output required.")
    vault._exclusive_output(out, ciphertext)
    print("Created NEW encrypted 0600 PRIVATE evidence material transfer.")
    print("Locally selected original indexed files:", len(all_material))
    print("Total private bytes:", total)
    print("No targets, grants, network calls, retests or provenance claims.")


def parse_transfer(payload: bytes, packet: dict, envelope: dict) -> list[tuple[str, bytes, dict]]:
    data = human._json(payload, LIMIT)
    if (set(data) != FIELDS or canonical(data) != payload
            or data["kind"] != KIND
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or data["disposition"] != "PRIVATE_UNVERIFIED_HUMAN_MATERIAL_ONLY"
            or data["source_contract"] != "lightup.finding_export._COLUMNS_v1"
            or data["source_sha256"] != packet["source_sha256"]
            or data["source_csv_sha256"] != envelope["original_csv_sha256"]
            or type(data["source_count"]) is not int
            or data["source_count"] != packet["source_count"]
            or data["client_reference"] != packet["client_reference"]
            or data["engagement_reference"] != packet["engagement_reference"]
            or data["inventory_sha256"] != digest(canonical(packet["attachments"]))
            or data["warning"] != WARNING
            or any(data[flag] is not False for flag in human.FLAGS)):
        raise ValueError("PRIVATE material packet is not bound to current original HUMAN source.")
    materials = data["materials"]
    if type(materials) is not list or not 1 <= len(materials) <= MAX_FILES:
        raise ValueError("Invalid bounded encrypted material membership.")
    available = {(r["finding_id"],r["sha256"]):r for r in packet["attachments"]}
    seen = set()
    all_material = []
    total = 0
    for ordinal, item in enumerate(materials, 1):
        if type(item) is not dict or set(item) != META:
            raise ValueError("PRIVATE material record structure changed.")
        if any(type(item[k]) is not str for k in ("finding_id", "sha256", "file_name", "content_base64")):
            raise ValueError("PRIVATE material identity must be text.")
        if type(item["byte_length"]) is not int or not 0 < item["byte_length"] <= MAX_MATERIAL:
            raise ValueError("Invalid material byte count.")
        key = (item["finding_id"], item["sha256"])
        record = available.get(key)
        if key in seen or not record or any(item[k] != record[k] for k in
                            ("finding_id", "sha256", "file_name", "byte_length")):
            raise ValueError("Local file differs from exact original HUMAN fingerprint.")
        seen.add(key)
        encoded = item["content_base64"]
        if len(encoded) > MAX_MATERIAL * 2:
            raise ValueError("Oversized encoded file.")
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded or (
                len(raw) != item["byte_length"] or digest(raw) != item["sha256"]):
            raise ValueError("Original HUMAN fingerprint is not matched by transferred bytes.")
        total += len(raw)
        if total > MAX_TOTAL:
            raise ValueError("Encrypted material exceeds original bounded transport.")
        # Never trust the original filename for the filesystem path.
        all_material.append((f"material-{ordinal:02d}.bin", raw, record))
    return all_material


def private_directory(path: Path) -> Path:
    dest = path.expanduser().absolute()
    if dest.exists() or dest.is_symlink():
        raise ValueError("Extraction destination must not already exist.")
    parent = dest.parent
    mode = parent.stat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or (
            mode.st_mode & 0o077) or parent.is_symlink():
        raise ValueError("A real owner-private 0700 parent is required.")
    return dest


def unpack(args, vault) -> None:
    envelope, packet, indexed = current_human(args, vault)
    cipher = required_private_file(args.package, ".ltv", vault, vault.MAX_VAULT)
    password = vault._password("Received PRIVATE evidence transfer passphrase: ", fresh=False)
    payload, mime, _ = vault._open(cipher, password)
    if mime != "application/json":
        raise ValueError("Received file is not a native encrypted JSON transfer.")
    files = parse_transfer(payload, packet, envelope)
    dest = private_directory(args.output_dir)
    # No original path is used; create a fresh 0700 directory and 0600 files.
    # Build manifest in memory only and clean partial new output if publication fails.
    metadata = {
        "kind": "lightup.private_local_material_receipt",
        "schema_version": 1, "disposition": "PRIVATE_HUMAN_UNVERIFIED_ONLY",
        "source_sha256": packet["source_sha256"],
        "files": [{"stored_as":name, "finding_id":rec["finding_id"],
                   "original_file_name":rec["file_name"], "sha256":rec["sha256"],
                   "byte_length":rec["byte_length"]} for name,_,rec in files],
        "warning": WARNING,
        **{name:False for name in human.FLAGS}
    }
    created = []
    os.mkdir(dest, 0o700)
    try:
        for name, data, _ in files:
            vault._exclusive_output(dest / name, data)
            created.append(name)
        vault._exclusive_output(dest / "PRIVATE-receipt.json", canonical(metadata))
        created.append("PRIVATE-receipt.json")
    except BaseException:
        for name in created:
            (dest / name).unlink(missing_ok=True)
        dest.rmdir()
        raise
    print("Extracted PRIVATE material to NEW owner-only 0700 directory.")
    print("Files:", len(files), "as neutral names; 0600 receipt binds original HUMAN records.")
    print("No verified remediation, active assessment, grant, consent or retest.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("pack", "unpack"):
        p = sub.add_parser(action)
        for name in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + name, required=True)
        p.add_argument("--human", required=True, type=Path,
                       help="Original existing encrypted current-source HUMAN .ltv")
        if action == "pack":
            p.add_argument("--selection", required=True, type=Path,
                           help="Owner-private 0600 JSON listing original IDs, SHA, absolute evidence paths")
            p.add_argument("--output", required=True, type=Path,
                           help="NEW encrypted 0600 .ltv; no overwrite")
        else:
            p.add_argument("--package", required=True, type=Path,
                           help="Received encrypted 0600 material transfer .ltv")
            p.add_argument("--output-dir", required=True, type=Path,
                           help="NEW owner-private folder under existing 0700 parent")
        p.add_argument("--ack-private-material", action="store_true",
                       help="Explicitly confirm this includes PRIVATE actual material bytes")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Explicit PRIVATE byte transfer acknowledgement and interactive terminal required.")
        if args.action == "pack" and (args.output == args.selection or args.output == args.human):
            raise ValueError("Never overwrite any original private record.")
        vault = ORIGINAL._vault()
        (pack if args.action == "pack" else unpack)(args, vault)
        return 0
    except Exception:
        print("HUMAN HOLD: No material transfer completed. Check original current account/source, "
              "private file permissions, fingerprints, limits, and output path.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
