#!/usr/bin/env python3
"""PRIVATE HUMAN evidence receipt and encrypted sender-return coordination.

The receiver acknowledges local bytes and proposes human follow-up only.
An original LightUp account READ is mandatory on both endpoints, but no source
claim, local note or return packet authenticates client consent or security.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import sys

import transfer

vault_owner = transfer.ORIGINAL
KIND = "lightup.private_human_evidence_material_receipt_reply"
FIELDS = {"kind", "schema_version", "disposition", "source_contract",
          "source_sha256", "source_csv_sha256", "source_count",
          "client_reference", "engagement_reference", "inventory_sha256",
          "transfer_sha256", "human_items", "warning", *transfer.human.FLAGS}
ITEM_FIELDS = {"finding_id", "sha256", "human_stage", "human_reviewer",
               "human_note", "recorded_utc"}
STAGES = {"received_unverified", "needs_human_followup", "human_hold"}
WARNING = ("Recipient-entered HUMAN-only receipt, not evidence of verified remediation, "
           "actual vulnerability, client approval, signed provenance, verified "
           "identity, assessment grant, scan, retest or release.")
MAX_REPLY = 30000
MAX_LABEL = 120
MAX_NOTE = 800


def _decrypt(path: Path, label: str, vault) -> tuple[bytes, bytes]:
    encoded = transfer.required_private_file(path, ".ltv", vault, vault.MAX_VAULT)
    password = vault._password(label, fresh=False)
    raw, mime, _ = vault._open(encoded, password)
    if mime != "application/json":
        raise ValueError("Expected native authenticated private JSON container.")
    return raw, password


def _source(args, vault) -> tuple[dict, dict, dict, str]:
    a, packet, indexed, original_key_hash = transfer.current_human(
        args, vault, keep_passphrase_fingerprint=True)
    return a, packet, indexed, original_key_hash


def _transfer(args, vault, envelope: dict, packet: dict) -> tuple[bytes,list,bytes]:
    raw, key = _decrypt(args.transfer,
        "Existing PRIVATE encrypted evidence transport passphrase: ", vault)
    # This uses the original exact CURRENT account/client/engagement and full
    # source/attachment fingerprint admission, not a claimed sender identity.
    files = transfer.parse_transfer(raw, packet, envelope)
    return raw, files, key


def _local_contents(folder: Path, files: list, packet: dict, vault) -> None:
    target = folder.expanduser().absolute()
    info = os.lstat(target)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Received evidence folder is not original owner-private 0700.")
    receipt_bytes = vault._private_input(target / "PRIVATE-receipt.json", MAX_REPLY)
    receipt = transfer.human._json(receipt_bytes, MAX_REPLY)
    if transfer.canonical(receipt) != receipt_bytes:
        raise ValueError("Received original PRIVATE receipt is not byte-canonical.")
    expected_fields = {"kind", "schema_version", "disposition", "source_sha256",
                       "files", "warning", *transfer.human.FLAGS}
    if (set(receipt) != expected_fields
        or receipt.get("kind") != "lightup.private_local_material_receipt"
        or type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1
        or receipt.get("disposition") != "PRIVATE_HUMAN_UNVERIFIED_ONLY"
        or receipt.get("source_sha256") != packet["source_sha256"]
        or receipt.get("warning") != transfer.WARNING
        or any(receipt[k] is not False for k in transfer.human.FLAGS)
        or type(receipt.get("files")) is not list
        or len(receipt["files"]) != len(files)):
        raise ValueError("Received original file index and PRIVATE receipt do not match.")
    listed = {"PRIVATE-receipt.json"}
    for ordinal, ((expected_name, bytes_, original), row) in enumerate(
            zip(files, receipt["files"], strict=True), 1):
        expected_fields = {"stored_as", "finding_id", "original_file_name",
                           "sha256", "byte_length"}
        if type(row) is not dict or set(row) != expected_fields:
            raise ValueError("Original PRIVATE material receipt record has changed.")
        wanted = {
            "stored_as": expected_name, "finding_id": original["finding_id"],
            "original_file_name": original["file_name"],
            "sha256": original["sha256"], "byte_length": original["byte_length"]}
        if row != wanted:
            raise ValueError("PRIVATE local receipt differs from encrypted original material.")
        current = vault._private_input(target / expected_name, transfer.MAX_MATERIAL)
        if current != bytes_:
            raise ValueError("Received local bytes no longer match encrypted original material.")
        listed.add(expected_name)
    if set(os.listdir(target)) != listed:
        raise ValueError("Unexpected or missing file in private evidence receipt directory.")


def _human_text(value: str, maxlen: int, label: str, *, required: bool=False) -> str:
    transfer.native._text(value, maxlen, required=required)
    if value != value.strip() or "\r" in value or "\n" in value:
        raise ValueError("Noncanonical private HUMAN " + label)
    return value


def _stage(selection: str) -> str:
    return {"1":"received_unverified","2":"needs_human_followup",
            "3":"human_hold"}.get(selection, "")


def _human_rows(files: list) -> list[dict]:
    print("PRIVATE MATERIAL RECEIPT — HUMAN-only, not verified security or identity.")
    alias = _human_text(input("Private reviewer alias (optional): "), MAX_LABEL, "reviewer")
    results = []
    for ordinal, (_, _, original) in enumerate(files, 1):
        # !a prints an escaped representation; untrusted source labels do not
        # become terminal control sequences.
        print(f'{ordinal:>2}. Original indexed file: {original["finding_id"]!a} '
              f'· {original["file_name"]!a} · sha256:{original["sha256"][:16]}…')
        print("  1 = received, unverified; 2 = needs human follow-up; 3 = human HOLD")
        status = _stage(input("  HUMAN status (1/2/3, empty cancels): ").strip())
        if status not in STAGES:
            raise ValueError("Human receipt must be explicitly marked for every file.")
        note = _human_text(input("  Private HUMAN note (max 800, optional): "),
                           MAX_NOTE, "note")
        recorded = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z")
        results.append({
            "finding_id": original["finding_id"], "sha256": original["sha256"],
            "human_stage": status, "human_reviewer": alias,
            "human_note": note, "recorded_utc": recorded
        })
    return results


def _reply_packet(reply: bytes, transport: bytes, files: list,
                  envelope: dict, packet: dict) -> list[dict]:
    obj = transfer.human._json(reply, MAX_REPLY)
    if (set(obj) != FIELDS or transfer.canonical(obj) != reply
        or obj["kind"] != KIND or type(obj["schema_version"]) is not int
        or obj["schema_version"] != 1
        or obj["disposition"] != "PRIVATE_HUMAN_RECEIPT_NOT_VERIFIED"
        or obj["source_contract"] != "lightup.finding_export._COLUMNS_v1"
        or obj["source_sha256"] != packet["source_sha256"]
        or obj["source_csv_sha256"] != envelope["original_csv_sha256"]
        or type(obj["source_count"]) is not int or obj["source_count"] != packet["source_count"]
        or obj["client_reference"] != packet["client_reference"]
        or obj["engagement_reference"] != packet["engagement_reference"]
        or obj["inventory_sha256"] != transfer.digest(
            transfer.canonical(packet["attachments"]))
        or obj["transfer_sha256"] != transfer.digest(transport)
        or obj["warning"] != WARNING
        or any(obj[f] is not False for f in transfer.human.FLAGS)):
        raise ValueError("HUMAN reply is not bound to exact present source and material.")
    rows = obj["human_items"]
    if type(rows) is not list or len(rows) != len(files):
        raise ValueError("PRIVATE HUMAN reply is not complete for received files.")
    for human_row, (_, _, original) in zip(rows, files, strict=True):
        if type(human_row) is not dict or set(human_row) != ITEM_FIELDS:
            raise ValueError("Unexpected HUMAN return fields.")
        if (type(human_row["finding_id"]) is not str
            or human_row["finding_id"] != original["finding_id"]
            or type(human_row["sha256"]) is not str
            or human_row["sha256"] != original["sha256"]
            or type(human_row["human_stage"]) is not str
            or human_row["human_stage"] not in STAGES):
            raise ValueError("HUMAN reply item is not original source-bound.")
        _human_text(human_row["human_reviewer"], MAX_LABEL, "reviewer")
        _human_text(human_row["human_note"], MAX_NOTE, "note")
        transfer.native._stamp(human_row["recorded_utc"])
    return rows


def prepare(args, vault) -> None:
    envelope, packet, indexed, original_key_hash = _source(args, vault)
    raw, files, material_password = _transfer(args, vault, envelope, packet)
    _local_contents(args.folder, files, packet, vault)
    rows = _human_rows(files)
    seal_reply(args.output, vault, envelope, packet, raw, files,
               material_password, original_key_hash, rows)


def seal_reply(output: Path, vault, envelope: dict, packet: dict,
               raw: bytes, files: list, material_password: bytes,
               original_key_hash: str, rows: list[dict]) -> None:
    """Seal a separately HUMAN-acknowledged original-source-bound private reply."""
    obj = {
        "kind": KIND, "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_RECEIPT_NOT_VERIFIED",
        "source_contract": "lightup.finding_export._COLUMNS_v1",
        "source_sha256": packet["source_sha256"],
        "source_csv_sha256": envelope["original_csv_sha256"],
        "source_count": packet["source_count"],
        "client_reference": packet["client_reference"],
        "engagement_reference": packet["engagement_reference"],
        "inventory_sha256": transfer.digest(transfer.canonical(packet["attachments"])),
        "transfer_sha256": transfer.digest(raw),
        "human_items": rows,
        "warning": WARNING,
        **{f:False for f in transfer.human.FLAGS}
    }
    serialized = transfer.canonical(obj)
    _reply_packet(serialized, raw, files, envelope, packet)
    replacement = vault._password("New PRIVATE HUMAN return passphrase: ", fresh=True)
    if transfer.digest(replacement) in (original_key_hash, transfer.digest(material_password)):
        raise ValueError("HUMAN return passphrase must differ from original and received transfer.")
    result = vault._seal(vault._inner(serialized, "application/json"), replacement)
    vault._exclusive_output(output.expanduser().absolute(), result)
    print("Created NEW encrypted PRIVATE HUMAN receipt reply. No original attachment state updated.")
    print("Human labels: ", dict(Counter(r["human_stage"] for r in rows)))
    print("No client consent, scan, verified remediation, signed proof or grant.")


def inspect(args, vault) -> None:
    envelope, packet, indexed, _ = _source(args, vault)
    raw, files, material_password = _transfer(args, vault, envelope, packet)
    reply, _ = _decrypt(args.reply, "Encrypted PRIVATE HUMAN receipt reply passphrase: ", vault)
    rows = _reply_packet(reply, raw, files, envelope, packet)
    print("SOURCE-BOUND PRIVATE HUMAN RECEIPT (original current source matched)")
    print("Locally documented evidence receipts:", len(rows))
    print("Human-only outcome counts:", dict(Counter(r["human_stage"] for r in rows)))
    if args.ack_private_details:
        print("PRIVATE source labels and HUMAN notes — not verified provenance:")
        for row in rows:
            print("  ", ascii(row["finding_id"]), row["sha256"][:16]+"…",
                  row["human_stage"], ascii(row["human_reviewer"]), ascii(row["human_note"]))
    print("No original HUMANS applied; no security evidence, retest or authorization certified.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("prepare", "inspect"):
        p = sub.add_parser(action)
        for name in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + name, required=True)
        p.add_argument("--human", type=Path, required=True,
                       help="Current matching original encrypted HUMAN source .ltv")
        p.add_argument("--transfer", type=Path, required=True,
                       help="Original encrypted PRIVATE material transfer .ltv")
        if action == "prepare":
            p.add_argument("--folder", type=Path, required=True,
                           help="Private extracted 0700 folder with exact native receipt")
            p.add_argument("--output", type=Path, required=True,
                           help="NEW 0600 encrypted PRIVATE HUMAN receipt reply .ltv")
        else:
            p.add_argument("--reply", type=Path, required=True,
                           help="Existing encrypted recipient HUMAN reply .ltv")
            p.add_argument("--ack-private-details", action="store_true",
                           help="Deliberately show sensitive original notes on private TTY")
        p.add_argument("--ack-private-receipt", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_receipt or not sys.stdin.isatty():
            raise ValueError("PRIVATE interactive terminal and explicit operator acknowledgement required.")
        if args.action == "prepare" and args.output.suffix.lower() != ".ltv":
            raise ValueError("A new encrypted PRIVATE .ltv reply is required.")
        vault = vault_owner._vault()
        (prepare if args.action == "prepare" else inspect)(args, vault)
        return 0
    except Exception:
        print("HUMAN HOLD: no valid original-current, locally matched private HUMAN receipt. "
              "No source or original HUMAN state changed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
