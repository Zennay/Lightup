#!/usr/bin/env python3
"""PRIVATE offline batch HUMAN review: neutral TSV edits -> NEW encrypted plan.

Reauthenticates the ORIGINAL current LightUp account/client/engagement; checks
original encrypted HUMAN source, all actual evidence bytes, native receipt and
the prior encrypted review on BOTH export and import. No scanner, deletion,
grants, consent, original Apply, retest or real legal hold release.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import retention as native

original = native.transfer
MAX_TSV = 32768
COLUMNS = ("source_sha256", "receipt_sha256", "prior_plan_sha256",
           "stored_as", "sha256", "byte_length", "decision", "review_on", "note_edit")


def _bound(args, vault):
    _, packet, indexed, original_key = original.current_human(
        args, vault, keep_passphrase_fingerprint=True)
    previous, plan_key = native._load_current_plan(args, vault, packet, indexed)
    files, receipt_sha = native._read_material(args.directory, packet, indexed, vault)
    if args.plan.suffix.lower() != ".ltv":
        raise ValueError("Native encrypted prior HUMAN review .ltv required.")
    cipher = vault._private_input(args.plan.expanduser().absolute(), vault.MAX_VAULT)
    return (packet, previous, files, receipt_sha, original.digest(cipher),
            original_key, plan_key)


def _template(packet: dict, previous: list, receipt_sha: str, plan_sha: str) -> bytes:
    lines = ["\t".join(COLUMNS)]
    for row in previous:
        cols = [packet["source_sha256"], receipt_sha, plan_sha,
                row["stored_as"], row["sha256"], str(row["byte_length"]),
                row["decision"], row["review_on"], ""]
        if any(type(s) is not str or not s.isascii() or any(c in s for c in "\t\r\n")
               for s in cols):
            raise ValueError("PRIVATE template identity field is not canonical.")
        lines.append("\t".join(cols))
    raw = ("\n".join(lines) + "\n").encode("ascii")
    if not 0 < len(raw) <= MAX_TSV:
        raise ValueError("PRIVATE HUMAN batch template too large.")
    return raw


def _edited(raw: bytes, packet: dict, old: list,
            receipt_sha: str, plan_sha: str) -> list:
    if not 0 < len(raw) <= MAX_TSV or b"\r" in raw or b"\x00" in raw:
        raise ValueError("Canonical bounded LF private TSV required.")
    value = raw.decode("utf-8", "strict")
    if not value.endswith("\n"):
        raise ValueError("Whole private TSV must have a final LF.")
    lines = value[:-1].split("\n")
    if len(lines) != len(old) + 1 or lines[0] != "\t".join(COLUMNS):
        raise ValueError("Original full review row order or header changed.")
    records = []
    for ordinal, (line, previous) in enumerate(zip(lines[1:], old), 1):
        fields = line.split("\t")
        if len(fields) != len(COLUMNS):
            raise ValueError("Exact private HUMAN column count required.")
        rec = dict(zip(COLUMNS, fields))
        expected = {
            "source_sha256": packet["source_sha256"],
            "receipt_sha256": receipt_sha,
            "prior_plan_sha256": plan_sha,
            "stored_as": previous["stored_as"],
            "sha256": previous["sha256"],
            "byte_length": str(previous["byte_length"]),
        }
        if any(rec[name] != value for name, value in expected.items()):
            raise ValueError("Original source, actual file, receipt or previous plan changed.")
        if rec["decision"] not in native.DECISIONS:
            raise ValueError("Invalid HUMAN review status.")
        review_date = native._review_day(rec["review_on"])
        if not rec["note_edit"]:
            note = previous["note"]
        elif rec["note_edit"] == "<clear>":
            note = ""
        else:
            note = native._safe_human_note(rec["note_edit"])
        updated = {**previous, "decision": rec["decision"],
                   "review_on": review_date, "note": note}
        records.append({
            "item": updated, "ordinal": ordinal,
            "changed": any(updated[k] != previous[k]
                           for k in ("decision", "review_on", "note")),
            "hold_downgrade": (previous["decision"] == "legal_hold"
                               and updated["decision"] != "legal_hold"),
        })
    return records


def _export(args, vault):
    packet, old, files, receipt, plan_sha, _, _ = _bound(args, vault)
    output = args.output.expanduser().absolute()
    if output.suffix.lower() != ".tsv" or output == args.plan.expanduser().absolute():
        raise ValueError("NEW separate 0600 PRIVATE .tsv output required.")
    vault._exclusive_output(output, _template(packet, old, receipt, plan_sha))
    print("Created NEW source- and actual-material-bound PRIVATE 0600 bulk editor.")
    print("Original neutral indexed rows:", len(old), "· no private notes exported.")
    print("Edit decision/review_on/note_edit only; blank note_edit preserves original.")
    print("Use a LOCAL offline editor, not a synced spreadsheet provider.")


def _prepare(args, vault):
    packet, old, files, receipt, plan_sha, source_key, prior_key = _bound(args, vault)
    edited_path = args.edited.expanduser().absolute()
    if edited_path.suffix.lower() != ".tsv":
        raise ValueError("Actual PRIVATE edit must be original template .tsv.")
    records = _edited(vault._private_input(edited_path, MAX_TSV),
                      packet, old, receipt, plan_sha)
    modified = [r for r in records if r["changed"]]
    if not modified:
        raise ValueError("No original HUMAN review changes found.")
    hold_changes = [r for r in modified if r["hold_downgrade"]]
    print("PRIVATE HUMAN change preview. No grant, Apply or legal conclusion.")
    print("Original private material:", len(old), "· changed HUMAN rows:", len(modified),
          "· HUMAN hold-label downgrades:", len(hold_changes))
    for entry in modified:
        old_item = old[entry["ordinal"] - 1]
        new_item = entry["item"]
        print("NEUTRAL ROW", entry["ordinal"], "· HUMAN", old_item["decision"],
              "→", new_item["decision"], "· date", old_item["review_on"], "→",
              new_item["review_on"], "· PRIVATE note",
              "changed" if old_item["note"] != new_item["note"] else "unchanged",
              "· EXPLICIT HOLD-LABEL ACK REQUIRED" if entry["hold_downgrade"] else "")
    return packet, files, receipt, source_key, prior_key, records, modified, hold_changes


def _preview(args, vault):
    _prepare(args, vault)
    print("All original current source, encrypted plan and actual material bytes admitted.")
    print("No new file or original HUMAN status created by this preview.")


def _import(args, vault):
    packet, files, receipt, source_key, prior_key, records, modified, hold_changes = (
        _prepare(args, vault))
    edited_path = args.edited.expanduser().absolute()
    for rec in hold_changes:
        command = input(
            "Row " + str(rec["ordinal"]) +
            ': type "RECORD HUMAN REVIEW ONLY" to change unverified HUMAN '
            "hold label (NEVER actual legal release): ")
        if command != "RECORD HUMAN REVIEW ONLY":
            raise ValueError("Independent HUMAN legal-hold acknowledgement missing.")
    if input('Type "SEAL PRIVATE BATCH" for a NEW encrypted HUMAN plan: ') != (
        "SEAL PRIVATE BATCH"
    ):
        raise ValueError("Explicit HUMAN bulk-encryption acknowledgement missing.")
    items = [r["item"] for r in records]
    body = {
        "kind": native.KIND, "schema_version": 1,
        "disposition": native.DISPOSITION,
        "source_sha256": packet["source_sha256"],
        "receipt_sha256": receipt, "items": items,
        "warning": native.WARNING,
        **{flag: False for flag in original.human.FLAGS},
    }
    plain = original.canonical(body)
    if len(plain) > native.MAX_PLAN:
        raise ValueError("Native original HUMAN encrypted review capacity exceeded.")
    native._admit_plan(plain, files, receipt, packet)
    secret = vault._password("NEW separate PRIVATE batch plan passphrase: ", fresh=True)
    if original.digest(secret) in (source_key, prior_key):
        raise ValueError("Different private passphrase required from both old vaults.")
    output = args.output.expanduser().absolute()
    if output.suffix.lower() != ".ltv" or output in {
        args.human.expanduser().absolute(), args.plan.expanduser().absolute(), edited_path
    }:
        raise ValueError("NEW distinct encrypted 0600 .ltv required.")
    vault._exclusive_output(
        output, vault._seal(vault._inner(plain, "application/json"), secret))
    print("Created NEW 0600 original-source-bound encrypted HUMAN plan.")
    print("Human review rows changed:", len(modified))
    print("Original evidence, previous encrypted plan, native Casework and grants untouched.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for operation in ("export", "preview", "import"):
        p = sub.add_parser(operation)
        for k in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + k, required=True)
        for k in ("human", "directory", "plan"):
            p.add_argument("--" + k, type=Path, required=True)
        if operation != "preview":
            p.add_argument("--output", type=Path, required=True)
        if operation in ("preview", "import"):
            p.add_argument("--edited", type=Path, required=True)
        p.add_argument("--ack-private-material", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Actual PRIVATE HUMAN interactive terminal required.")
        vault = original.ORIGINAL._vault()
        {"export": _export, "preview": _preview, "import": _import}[args.action](args, vault)
        return 0
    except Exception:
        print("HUMAN HOLD: No complete original-source-bound PRIVATE batch review "
              "published. Check genuine current account/source, full evidence "
              "bytes, immutable TSV, human confirmations and output privacy.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
