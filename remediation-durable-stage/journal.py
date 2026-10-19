#!/usr/bin/env python3
"""Durable LOCAL HUMAN draft handoff journal on original LightUp evidence sources.

A fail-closed single-host convenience fence for original-native encrypted HUMAN
follow-up drafts. It is not a lock across devices, a grant or proof of Apply.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "remediation-evidence-retention"))
import request_handoff as bridge
import reconcile as native_status
import report as local_dashboard
import handoff_review as delivery

source = bridge.source
original = bridge.original
KIND = "lightup.local_human_retention_stage_journal"
MAX_JOURNAL = 64 * 1024
MAX_CYCLES = 64
STATES = ("pending", "staged", "reviewed", "aborted_unpublished")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key(packet: dict, receipt_sha: str) -> str:
    # Omit plan SHA: switching/renewing HUMAN plans must not evade the journal.
    return _digest(original.canonical({
        "client": packet["client_reference"],
        "engagement": packet["engagement_reference"],
        "receipt_sha256": receipt_sha,
        "source_sha256": packet["source_sha256"],
    }))


def _source(args, vault):
    envelope, packet, indexed, items, old_hash, plan_hash = bridge._load(args, vault)
    _, receipt_sha = source._read_material(args.directory, packet, indexed, vault)
    return envelope, packet, indexed, items, old_hash, plan_hash, _key(packet, receipt_sha)


def _owned_regular(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ValueError("Expected an owner-private nonlinked regular file.")


@contextmanager
def _locked(directory: Path):
    folder = source._hold_if_not_private_directory(directory)
    lock = folder / ".human-stage.lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        _owned_regular(lock)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield folder
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read(folder: Path, key: str, vault) -> dict:
    path = folder / (key + ".json")
    if not path.exists() and not path.is_symlink():
        return {"kind": KIND, "schema_version": 1, "source_key": key, "cycles": []}
    _owned_regular(path)
    raw = vault._private_input(path, MAX_JOURNAL)
    document = original.human._json(raw, MAX_JOURNAL)
    if (type(document) is not dict or set(document) != {
            "kind", "schema_version", "source_key", "cycles"}
            or document["kind"] != KIND
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["source_key"] != key
            or original.canonical(document) != raw):
        raise ValueError("Private local journal changed, HOLD.")
    cycles = document["cycles"]
    if type(cycles) is not list or len(cycles) > MAX_CYCLES:
        raise ValueError("Private HUMAN cycle history invalid.")
    for record in cycles:
        if (type(record) is not dict or set(record) != {
                "state", "output", "sha256", "requests", "created", "updated"}
                or record["state"] not in STATES
                or type(record["output"]) is not str
                or type(record["sha256"]) is not str
                or type(record["requests"]) is not list
                or len(record["requests"]) > original.native.MAX_REQUESTS
                or any(type(ref) is not str or len(ref) != 64
                       or any(c not in "0123456789abcdef" for c in ref)
                       for ref in record["requests"])
                or type(record["created"]) is not str
                or type(record["updated"]) is not str):
            raise ValueError("Malformed original HUMAN local journal cycle.")
    return document


def _write(folder: Path, key: str, document: dict) -> None:
    payload = original.canonical(document)
    if len(payload) > MAX_JOURNAL:
        raise ValueError("Local journal capacity reached; retain existing records.")
    target = folder / (key + ".json")
    if target.exists() or target.is_symlink():
        _owned_regular(target)
    temporary = folder / (".writing-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        folder_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _ref(row: dict) -> str:
    # In the 0600 journal keep only a hash of original HUMAN request identity.
    return _digest(original.canonical({
        "finding_id": row["finding_id"], "linked_sha256": row["linked_sha256"],
        "request_id": row["request_id"],
    }))


def _closed(record: dict, packet: dict) -> bool:
    rows = packet.get("human_requests", [])
    if type(rows) is not list:
        raise ValueError("Canonical HUMAN requests required.")
    closed = {_ref(row) for row in rows if row["human_stage"] == "closed_human"}
    return bool(record["requests"]) and all(ref in closed for ref in record["requests"])


def _inspect(document: dict, packet: dict) -> None:
    latest = document["cycles"][-1] if document["cycles"] else None
    print("Original source and actual PRIVATE evidence bytes checked.")
    print("LOCAL HUMAN handoff cycles:", len(document["cycles"]))
    print("Latest local state:", latest["state"] if latest else "empty")
    if latest:
        print("Previous native HUMAN draft records:", len(latest["requests"]))
        print("Original current HUMAN closed markers for latest cycle:",
              _closed(latest, packet) if latest["requests"] else False)
    print("Only local HUMAN bookkeeping. No native Apply, client consent or execution authority.")


def _stage(args, vault, folder, journal, current) -> None:
    envelope, packet, indexed, items, old_hash, plan_hash, key = current
    cycles = journal["cycles"]
    if len(cycles) >= MAX_CYCLES:
        raise ValueError("Local HUMAN journal capacity reached.")
    if cycles and cycles[-1]["state"] not in ("reviewed", "aborted_unpublished"):
        raise ValueError("Unresolved prior HUMAN draft/pending invocation: HOLD.")
    if any(row["state"] == "reviewed" and not _closed(row, packet) for row in cycles):
        raise ValueError("Earlier original HUMAN closure not in current source: HOLD.")
    candidates, blocked, due = bridge._eligible(packet, items)
    print("Current due original HUMAN findings:", due, "· existing open:", blocked,
          "· available:", len(candidates))
    if not candidates:
        raise ValueError("No new native HUMAN request group can be prepared.")
    chosen = bridge._choose(candidates)
    if input('Type "STAGE DURABLE HUMAN DRAFT" to prepare a LOCAL-only draft: ') != (
            "STAGE DURABLE HUMAN DRAFT"):
        raise ValueError("No deliberate HUMAN draft acknowledgment.")
    out = args.output.expanduser().absolute()
    if (out.suffix.lower() != ".ltv" or out in {
            args.human.expanduser().absolute(), args.plan.expanduser().absolute()}
            or out.exists() or out.is_symlink()):
        raise ValueError("Distinct unoccupied encrypted HUMAN .ltv output required.")
    # Keep confidential original-native draft paths under a real private owner
    # directory; source material and journal paths have the same no-symlink rule.
    source._hold_if_not_private_directory(out.parent)
    # A fresh ORIGINAL authenticated read after the human interaction. If current
    # source/requests/plan/bytes drift, there is no journal or encrypted output.
    newer = _source(args, vault)
    if (newer[6] != key or newer[1] != packet or newer[3] != items
            or newer[2] != indexed):
        raise ValueError("Original current source/HUMAN/material changed during review.")
    envelope, packet, indexed, items, old_hash, plan_hash, key = newer
    drafts = bridge._build(packet, chosen)
    updated = dict(packet)
    updated["schema_version"] = 2
    updated["human_requests"] = [*packet.get("human_requests", []), *drafts]
    csv = original.human._unb64(
        envelope["original_csv_base64"], original.ORIGINAL.MAX_CSV_BYTES)
    original.native._records(updated, original._current_rows(csv))
    workroom = original.human._make_workspace(
        csv, original.canonical(updated),
        packet["client_reference"], packet["engagement_reference"])
    password = vault._password("NEW PRIVATE native HUMAN draft passphrase: ", fresh=True)
    if original.digest(password) in (old_hash, plan_hash):
        raise ValueError("Never reuse an original source or retention-plan secret.")
    entry = {"state": "pending", "output": str(out), "sha256": "",
             "requests": [_ref(row) for row in drafts],
             "created": _utc(), "updated": _utc()}
    cycles.append(entry)
    _write(folder, key, journal)  # durable intent BEFORE encrypted output
    vault._exclusive_output(out, vault._seal(vault._inner(workroom, "application/json"), password))
    _owned_regular(out)
    entry["sha256"] = _digest(vault._private_input(out, vault.MAX_VAULT))
    entry["state"] = "staged"
    entry["updated"] = _utc()
    _write(folder, key, journal)
    print("New original-native encrypted 0600 HUMAN draft created:", len(drafts),
          "· durable LOCAL stage recorded.")
    print("Next: separate original source-bound Preview + HUMAN Apply, then closed"
          " HUMAN workroom review. No Apply performed here.")


def _recover(args, vault, folder, journal, current) -> None:
    """Complete a crash-interrupted local entry only from an admitted encrypted original draft."""
    envelope, packet, indexed, items, _, _, key = current
    cycles = journal["cycles"]
    if not cycles or cycles[-1]["state"] != "pending":
        raise ValueError("No interrupted pending HUMAN draft.")
    entry = cycles[-1]
    draft_path = Path(entry["output"])
    source._hold_if_not_private_directory(draft_path.parent)
    _owned_regular(draft_path)
    # The CURRENT native HUMAN source may legitimately contain the staged
    # request by now. Never require a stale baseline prefix for recovery.
    # Re-admit exact encrypted native source/attachment/request identities
    # against the pending journal, including after a separate HUMAN handoff.
    rows, totals = delivery.collect(
        entry, args, vault, envelope, packet, pending_recovery=True)
    if totals["selected"] != len(entry["requests"]):
        raise ValueError("Interrupted original-native HUMAN selection incomplete.")
    if input('Type "RECOVER ENCRYPTED HUMAN DRAFT" after private inspection: ') != (
            "RECOVER ENCRYPTED HUMAN DRAFT"):
        raise ValueError("No HUMAN recovery acknowledgment.")
    entry["sha256"] = _digest(vault._private_input(draft_path, vault.MAX_VAULT))
    entry["state"] = "staged"
    entry["updated"] = _utc()
    _write(folder, key, journal)
    print("Interrupted original-native encrypted HUMAN draft recovered in LOCAL journal.")
    print("It is still HUMAN-only, not an applied or consented original request.")


def _resolve(args, vault, folder, journal, current) -> None:
    envelope, packet, indexed, items, old_hash, plan_hash, key = current
    cycles = journal["cycles"]
    if not cycles or cycles[-1]["state"] not in ("pending", "staged"):
        raise ValueError("No unresolved original HUMAN stage in this local journal.")
    entry = cycles[-1]
    destination = Path(entry["output"])
    source._hold_if_not_private_directory(destination.parent)
    if entry["state"] == "pending" and not destination.exists() and not destination.is_symlink():
        print("A pending previous invocation has no output at its recorded path.")
        if input('Type "CONFIRM NO DRAFT PUBLISHED" after independent PRIVATE review: ') != (
                "CONFIRM NO DRAFT PUBLISHED"):
            raise ValueError("HUMAN review needed; retaining pending HOLD.")
        entry["state"] = "aborted_unpublished"
    else:
        _owned_regular(destination)
        if not entry["sha256"]:
            raise ValueError("An interrupted publication needs independent operator review: HOLD.")
        if _digest(vault._private_input(destination, vault.MAX_VAULT)) != entry["sha256"]:
            raise ValueError("Encrypted native HUMAN draft changed: HOLD.")
        _, delivery_totals = delivery.collect(entry, args, vault, envelope, packet)
        if delivery_totals["remaining_unclosed"]:
            raise ValueError("Original HUMAN request delivery is not all human-closed.")
        if input('Type "ACK HUMAN CLOSED ONLY" (not proof of Apply or consent): ') != (
                "ACK HUMAN CLOSED ONLY"):
            raise ValueError("Human closeout not acknowledged.")
        entry["state"] = "reviewed"
    entry["updated"] = _utc()
    _write(folder, key, journal)
    print("Local journal updated. HUMAN states remain unverified, no authority issued.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    for action in ("status", "stage", "report", "review", "review-html", "recover", "resolve"):
        p = subs.add_parser(action)
        for name in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + name, required=True)
        for name in ("human", "directory", "plan", "journal-dir"):
            p.add_argument("--" + name, type=Path, required=True)
        if action in ("stage", "report", "review-html"):
            p.add_argument("--output", type=Path, required=True)
        p.add_argument("--ack-private-material", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Interactive current PRIVATE HUMAN approval required.")
        vault = original.ORIGINAL._vault()
        with _locked(args.journal_dir) as folder:
            current = _source(args, vault)
            packet, key = current[1], current[6]
            document = _read(folder, key, vault)
            if args.action == "status":
                _inspect(document, packet)
            elif args.action == "report":
                destination = args.output.expanduser().absolute()
                if (destination.suffix.lower() != ".html"
                        or destination in {
                            args.human.expanduser().absolute(),
                            args.plan.expanduser().absolute()}
                        or destination.exists() or destination.is_symlink()):
                    raise ValueError("Distinct NEW private HTML output required.")
                latest = document["cycles"][-1] if document["cycles"] else None
                closed = _closed(latest, packet) if latest and latest["requests"] else False
                payload = local_dashboard.build(document, closed)
                source._hold_if_not_private_directory(destination.parent)
                vault._exclusive_output(destination, payload)
                print("New owner-private 0600 scriptless offline HUMAN journal created.")
                print("Only anonymous local cycle states, timestamps and counts included.")
            elif args.action in ("review", "review-html"):
                entry = document["cycles"][-1] if document["cycles"] else None
                if entry is None:
                    raise ValueError("No original HUMAN staging record.")
                records, totals = delivery.collect(entry, args, vault, current[0], packet)
                if args.action == "review":
                    delivery.print_review(records, totals)
                else:
                    destination = args.output.expanduser().absolute()
                    if (destination.suffix.lower() != ".html"
                            or destination in {
                                args.human.expanduser().absolute(),
                                args.plan.expanduser().absolute()}
                            or destination.exists() or destination.is_symlink()):
                        raise ValueError("Distinct NEW private review HTML required.")
                    source._hold_if_not_private_directory(destination.parent)
                    vault._exclusive_output(destination, delivery.html_review(records, totals))
                    print("NEW PRIVATE scriptless original HUMAN delivery review published.")
            elif args.action == "stage":
                _stage(args, vault, folder, document, current)
            elif args.action == "recover":
                _recover(args, vault, folder, document, current)
            else:
                _resolve(args, vault, folder, document, current)
        return 0
    except Exception:
        print("HUMAN HOLD: Original current source, real local bytes, encrypted"
              " PRIVATE HUMAN plan, output continuity or operator review refused."
              " No native Apply/consent/retest/deletion performed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
