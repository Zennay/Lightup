#!/usr/bin/env python3
"""Offline source-free PRIVATE HUMAN inbox for 1–12 encrypted cockpit packets.

Only self-declared human workload counts; no original evidence, client identity,
authorization, verified fix, retest or active network work is imported.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

import attest
import transport

native = attest.read_cockpit
review = attest.review
KIND = "lightup.private_human_encrypted_cockpit_inbox"
WARNING = ("Offline PRIVATE HUMAN workload from independently admitted encrypted "
           "source-free cockpits only. Slots are not unique clients, findings, "
           "verified fixes, consent, source authenticity or security verdicts.")
MAX = 12
ROOT = frozenset({"index.html", "summary.json", "manifest.json"})
FIELDS = frozenset({"kind", "schema_version", "disposition", "slot_count",
                    "slots", "pending_human_questions_not_fixes",
                    "warning", *review.FLAGS})


def require(yes: bool) -> None:
    attest.require(yes)


def pretty(payload: dict) -> bytes:
    return native.workspace.pretty(payload)


def strict_private_dir(path: Path) -> None:
    require(path.is_absolute() and path.parent == path.parent.resolve(strict=True)
            and not path.is_symlink())
    meta = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
            and meta.st_mode & 0o077 == 0)


def descriptor(raw: bytes) -> dict:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def authenticate_packet(raw: bytes, key: bytes) -> tuple[bytes, bytes, dict[str, bytes]]:
    manifest, receipt, files = transport.unseal(raw, key)
    # Fail before plaintext staging: authenticated AEAD alone does not
    # establish the detached source-free manifest HMAC identity.
    envelope = json.loads(receipt.decode("ascii"),
                          object_pairs_hook=transport.no_duplicate_pairs)
    require(type(envelope) is dict and set(envelope) == attest.FIELDS
            and envelope.get("kind") == attest.KIND
            and type(envelope.get("schema_version")) is int
            and envelope["schema_version"] == 1
            and envelope.get("algorithm") == "HMAC-SHA256"
            and type(envelope.get("mac")) is str
            and type(envelope.get("manifest_sha256")) is str
            and hmac_compare(envelope["mac"], attest.mac(key, manifest))
            and hmac_compare(envelope["manifest_sha256"],
                             hashlib.sha256(manifest).hexdigest())
            and receipt == transport.canonical(envelope))
    return manifest, receipt, files


def hmac_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)


def row_from_admission(index: int, admitted: dict, manifest: bytes) -> dict:
    return {
        "slot": index,
        "original_source_slots_not_unique_cases":
            admitted["original_source_slots_not_unique_cases"],
        "locally_pending_human_questions_not_fixes":
            admitted["local_pending_human_questions_not_fixes"],
        "same_original_source_claimed":
            admitted["same_original_source_claimed"],
        "accepted_private_files": admitted["accepted_private_files"],
        # This digest authenticates *local source-free summary bytes* only.
        # It is private inventory metadata, not an original evidence fingerprint.
        "source_free_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
    }


def summary(rows: list[dict]) -> dict:
    require(1 <= len(rows) <= MAX)
    return {
        "kind": KIND,
        "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_REVIEW_ONLY_NO_AUTHORITY",
        "slot_count": len(rows),
        "slots": rows,
        "pending_human_questions_not_fixes":
            sum(r["locally_pending_human_questions_not_fixes"] for r in rows),
        "warning": WARNING,
        **{f: False for f in review.FLAGS},
    }


def render(data: dict) -> bytes:
    # Fixed slot labels and generated bounded numbers only. No user strings or
    # imported private notes are embedded in the standalone browser summary.
    rows = []
    for r in data["slots"]:
        idx = r["slot"]
        name = f"slot-{idx:02d}"
        link = f"{name}/cockpit/index.html"
        rows.append(
            '<tr><td><a href="' + link + '">PRIVATE source slot ' +
            str(idx) + '</a></td><td>' +
            str(r["original_source_slots_not_unique_cases"]) +
            '</td><td>' + str(r["locally_pending_human_questions_not_fixes"]) +
            '</td><td>' + ("Self-declared repeated" if
            r["same_original_source_claimed"] else "No time claim") +
            '</td></tr>')
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\';">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>PRIVATE HUMAN Evidence Inbox</title>'
        '<style>body{font:16px system-ui,sans-serif;max-width:960px;margin:3rem auto;'
        'padding:1rem;color:#182234;background:#f7f9fc}h1{font-size:1.8rem}'
        'table{border-collapse:collapse;width:100%;background:white}'
        'th,td{border:1px solid #cbd5e1;padding:.9rem;text-align:left}'
        'a{color:#194a9d}small{color:#475569}p{line-height:1.6}</style>'
        '</head><body><h1>PRIVATE HUMAN Evidence Inbox</h1>'
        '<p>Separately received source-free cockpit workrooms: <b>' +
        str(data["slot_count"]) + '</b>. Local pending HUMAN questions '
        '(not verified fixes): <b>' +
        str(data["pending_human_questions_not_fixes"]) + '</b>.</p>'
        '<p role="note"><small>' + html.escape(WARNING) + '</small></p>'
        '<table><thead><tr><th>Offline workroom</th><th>Original slots '
        '(not unique clients)</th><th>Local pending HUMAN questions</th>'
        '<th>Chronology</th></tr></thead><tbody>' +
        "".join(rows) + '</tbody></table>'
        '<p><small>Each link opens a locally admitted independent original '
        'source-free cockpit. No automatic merge, reporting verdict, client '
        'authorization, active assessment, grant or retest occurs.</small></p>'
        '</body></html>\n')
    return document.encode("utf-8")


def inspect(folder: Path, key_file: Path) -> dict:
    strict_private_dir(folder)
    key = attest.key_bytes(key_file)
    mbytes = review.private_read(folder / "manifest.json")
    manifest = native.verify.json_obj(mbytes)
    require(set(manifest) == {"kind", "schema_version", "files", "slots"} and
            manifest.get("kind") == KIND and
            type(manifest.get("schema_version")) is int and
            manifest["schema_version"] == 1 and
            type(manifest.get("slots")) is list and
            1 <= len(manifest["slots"]) <= MAX)
    n = len(manifest["slots"])
    names = [f"slot-{i:02d}" for i in range(1, n+1)]
    require(manifest["slots"] == names and set(p.name for p in folder.iterdir())
            == set(names) | ROOT and
            type(manifest.get("files")) is dict and
            set(manifest["files"]) == {"index.html", "summary.json"})
    rows = []
    sha_set: set[str] = set()
    for index, name in enumerate(names, 1):
        slot = folder / name
        strict_private_dir(slot)
        require({p.name for p in slot.iterdir()} == {"cockpit", "receipt.json"})
        cockpit = slot / "cockpit"
        admitted = attest.inspect(cockpit, key_file, slot / "receipt.json")
        original_manifest = review.private_read(cockpit / "manifest.json")
        row = row_from_admission(index, admitted, original_manifest)
        require(row["source_free_manifest_sha256"] not in sha_set)
        sha_set.add(row["source_free_manifest_sha256"])
        rows.append(row)
    document = summary(rows)
    require(set(document) == FIELDS and all(document[f] is False for f in review.FLAGS))
    expected = {"index.html": render(document), "summary.json": pretty(document)}
    for name, raw in expected.items():
        payload = review.private_read(folder / name)
        require(payload == raw and manifest["files"][name] == descriptor(raw))
    require(mbytes == pretty(manifest))
    return document


def receive_many(packages: list[Path], key_file: Path, target_parent: Path) -> tuple[Path, dict]:
    require(type(packages) is list and 1 <= len(packages) <= MAX)
    strict_private_dir(target_parent)
    key = attest.key_bytes(key_file)
    require(all(p.is_absolute() and p not in (key_file, target_parent)
                and p not in target_parent.parents
                for p in packages))
    require(len({str(p) for p in packages}) == len(packages))
    stage = Path(tempfile.mkdtemp(prefix=".lightup-inbox-pending-", dir=target_parent))
    complete = False
    try:
        rows = []
        sha_set: set[str] = set()
        names = []
        for index, path in enumerate(packages, 1):
            raw = attest.private_file(path, transport.MAX_ENCRYPTED)
            manifest, receipt, files = authenticate_packet(raw, key)
            name = f"slot-{index:02d}"
            names.append(name)
            slot = stage / name
            slot.mkdir(mode=0o700)
            # Original native owner-only renderer admission from the exact
            # source-owner dependency, no reimplemented HTML trust semantics.
            native.workspace.publish_bundle(slot / "cockpit", files, manifest)
            attest.exclusive_private_write(slot / "receipt.json", receipt)
            admitted = attest.inspect(slot / "cockpit", key_file, slot / "receipt.json")
            row = row_from_admission(index, admitted, manifest)
            require(row["source_free_manifest_sha256"] not in sha_set)
            sha_set.add(row["source_free_manifest_sha256"])
            rows.append(row)
        counts = summary(rows)
        html_raw = render(counts)
        json_raw = pretty(counts)
        manifest = {"kind": KIND, "schema_version": 1, "slots": names,
                    "files": {"index.html": descriptor(html_raw),
                              "summary.json": descriptor(json_raw)}}
        for name, content in (("index.html", html_raw),
                              ("summary.json", json_raw),
                              ("manifest.json", pretty(manifest))):
            attest.exclusive_private_write(stage / name, content)
        inspect(stage, key_file)  # Native read + regenerated browser summary.
        result = target_parent / ("lightup-human-inbox-" + os.urandom(16).hex())
        require(not result.exists() and not result.is_symlink())
        native.workspace.exclusive_dir_publish(stage, result)
        complete = True
        return result, counts
    finally:
        if not complete:
            shutil.rmtree(stage)



def anonymous_counts(admitted: dict) -> dict:
    # A PRIVATE manifest digest in the internal summary may correlate two
    # copies of the same source-free workroom. Never export it as anonymous.
    require(type(admitted) is dict and admitted.get("kind") == KIND and
            type(admitted.get("slots")) is list and
            type(admitted.get("slot_count")) is int and
            1 <= admitted["slot_count"] <= MAX and
            admitted["slot_count"] == len(admitted["slots"]))
    return {
        "kind": "lightup.anonymous_human_inbox_counts_only",
        "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_COUNTS_ONLY_NO_AUTHORITY",
        "source_free_workrooms_not_unique_cases": admitted["slot_count"],
        "local_pending_human_questions_not_fixes":
            admitted["pending_human_questions_not_fixes"],
        "warning": WARNING,
        **{flag: False for flag in review.FLAGS},
    }


def export_counts(folder: Path, key_file: Path, output: Path) -> dict:
    require(output != folder and output != key_file and
            folder not in output.parents and not output.exists() and
            not output.is_symlink())
    original = inspect(folder, key_file)
    result = anonymous_counts(original)
    require(inspect(folder, key_file) == original)
    attest.exclusive_private_write(output, pretty(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Receive 1–12 encrypted source-free HUMAN cockpits into one native "
        "PRIVATE offline human-workload inbox; no original findings or authority"))
    actions = parser.add_subparsers(dest="action", required=True)
    receive = actions.add_parser("receive-many", help="One atomic PRIVATE inbox from encrypted packages")
    receive.add_argument("--package", action="append", required=True, type=Path,
                         help="Repeat for 1–12 complete previously encrypted cockpit files")
    receive.add_argument("--key-file", required=True, type=Path)
    receive.add_argument("--output-parent", required=True, type=Path)
    inspect_action = actions.add_parser("inspect", help="Read-only native admission of complete inbox")
    inspect_action.add_argument("--inbox", required=True, type=Path)
    inspect_action.add_argument("--key-file", required=True, type=Path)
    counts_action = actions.add_parser("export-counts", help="Separate privacy-minimal counts-only JSON, no manifest digests")
    counts_action.add_argument("--inbox", required=True, type=Path)
    counts_action.add_argument("--key-file", required=True, type=Path)
    counts_action.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "receive-many":
            result, data = receive_many(args.package, args.key_file, args.output_parent)
            print("PRIVATE offline HUMAN inbox atomically published: " + str(result))
        elif args.action == "export-counts":
            data = export_counts(args.inbox, args.key_file, args.output)
            print("PRIVATE counts-only JSON exported: no source-free manifest digests or per-slot links.")
            print(str(data["source_free_workrooms_not_unique_cases"]) +
                  " source-free workroom slot(s); " +
                  str(data["local_pending_human_questions_not_fixes"]) +
                  " locally pending HUMAN questions (NOT fixes).")
            print("No source identities, original findings, verified fixes or client consent.")
            return 2
        else:
            data = inspect(args.inbox, args.key_file)
            print("REVIEW_ONLY: private native HUMAN inbox and all receipt pages admitted.")
        print(str(data["slot_count"]) + " separately received source-free workroom(s), " +
              str(data["pending_human_questions_not_fixes"]) +
              " locally pending HUMAN questions, NOT unique findings or verified fixes.")
        print("No client identity, consent, authorized target, retest or original evidence certified.")
        return 2
    except (OSError, TypeError, ValueError, KeyError, UnicodeError, OverflowError,
            RecursionError, review.Hold, transport.InvalidTag, transport.binascii.Error):
        print("HOLD: encrypted PRIVATE HUMAN inbox not admitted; nothing authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
