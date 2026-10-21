"""Owner-private multi-room HUMAN inbox board for completed offline LightUp handoffs.

No scanner, network, grant, client authority, result verification or source
promotion. Source-file digests are local custody only, never signatures.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
import re
import stat
import sys

import private_intake as inbox
import private_reopen as reopened
import reconcile
from human_review import Hold, receipt_content, source_bytes, safe_note
from preflight import KINDS

MAX_ROOMS = 12
HTML = "PRIVATE-inbox-portfolio.html"
CSV = "PRIVATE-inbox-portfolio.csv"
JSON = "PRIVATE-inbox-portfolio.json"
FIELDS = ("slot", "source_declarations", "human_a_choices", "human_b_choices",
          "unselected_hold", "result_transport", "local_file_custody",
          "source_reopening", "authority", "human_followup")


def admitted_decisions(path: str, receipt_path: str) -> tuple[int, int, int, int]:
    original_sha, originals = receipt_content(source_bytes(receipt_path))
    text = source_bytes(path).decode("utf-8-sig", "strict")
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    if tuple(reader.fieldnames or ()) != reconcile.DECISION_FIELDS:
        raise ValueError("original decision columns changed")
    rows = list(reader)
    if len(rows) != len(originals):
        raise ValueError("original decision membership changed")
    counts = {"A": 0, "B": 0, "HOLD": 0}
    for i, (row, original) in enumerate(zip(rows, originals), 1):
        if (type(row) is not dict or set(row) != set(reconcile.DECISION_FIELDS) or
            row["receipt_sha256"] != original_sha or
            row["ordinal"] != str(i) or row["source_kind"] != original["kind"] or
            row["choice"] not in counts or
            not all(type(row[key]) is str and re.fullmatch("[a-f0-9]{64}", row[key])
                    for key in ("review_a_sha256", "review_b_sha256"))):
            raise ValueError("unsigned decisions not admitted")
        # Reject invalid reasons, never render/store them.
        safe_note(row["human_reason"])
        if row["choice"] != "HOLD" and not row["human_reason"].strip():
            raise ValueError("HUMAN choice without required explicit reason")
        counts[row["choice"]] += 1
    return len(originals), counts["A"], counts["B"], counts["HOLD"]


def read_one(parent_fd: int, parent_path: str, name: str, slot: int, full_reopened: bool = False) -> dict:
    if not inbox.ROOM_PATTERN.fullmatch(name):
        raise ValueError("room identifier refused")
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                 getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    try:
        meta = os.fstat(fd)
        if (meta.st_uid != os.geteuid() or
            not stat.S_ISDIR(meta.st_mode) or
            stat.S_IMODE(meta.st_mode) & 0o077):
            raise ValueError("PRIVATE room must be owner-only")
        room = os.path.join(parent_path, name)
        # Existing read-only intake inventory: exact original source bytes,
        # manifest authority flags, original role count, unexpected filenames.
        inventory, _ = reopened.exact_manifest(room, fd)
        count, aa, bb, held = admitted_decisions(
            os.path.join(room, inbox.DECISIONS),
            os.path.join(room, inbox.RECEIPT))
    finally:
        os.close(fd)
    return {
        "slot": slot,
        "source_declarations": count,
        "human_a_choices": aa,
        "human_b_choices": bb,
        "unselected_hold": held,
        "result_transport": ("ENCRYPTED" if inventory["transfer_mode"] ==
                             "PRIVATE_ENCRYPTED_BUNDLE" else "PRIVATE_PLAINTEXT"),
        "local_file_custody": "EXACT_UNSIGNED_BYTES",
        "source_reopening": ("ORIGINAL_NATIVE_REVIEW_ONLY" if full_reopened else "NOT_PERFORMED_BY_BOARD"),
        "authority": "NONE",
        "human_followup": ("CHECK_HOLD_CHOICES" if held else "INDEPENDENT_REVIEW_REQUIRED")
    }


def manifest_bytes(rows: list[dict], full_reopened: bool) -> bytes:
    manifest = {
        "schema": "lightup.private_human_inbox_board.v1",
        "status": "REVIEW_ONLY",
        "source_free": True,
        "source_authenticated": False,
        "reviewers_authenticated": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "release_allowed": False,
        "original_human_reopening_performed": bool(full_reopened),
        "signed": False,
        "rooms": rows,
    }
    return (json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def require_output_outside_source_tree(parent_path: str, output_dir: str) -> None:
    source_parent = os.path.realpath(parent_path)
    output_path = os.path.realpath(output_dir)
    if os.path.commonpath((source_parent, output_path)) == source_parent:
        raise ValueError("PRIVATE board output must be outside the original inbox tree")


def source_free_csv(rows: list[dict]) -> str:
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return out.getvalue()


def render(rows: list[dict]) -> str:
    headings = ("Slot", "Declared originals", "A decisions", "B decisions",
                "HOLD decisions", "Result mode", "Local custody",
                "Original HUMAN reopening", "HUMAN follow-up")
    body = []
    for row in rows:
        fields = (str(row["slot"]), str(row["source_declarations"]),
                  str(row["human_a_choices"]), str(row["human_b_choices"]),
                  str(row["unselected_hold"]), row["result_transport"],
                  row["local_file_custody"], row["source_reopening"], row["human_followup"])
        body.append("<tr>"+"".join("<td>"+html.escape(f)+"</td>" for f in fields)+"</tr>")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE HUMAN inbox portfolio</title><style>
body{font:16px/1.55 system-ui;max-width:1200px;margin:2rem auto;padding:1.3rem;color:#152336}
header{border-bottom:2px solid #425975;margin-bottom:1.6rem}
.warning{padding:1rem;border-left:5px solid #965d00;background:#fff2df}
table{border-collapse:collapse;width:100%;margin:1.5rem 0}
th,td{padding:.65rem;vertical-align:top;border:1px solid #9faebb;text-align:left;overflow-wrap:anywhere}
th{background:#ecf3fc}
.note{font-size:.92rem}
@media print{body{margin:0}tr{break-inside:avoid}}
</style></head><body><header><h1>LightUp PRIVATE HUMAN inbox board</h1>
<p>Strictly local, source-free **slot-ordered** operator overview; REVIEW_ONLY / HOLD.</p></header>
<p class="warning"><strong>LOCAL UNSIGNED CUSTODY ONLY.</strong>
The default board checks original exact received PRIVATE source bytes and
HUMAN decisions. With manually requested --full-reopen, the original native
source-bound HUMAN reopener also runs for each selected room before publishing.
Neither mode authenticates clients/reviewers, proves source/mitigation/security,
grants consent, permits any scan or authorizes release. Native REVIEW_ONLY
never means approved evidence, identity, or permission.</p>
<table><thead><tr>"""+"".join("<th scope='col'>"+html.escape(x)+"</th>" for x in headings)+"""</tr></thead>
<tbody>"""+"".join(body)+"""</tbody></table>
<p class="note">Room numbers refer ONLY to the caller's local --room order.
Original room names, disk paths, evidence, HUMAN free-text, reviewer IDs, SHA
and customer identifiers are intentionally absent. The table is still PRIVATE:
small-cohort counts may identify a lab, so do not publish or email it.
Zero HOLD choices or original native reopener REVIEW_ONLY are NOT approval,
finding verification or resolved vulnerability. Native decryption may require
local no-echo human input. Absent rooms never mean a fixed issue.</p>
<p>Follow-up: reopen each original room explicitly with the native read-only
PRIVATE HUMAN receiver; confirm genuine source owner and independent
privacy/security/browser review, current separate authenticated client and
operator consent with revocation at action-time, and explicit HUMAN GO before
any future release. Incubate M3/M7 PLAN/LAB ONLY.</p>
</body></html>"""


def atomic_private_publish(output_dir: str, artifacts: list[tuple[str, bytes]]) -> None:
    directory_fd, _ = inbox.user_private_parent(output_dir)
    staged = []
    published = []
    try:
        for name, raw in artifacts:
            temporary = ".lightup-private-board-" + os.urandom(16).hex()
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
            staged.append(temporary)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        for (name, _), temporary in zip(artifacts, staged):
            os.link(temporary, name, src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
            published.append(name)
        os.fsync(directory_fd)
    except (OSError, ValueError, TypeError):
        for name in published:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
        raise
    finally:
        for temp in staged:
            try:
                os.unlink(temp, dir_fd=directory_fd)
            except OSError:
                pass
        os.close(directory_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="PRIVATE multi-room source-free HUMAN inbox board")
    parser.add_argument("--private-parent", required=True, help="owner-only 0700 original room parent")
    parser.add_argument("--room", action="append", required=True,
                        help="original PRIVATE room name, repeat 1–12 times in intended slot order")
    parser.add_argument("--private-output-dir", required=True,
                        help="existing owner-only 0700 directory, preferably separate from source rooms")
    parser.add_argument("--full-reopen", action="store_true",
                        help="explicit trusted TTY original HUMAN readmission of all selected rooms; no authorization")
    args = parser.parse_args()
    parent_fd = None
    try:
        if not 1 <= len(args.room) <= MAX_ROOMS or len(set(args.room)) != len(args.room):
            raise ValueError("1–12 distinct original PRIVATE rooms required")
        parent_fd, parent_path = inbox.user_private_parent(args.private_parent)
        require_output_outside_source_tree(parent_path, args.private_output_dir)
        rows = [read_one(parent_fd, parent_path, name, i)
                for i, name in enumerate(args.room, 1)]
        if args.full_reopen:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise ValueError("full original HUMAN reopening needs a trusted terminal")
            print("PRIVATE full original HUMAN reopening of", len(rows), "rooms.")
            print("Original decryption may ask for passphrases privately.")
            print("This is never identity verification, client consent or release.")
            if input("Type exactly REOPEN to continue: ").strip() != "REOPEN":
                raise ValueError("HUMAN did not confirm full original reopen")
            for name in args.room:
                reopened.reopen(parent_path, name)
            # Catch source/decision changes after the initial source overview.
            after = [read_one(parent_fd, parent_path, name, i, full_reopened=True)
                     for i, name in enumerate(args.room, 1)]
            expected = [{**row, "source_reopening": "ORIGINAL_NATIVE_REVIEW_ONLY"}
                        for row in rows]
            if after != expected:
                raise ValueError("source changed during original HUMAN readmission")
            rows = after
        # All inputs admitted before any output name becomes visible.
        outputs = [
            (HTML, render(rows).encode("utf-8")),
            (CSV, source_free_csv(rows).encode("utf-8")),
            (JSON, manifest_bytes(rows, args.full_reopen))
        ]
        atomic_private_publish(args.private_output_dir, outputs)
    except (OSError, TypeError, ValueError, UnicodeError, MemoryError, Hold, csv.Error):
        print("HOLD: original PRIVATE HUMAN inbox board not published; no authority", file=sys.stderr)
        return 3
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
    print("REVIEW_ONLY: source-free PRIVATE HUMAN board published to owner-only output directory")
    if args.full_reopen:
        print("Original HUMAN readmission completed: still REVIEW_ONLY, no consent or release")
    else:
        print("Slots are input order; full original HUMAN readmission NOT requested")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
