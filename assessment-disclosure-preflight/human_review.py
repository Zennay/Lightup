"""Offline HUMAN-only disclosure follow-up for PRIVATE preflight receipts.

No raw lab input, network, grant, execution, source-authenticity or release.
The SHA-256 here binds HUMAN rows only to receipt bytes, never original sources.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
from pathlib import Path
import stat
import sys

from preflight import Hold, KINDS, require

FIELDS = ("receipt_sha256", "ordinal", "source_kind", "stage", "question", "next_action")
STAGES = ("unreviewed", "privacy_hold", "source_owner_hold", "consent_hold",
          "follow_up_required", "human_reviewed_no_release")
MAX_TEXT = 1200
MAX_BYTES = 256 * 1024
TEMPLATE = "PRIVATE-human-template.csv"
REPORT = "PRIVATE-human-followup.html"


def source_bytes(name: str) -> bytes:
    fd = -1
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_BYTES)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_BYTES + 1)
        require(0 < len(raw) <= MAX_BYTES)
        return raw
    except OSError:
        raise Hold("HOLD: PRIVATE receipt or answer file not admitted") from None
    finally:
        if fd >= 0:
            os.close(fd)


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    output = {}
    for key, value in pairs:
        require(type(key) is str and key not in output)
        output[key] = value
    return output


def receipt(name: str) -> tuple[str, list[dict]]:
    raw = source_bytes(name)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold()))
    except (UnicodeError, ValueError, RecursionError, MemoryError):
        raise Hold("HOLD: PRIVATE receipt JSON rejected") from None
    require(type(doc) is dict and doc.get("schema") == "lightup.assessment_disclosure_preflight.v1")
    require(doc.get("status") == "REVIEW_ONLY" and doc.get("source_byte_bound") is False)
    flags = ("source_authenticated", "ground_truth_verified", "client_consent_verified",
             "operator_consent_verified", "authorization_granted", "dispatch_allowed", "release_allowed")
    require(all(doc.get(flag) is False for flag in flags))
    rows = doc.get("inspected_declarations_only")
    require(type(rows) is list and 1 <= len(rows) <= 12 and type(doc.get("source_count")) is int
            and len(rows) == doc["source_count"])
    for n, row in enumerate(rows, 1):
        require(type(row) is dict and type(row.get("ordinal")) is int and row["ordinal"] == n)
        require(type(row.get("kind")) is str and row["kind"] in KINDS)
    return hashlib.sha256(raw).hexdigest(), rows


def safe_note(text: object) -> str:
    require(type(text) is str and len(text) <= MAX_TEXT)
    require(all(char >= " " and char != "\x7f" for char in text))
    return text


def template(digest: str, rows: list[dict]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(FIELDS)
    for row in rows:
        writer.writerow((digest, row["ordinal"], row["kind"], "unreviewed", "", ""))
    return output.getvalue()


def admitted_answers(data: bytes, digest: str, originals: list[dict]) -> list[dict]:
    try:
        value = data.decode("utf-8-sig")
        stream = io.StringIO(value, newline="")
        reader = csv.DictReader(stream, strict=True)
        require(tuple(reader.fieldnames or ()) == FIELDS)
        answers = list(reader)
    except (UnicodeError, csv.Error, ValueError):
        raise Hold("HOLD: HUMAN CSV rejected") from None
    require(len(answers) == len(originals))
    output = []
    for i, (entry, original) in enumerate(zip(answers, originals), 1):
        require(type(entry) is dict and set(entry) == set(FIELDS))
        require(entry["receipt_sha256"] == digest and entry["ordinal"] == str(i))
        require(entry["source_kind"] == original["kind"])
        require(entry["stage"] in STAGES)
        output.append({
            "ordinal": i,
            "kind": original["kind"],
            "stage": entry["stage"],
            "question": safe_note(entry["question"]),
            "next_action": safe_note(entry["next_action"]),
        })
    return output


def render(answers: list[dict]) -> str:
    table = []
    for row in answers:
        cells = (row["ordinal"], row["kind"], row["stage"], row["question"], row["next_action"])
        table.append("<tr>" + "".join("<td>" + html.escape(str(cell)) + "</td>" for cell in cells) + "</tr>")
    counts = {stage: sum(row["stage"] == stage for row in answers) for stage in STAGES}
    counts_line = "; ".join(stage.replace("_", " ") + ": " + str(number)
                            for stage, number in counts.items())
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE HUMAN disclosure follow-up</title><style>
body{font:16px/1.5 system-ui;max-width:1080px;margin:2rem auto;padding:1rem}
.warning{padding:1rem;border:2px solid #943}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #999;text-align:left;vertical-align:top;padding:.6rem;overflow-wrap:anywhere}
thead{background:#eee}@media print{body{margin:0}}</style></head><body>
<h1>PRIVATE HUMAN disclosure follow-up</h1>
<p class="warning"><strong>NOT RELEASE AUTHORITY.</strong> These are unsigned local
HUMAN notes bound only to an earlier unsigned PRIVATE receipt's exact bytes,
NOT to original assessment artifacts, authenticated reviewers or client grants.
All statuses are human-only; even human_reviewed_no_release is never approval.
Questions and actions can contain confidential information. Keep PRIVATE.
No scanner, model, network, deletion, share or automated release takes place.</p>
<p>Stages: """ + html.escape(counts_line) + """</p>
<table><thead><tr><th>Ordinal</th><th>Kind</th><th>HUMAN stage</th>
<th>HUMAN question</th><th>HUMAN next action</th></tr></thead><tbody>""" + "".join(table) + """</tbody></table>
<p>Obtain original source-owner and independent security/privacy review, authentic
current separate client/operator consent, action-time revocation and explicit HUMAN GO
outside this file. Original #177/#182/#829 and mandatory hosted/named VPS CI remain.</p>
</body></html>"""


def publish(output_dir: str, filename: str, text: str) -> None:
    directory = Path(output_dir)
    try:
        info = os.lstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0)
        path = directory / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(text.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                path.unlink()
            except OSError:
                pass
            raise
    except OSError:
        raise Hold("HOLD: exclusive PRIVATE output rejected") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PRIVATE receipt-bound HUMAN disclosure notes, never release")
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "render"):
        sub = commands.add_parser(name)
        sub.add_argument("--receipt", required=True, help="preflight PRIVATE-receipt.json")
        sub.add_argument("--private-output-dir", required=True, help="existing owner-only 0700 directory")
        if name == "render":
            sub.add_argument("--answers", required=True, help="completed PRIVATE-human-template.csv")
    args = parser.parse_args(argv)
    try:
        digest, rows = receipt(args.receipt)
        if args.action == "prepare":
            publish(args.private_output_dir, TEMPLATE, template(digest, rows))
        else:
            answers = admitted_answers(source_bytes(args.answers), digest, rows)
            publish(args.private_output_dir, REPORT, render(answers))
    except Hold:
        print("HOLD: PRIVATE HUMAN follow-up refused; no authority or release", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: HUMAN-only PRIVATE output created, no authority or release")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
