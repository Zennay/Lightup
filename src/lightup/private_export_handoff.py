"""Explicit private, non-authorizing export handoff for existing tenant finding summaries.

This does not invoke scans, create grants, approve findings, or authenticate
archive recipients. All customer-bearing output stays in a local 0600 ZIP.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
from getpass import GetPassWarning, getpass
import hashlib
from html import escape
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import warnings
import zipfile

from .domain import AccountLockedError, DomainStore
from .finding_export_service import render_client_findings_csv
from .models import RetestStatus, Severity

KIND = "lightup.private_findings_handoff"
CSV_NAME = "findings.csv"
MANIFEST_NAME = "manifest.json"
NOTICE_NAME = "READ_FIRST.txt"
HEADERS = ("finding_id", "title", "severity", "retest_status", "remediation")
ARCHIVE_LIMIT = 2 * 1024 * 1024
CSV_LIMIT = 512 * 1024
NOTICE = (
    "PRIVATE, UNENCRYPTED: handle with separately approved secure transport.\n"
    "Finding labels, source retest statuses and digests are unverified claims.\n"
    "This file cannot grant scope, approve active testing, prove fixes, or authenticate a client.\n"
    "Manually reauthenticate the intended recipient and real source before use.\n"
)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate archive manifest key")
        result[key] = value
    return result


def _rows(data: bytes) -> list[dict[str, str]]:
    if len(data) > CSV_LIMIT:
        raise ValueError("CSV exceeds offline handoff budget")
    try:
        decoded = data.decode("utf-8", errors="strict")
        stream = io.StringIO(decoded, newline="")
        reader = csv.reader(stream, strict=True)
        heading = next(reader)
        if tuple(heading) != HEADERS:
            raise ValueError("unexpected CSV columns")
        records = []
        identifiers: set[str] = set()
        for record in reader:
            if len(record) != len(HEADERS) or len(records) >= 128:
                raise ValueError("invalid CSV row shape or batch size")
            fields = dict(zip(HEADERS, record))
            identity = fields["finding_id"]
            if not identity.strip() or identity in identifiers:
                raise ValueError("invalid or duplicate original finding ID")
            identifiers.add(identity)
            if not fields["title"].strip() or not fields["remediation"].strip():
                raise ValueError("blank original finding description")
            if fields["severity"] not in {level.value for level in Severity}:
                raise ValueError("unknown source severity")
            if fields["retest_status"] not in {status.value for status in RetestStatus}:
                raise ValueError("unknown source retest label")
            records.append(fields)
        return records
    except (UnicodeError, csv.Error, StopIteration) as exc:
        raise ValueError("invalid original CSV encoding or shape") from exc


def _output_path(raw: str, extension: str) -> Path:
    path = Path(raw).expanduser()
    if path.suffix.lower() != extension:
        raise ValueError("output must end with " + extension)
    if path.name in (".", "..") or not path.name:
        raise ValueError("output filename required")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("output parent must be an existing directory")
    result = parent / path.name
    if result.exists() or result.is_symlink():
        raise FileExistsError("existing output cannot be replaced")
    return result


def _atomic_private_publish(output: Path, content: bytes) -> None:
    """Create one private local artifact, without clobbering or exposing partial data."""
    fd, temporary = tempfile.mkstemp(prefix=".lightup-private-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is atomic and fails if another process created output.
        os.link(temporary, output, follow_symlinks=False)
        try:
            directory_fd = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Publication has already succeeded; never misreport an existing file
            # as a failed write and tempt a second publication.
            pass
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _make_archive(csv_text: str, client_id: str, engagement_id: str | None) -> bytes:
    raw = csv_text.encode("utf-8", errors="strict")
    rows = _rows(raw)
    manifest = {
        "kind": KIND,
        "version": 1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "declared_client_id": client_id,
        "declared_engagement_id": engagement_id,
        "source_csv_sha256": hashlib.sha256(raw).hexdigest(),
        "source_row_count": len(rows),
        "authorizes_action": False,
        "certifies_remediation": False,
        "confirms_client_identity": False,
        "encrypted": False,
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr(CSV_NAME, raw)
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        archive.writestr(NOTICE_NAME, NOTICE.encode("utf-8"))
    blob = stream.getvalue()
    if len(blob) > ARCHIVE_LIMIT:
        raise ValueError("archive exceeds offline handoff budget")
    return blob


def _read_archive(filename: str) -> tuple[dict, list[dict[str, str]]]:
    path = Path(filename)
    if not path.is_file() or path.stat().st_size > ARCHIVE_LIMIT:
        raise ValueError("archive missing or exceeds import limit")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) != 3 or {i.filename for i in infos} != {CSV_NAME, MANIFEST_NAME, NOTICE_NAME}:
                raise ValueError("unexpected, duplicate or missing archive entries")
            if any(i.file_size > CSV_LIMIT or i.flag_bits & 0x1 or i.is_dir() for i in infos):
                raise ValueError("oversize, encrypted or non-file archive entry")
            raw = archive.read(CSV_NAME)
            manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8", "strict"),
                                  object_pairs_hook=_no_duplicate_keys)
            notice = archive.read(NOTICE_NAME).decode("utf-8", "strict")
    except (OSError, zipfile.BadZipFile, RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid private export archive") from exc
    if notice != NOTICE or type(manifest) is not dict or set(manifest) != {
        "kind", "version", "generated_utc", "declared_client_id",
        "declared_engagement_id", "source_csv_sha256", "source_row_count",
        "authorizes_action", "certifies_remediation", "confirms_client_identity", "encrypted"
    }:
        raise ValueError("invalid archive metadata")
    if manifest["kind"] != KIND or type(manifest["version"]) is not int or manifest["version"] != 1:
        raise ValueError("unrecognized handoff version")
    if any(manifest[field] is not False for field in (
        "authorizes_action", "certifies_remediation", "confirms_client_identity", "encrypted"
    )):
        raise ValueError("invalid authority or encryption claim")
    if type(manifest["declared_client_id"]) is not str or not manifest["declared_client_id"].strip():
        raise ValueError("missing declared source client")
    if manifest["declared_engagement_id"] is not None and (
        type(manifest["declared_engagement_id"]) is not str or not manifest["declared_engagement_id"].strip()
    ):
        raise ValueError("invalid declared engagement")
    if type(manifest["generated_utc"]) is not str or len(manifest["generated_utc"]) > 48:
        raise ValueError("invalid archive creation time")
    try:
        if datetime.fromisoformat(manifest["generated_utc"]).utcoffset() is None:
            raise ValueError("archive time must have UTC offset")
    except ValueError as exc:
        raise ValueError("invalid archive creation time") from exc
    if type(manifest["source_csv_sha256"]) is not str or len(manifest["source_csv_sha256"]) != 64:
        raise ValueError("invalid source digest")
    if hashlib.sha256(raw).hexdigest() != manifest["source_csv_sha256"]:
        raise ValueError("private source CSV digest mismatch")
    rows = _rows(raw)
    if type(manifest["source_row_count"]) is not int or manifest["source_row_count"] != len(rows):
        raise ValueError("private source count mismatch")
    return manifest, rows


def _report_html(rows: list[dict[str, str]]) -> str:
    severities = Counter(row["severity"] for row in rows)
    statuses = Counter(row["retest_status"] for row in rows)
    def cards(values: Counter, order: list[str]) -> str:
        return "".join(
            '<tr><th scope="row">' + escape(name.replace("_", " ")) +
            '</th><td>' + str(values[name]) + '</td></tr>' for name in order
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>LightUp — anonymous finding summary</title>"
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        '<style>body{font:17px system-ui,sans-serif;line-height:1.5;max-width:760px;margin:5vh auto;padding:24px;color:#16202e}'
        'h1{font-size:2rem}table{border-collapse:collapse;width:100%;margin:20px 0 32px}'
        'th,td{padding:11px;border-bottom:1px solid #ccd2da;text-align:left}'
        '.warning{border-left:4px solid #92400e;padding:10px 18px;background:#fffaf0}'
        '@media print{body{margin:0;padding:0}}'
        '</style><body><h1>LightUp | source-reported findings</h1>'
        '<p>Offline aggregate only · total original records: <strong>' + str(len(rows)) + '</strong></p>'
        '<h2>Source-reported severity</h2><table>' +
        cards(severities, [v.value for v in Severity]) + '</table>'
        '<h2>Source-reported retest label</h2><table>' +
        cards(statuses, [v.value for v in RetestStatus]) + '</table>'
        '<div class="warning"><strong>HUMAN REVIEW / HOLD.</strong> These numbers come from a private, '
        'self-described source archive. A digest proves only byte-consistency, not provenance. '
        'No retest, repaired issue, client identity, consent, or authorization has been verified. '
        'Never use this report to authorize testing, close findings or claim security remediation.</div>'
        '<p>No original finding IDs, client names, asset names, notes, evidence or remedy text are included. '
        'Small cohorts may still be identifying; review recipients before sharing.</p>'
        '</body></html>'
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LightUp offline PRIVATE evidence summary handoff; not a scan or authorization")
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create", help="Sign in to original local DomainStore and publish one private ZIP")
    create.add_argument("--db", required=True)
    create.add_argument("--email", required=True)
    create.add_argument("--client-id", required=True)
    create.add_argument("--engagement-id")
    create.add_argument("--output", required=True, help="new .zip path, never overwrite")
    create.add_argument("--ack-private-plaintext", action="store_true", help="acknowledge output is NOT encrypted")
    inspect = sub.add_parser("inspect", help="Offline inspect integrity and anonymous counts; no identity verification")
    inspect.add_argument("archive")
    report = sub.add_parser("report", help="Create a scriptless, ID-free local human summary")
    report.add_argument("archive")
    report.add_argument("--output", required=True, help="new .html path, never overwrite")
    report.add_argument("--ack-private-plaintext", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.action == "create":
            if not args.ack_private_plaintext:
                raise ValueError("explicit --ack-private-plaintext required")
            destination = _output_path(args.output, ".zip")
            if not Path(args.db).is_file() or not sys.stdin.isatty():
                raise ValueError("existing domain database and interactive secure terminal required")
            with warnings.catch_warnings():
                warnings.simplefilter("error", GetPassWarning)
                password = getpass("LightUp password: ")
            store = DomainStore(args.db)
            try:
                user = store.authenticate(args.email, password)
            finally:
                del password
            if user is None:
                raise PermissionError("sign-in denied")
            ctx = store.context_for_user(user.user_id)
            csv_text = render_client_findings_csv(
                store, ctx, args.client_id, engagement_id=args.engagement_id)
            bundle = _make_archive(csv_text, args.client_id, args.engagement_id)
            _atomic_private_publish(destination, bundle)
            print("Created private unencrypted offline handoff. No grant/retest/repair verified.")
        else:
            manifest, rows = _read_archive(args.archive)
            if args.action == "inspect":
                print("Byte-consistent PRIVATE handoff; source authenticity NOT established.")
                print("Finding count:", len(rows))
                for column in ("severity", "retest_status"):
                    for label, number in sorted(Counter(row[column] for row in rows).items()):
                        print(column + " " + label + ": " + str(number))
            else:
                if not args.ack_private_plaintext:
                    raise ValueError("explicit --ack-private-plaintext required")
                destination = _output_path(args.output, ".html")
                _atomic_private_publish(destination, _report_html(rows).encode("utf-8"))
                print("Created private aggregate HTML. Recipient/privacy review still required.")
        return 0
    except (ValueError, PermissionError, AccountLockedError, sqlite3.DatabaseError,
            GetPassWarning, EOFError, KeyboardInterrupt, FileExistsError, OSError) as exc:
        # Do not print raw source text, database fields, filesystem paths or identities.
        print("Private handoff rejected; source, authorization or output conditions invalid.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
