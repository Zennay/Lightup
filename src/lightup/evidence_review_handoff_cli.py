"""Authenticated, tenant-scoped private Evidence Review HTML handoff.

Extends the ORIGINAL interactive domain/source export only. Not a scan, grant,
retest, approval, or live operator dashboard. Output contains sensitive findings.
"""
from __future__ import annotations

import argparse
import base64
import csv
from getpass import GetPassWarning, getpass
import io
import json
import os
from pathlib import Path
import runpy
import sqlite3
import tempfile
import sys
import warnings

from .domain import AccountLockedError, DomainStore
from .finding_export_service import render_client_findings_csv

EXPECTED = ("finding_id", "title", "severity", "retest_status", "remediation")
SEVERITIES = frozenset(("critical", "high", "medium", "low", "info"))
RETEST = frozenset(("not_tested", "fix_pending", "fixed", "regression"))
MAX_CSV_BYTES = 1_048_576
MAX_FINDINGS = 350


def _validate_source(csv_text: str) -> bytes:
    """Only the original five-field tenant-export summary may enter the handoff."""
    if type(csv_text) is not str:
        raise ValueError("invalid source type")
    raw = csv_text.encode("utf-8")
    if not raw or len(raw) > MAX_CSV_BYTES or csv_text.startswith("\ufeff"):
        raise ValueError("invalid source size or header")
    rows = csv.reader(io.StringIO(csv_text, newline=""), strict=True)
    if tuple(next(rows, ())) != EXPECTED:
        raise ValueError("non-canonical original summary")
    seen: set[str] = set()
    count = 0
    for row in rows:
        if len(row) != 5:
            raise ValueError("malformed original finding")
        fid, title, severity, retest, remediation = row
        if (
            not fid.strip()
            or len(fid) > 160
            or fid in seen
            or not title.strip()
            or not remediation.strip()
            or any(len(col) > 6000 for col in row)
            or severity not in SEVERITIES
            or retest not in RETEST
        ):
            raise ValueError("invalid original finding record")
        seen.add(fid)
        count += 1
        if count > MAX_FINDINGS:
            raise ValueError("original finding count limit")
    if not count:
        raise ValueError("no authorized original findings")
    return raw


def _bundle_original_source(csv_text: str, *, root: Path) -> str:
    """Rebuild the immutable-source-pinned local Evidence Review; embed DATA only."""
    selected_bytes = _validate_source(csv_text)
    bundler = root / "remediation-evidence" / "package.py"
    if bundler.is_symlink() or not bundler.is_file():
        raise ValueError("original offline bundler unavailable")
    factory = runpy.run_path(str(bundler), run_name="lightup_evidence_bundle")["build"]
    html = factory().decode("utf-8")
    if html.count("</main>") != 1 or '<script id="preloadedCsv"' in html:
        raise ValueError("unexpected offline handoff document")
    encoded = json.dumps(
        {
            "format": "lightup.authenticated_findings_handoff_v1",
            "csv_base64": base64.b64encode(selected_bytes).decode("ascii"),
        },
        separators=(",", ":"),
    )
    # Passive application/json payload is base64 ASCII: no active JS or HTML
    # metacharacters. Static scripts remain tied to original SHA-256 CSP hashes.
    inert = '<script id="preloadedCsv" type="application/json">' + encoded + "</script>"
    return html.replace("</main>", "</main>" + inert, 1)


def _publish_exclusive_private(path: Path, html: str) -> None:
    """Publish a complete 0600 report atomically, refusing any existing destination."""
    if path.suffix.lower() != ".html":
        raise ValueError("private output must be a new .html file")
    fd, temporary = tempfile.mkstemp(prefix=".lightup-evidence-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
            out.write(html)
            out.flush()
            os.fsync(out.fileno())
        # Atomic no-replace publication: even symlink destinations already exist.
        os.link(temporary, path, follow_symlinks=False)
        try:
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory = os.open(str(path.parent), directory_flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.unlink(temporary)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create one offline Evidence Review HTML using current original "
                    "LightUp login and tenant/engagement-restricted findings export. "
                    "NEVER an authorization, scan, grant or retest."
    )
    parser.add_argument("--db", required=True, help="existing trusted LightUp database")
    parser.add_argument("--email", required=True, help="existing original account email")
    parser.add_argument("--client-id", required=True, help="existing client identifier")
    parser.add_argument("--engagement-id", required=True, help="exact existing engagement")
    parser.add_argument("--output", required=True, help="new private .html output (never overwrite)")
    args = parser.parse_args(argv)
    database = Path(args.db)
    output = Path(args.output)
    if not database.is_file():
        print("Export requires an existing original LightUp database.", file=sys.stderr)
        return 2
    if output.suffix.lower() != ".html" or not output.parent.is_dir() or output.exists() or output.is_symlink():
        print("Choose a new .html file in an existing private folder.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Interactive terminal required for secure password entry.", file=sys.stderr)
        return 2
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("LightUp password: ")
        store = DomainStore(str(database))
        user = store.authenticate(args.email, password)
        del password
        if user is None:
            print("Sign-in failed.", file=sys.stderr)
            return 2
        ctx = store.context_for_user(user.user_id)
        original_csv = render_client_findings_csv(
            store, ctx, args.client_id, engagement_id=args.engagement_id
        )
        private_html = _bundle_original_source(
            original_csv, root=Path(__file__).resolve().parents[2]
        )
        _publish_exclusive_private(output, private_html)
    except GetPassWarning:
        print("Secure password entry unavailable.", file=sys.stderr)
        return 2
    except AccountLockedError:
        print("Sign-in temporarily locked.", file=sys.stderr)
        return 2
    except (PermissionError, ValueError, KeyError, csv.Error, sqlite3.DatabaseError):
        print("Original authorization denied or selected summary is invalid.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("Private offline handoff unavailable; verify local output location.", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("Export cancelled.", file=sys.stderr)
        return 2
    print("Private offline Evidence Review HTML created (0600). Sensitive original "
          "finding summaries are embedded. Authentication occurred only at export "
          "time; this unsigned local copy is never a current grant, consent, "
          "verified repair, approved retest or scanner authorization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
