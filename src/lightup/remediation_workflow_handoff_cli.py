"""Private authenticated-at-export LightUp Remediation Coordination Cockpit.

This is a read-only original tenant/engagement findings export, not a new
authorization provider, consent mechanism, scan, retest or live dashboard.
The saved HTML contains sensitive client summary data in cleartext.
"""
from __future__ import annotations

import argparse
import base64
import csv
from getpass import getpass, GetPassWarning
import json
import os
from pathlib import Path
import runpy
import sqlite3
import sys
import warnings

from .domain import AccountLockedError, DomainStore
from .finding_export_service import render_client_findings_csv
from .evidence_review_handoff_cli import _validate_source, _publish_exclusive_private


def _build_private_cockpit(original_csv: str, *, root: Path) -> str:
    """Package original, SHA-pinned offline scripts and embed passive CSV only."""
    raw = _validate_source(original_csv)
    package = root / "remediation-workflow" / "package.py"
    if package.is_symlink() or not package.is_file():
        raise ValueError("trusted standalone source package unavailable")
    bundle = runpy.run_path(str(package), run_name="lightup_workflow_source")["build"]()
    html = bundle.decode("utf-8")
    if html.count("</main>") != 1 or 'id="preloadedCsv"' in html:
        raise ValueError("unexpected original offline source structure")
    payload = json.dumps(
        {
            "format": "lightup.authenticated_findings_handoff_v1",
            "csv_base64": base64.b64encode(raw).decode("ascii"),
        },
        separators=(",", ":"),
    )
    # JSON base64 ASCII is inert; no executable script, token, role or grant.
    inert = '<script id="preloadedCsv" type="application/json">' + payload + "</script>"
    return html.replace("</main>", "</main>" + inert, 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a PRIVATE offline remediation cockpit with the "
        "original authenticated tenant/engagement finding export. "
        "NO scan, grant, consent, approval or verified retest."
    )
    parser.add_argument("--db", required=True, help="existing trusted LightUp SQLite database")
    parser.add_argument("--email", required=True, help="existing original account email")
    parser.add_argument("--client-id", required=True, help="selected original client ID")
    parser.add_argument("--engagement-id", required=True, help="exact original assessment engagement ID")
    parser.add_argument("--output", required=True, help="new private HTML path, never overwrite")
    args = parser.parse_args(argv)
    db = Path(args.db)
    output = Path(args.output)
    if not db.is_file():
        print("Export requires an existing original LightUp database.", file=sys.stderr)
        return 2
    if output.suffix.lower() != ".html" or not output.parent.is_dir() or output.exists() or output.is_symlink():
        print("Choose a new .html path in an existing private directory.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Interactive terminal is required for private password entry.", file=sys.stderr)
        return 2
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("LightUp password: ")
        store = DomainStore(str(db))
        user = store.authenticate(args.email, password)
        del password
        if user is None:
            print("Sign-in failed.", file=sys.stderr)
            return 2
        ctx = store.context_for_user(user.user_id)
        original_csv = render_client_findings_csv(
            store, ctx, args.client_id, engagement_id=args.engagement_id
        )
        html = _build_private_cockpit(
            original_csv, root=Path(__file__).resolve().parents[2]
        )
        _publish_exclusive_private(output, html)
    except (AccountLockedError, GetPassWarning):
        print("Sign-in temporarily unavailable or locked.", file=sys.stderr)
        return 2
    except (PermissionError, ValueError, KeyError, csv.Error, sqlite3.DatabaseError):
        print("Original access denied or findings summary invalid.", file=sys.stderr)
        return 2
    except (UnicodeError, OSError):
        print("Private output unavailable; inspect your trusted local path.", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("Private export cancelled.", file=sys.stderr)
        return 2
    print(
        "Private Coordination Cockpit created (0600). Original findings are "
        "embedded. Authentication was at EXPORT TIME only; this HTML is NOT "
        "a current grant, consent, a verified patch or a retest authorization."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
