"""Create one self-contained *offline* remediation workspace from authorized findings.

Usage: python -m lightup.remediation_handoff_cli --db ... --email ... \
  --client-id ... --output /private/path/casework.html

Uses the EXISTING tenant-aware finding_export_service; never issues grants, touches
targets, changes persisted findings or upgrades local casework to an audit verdict.
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
import re
import secrets
import sqlite3
import sys
import warnings

from .domain import AccountLockedError, DomainStore
from .finding_export_service import render_client_findings_csv


MAX_FINDINGS = 350
MAX_CSV_BYTES = 1_048_576
ASSETS = (
    "remediation-engine.js",
    "remediation-schedule.js",
    "remediation-app.js",
)


def _bundle_workspace(csv_text: str, *, root: Path) -> str:
    """Bundle the already selected/redacted authorized summary, never raw evidence."""
    if type(csv_text) is not str:
        raise ValueError("source export must be a string")
    csv_bytes = csv_text.encode("utf-8")
    if len(csv_bytes) > MAX_CSV_BYTES:
        raise ValueError("authorized export exceeds offline workspace size bound")
    rows = csv.reader(io.StringIO(csv_text, newline=""))
    if next(rows, None) != [
        "finding_id", "title", "severity", "retest_status", "remediation"
    ]:
        raise ValueError("not a LightUp findings summary")
    count = 0
    for row in rows:
        if len(row) != 5 or not row[0] or not row[1] or not row[4]:
            raise ValueError("malformed finding summary")
        count += 1
        if count > MAX_FINDINGS:
            raise ValueError("authorized export exceeds offline finding limit")
    if count == 0:
        raise ValueError("no findings in the selected authorized scope")

    directory = root / "casework"
    html = (directory / "index.html").read_text(encoding="utf-8")
    nonce = secrets.token_urlsafe(22)
    marker = '<meta name="referrer" content="no-referrer">'
    if html.count(marker) != 1:
        raise ValueError("cannot locate offline browser security header")
    csp = (
        "default-src 'none'; script-src 'nonce-" + nonce + "'; "
        "style-src 'unsafe-inline'; img-src 'none'; "
        "connect-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    html = html.replace(
        marker, marker + '<meta http-equiv="Content-Security-Policy" '
        'content="' + csp + '">', 1
    )
    for name in ASSETS:
        external = '<script src="./' + name + '"></script>'
        if html.count(external) != 1:
            raise ValueError("missing local casework asset: " + name)
        source = (directory / name).read_text(encoding="utf-8")
        if re.search(r"</\s*script", source, flags=re.IGNORECASE):
            raise ValueError("unexpected HTML end marker inside local script")
        html = html.replace(
            external,
            '<script nonce="' + nonce + '">\n' + source + '\n</script>',
            1,
        )
    envelope = json.dumps(
        {
            "format": "lightup.authenticated_findings_handoff_v1",
            "csv_base64": base64.b64encode(csv_bytes).decode("ascii"),
        }, separators=(",", ":")
    )
    # Base64 is ASCII-only and cannot terminate this inert JSON script tag.
    bootstrap = (
        '<script id="preloadedCsv" type="application/json">'
        + envelope + '</script>'
    )
    if html.count("</main>") != 1:
        raise ValueError("invalid offline document structure")
    return html.replace("</main>", "</main>" + bootstrap, 1)


def _write_private_new_file(path: Path, text: str) -> None:
    """Create exclusively with 0600 permissions; never replace an existing file."""
    if path.suffix.lower() != ".html":
        raise ValueError("output must be a new .html file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate and render one client's selected findings into a "
            "private standalone offline remediation-planning HTML document"
        )
    )
    parser.add_argument("--db", required=True, help="existing LightUp domain database")
    parser.add_argument("--email", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--engagement-id", required=True, help="exact approved engagement, checked against selected client")
    parser.add_argument(
        "--output", required=True,
        help="new private .html file; existing files are never replaced",
    )
    args = parser.parse_args(argv)
    source_db = Path(args.db)
    output_path = Path(args.output)

    if not source_db.is_file():
        print("Export requires an existing domain database.", file=sys.stderr)
        return 2
    if output_path.suffix.lower() != ".html" or not output_path.parent.is_dir():
        print("Choose a new .html file in an existing private output folder.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Interactive terminal required for secure password entry.", file=sys.stderr)
        return 2

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("LightUp password: ")
        store = DomainStore(str(source_db))
        user = store.authenticate(args.email, password)
        del password
        if user is None:
            print("Sign-in failed.", file=sys.stderr)
            return 2
        # Current persisted identity/role/tenant resolution, same as original CLI.
        ctx = store.context_for_user(user.user_id)
        csv_text = render_client_findings_csv(
            store, ctx, args.client_id, engagement_id=args.engagement_id
        )
        html = _bundle_workspace(
            csv_text, root=Path(__file__).resolve().parents[2]
        )
        _write_private_new_file(output_path, html)
    except GetPassWarning:
        print("Secure password entry unavailable.", file=sys.stderr)
        return 2
    except AccountLockedError:
        print("Sign-in temporarily locked.", file=sys.stderr)
        return 2
    except (PermissionError, ValueError, KeyError, sqlite3.DatabaseError):
        print("Export denied or source data is invalid.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("Offline export unavailable; verify local files and private output path.", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("Export cancelled.", file=sys.stderr)
        return 2

    print(
        "Private offline remediation workspace created. Treat the HTML as "
        "sensitive; saved files do not prove current identity, consent, "
        "scope authorization or verified retest."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
