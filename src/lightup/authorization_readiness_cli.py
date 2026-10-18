"""Offline, authenticated operator-only authorization-readiness review.

No grant issuance, authorization decisions, execution, network traffic, or
database changes apart from existing authentication bookkeeping.
The report is a triage aid, never an authorization certificate.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from getpass import GetPassWarning, getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import warnings

from .domain import AccountLockedError, DomainStore

MAX_ROWS = 3000
MAX_OUTPUT = 2_000_000
AUTHORIZATION_FALSE = {
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "execution_allowed": False,
    "release_approved": False,
}


def _rows(con: sqlite3.Connection, sql: str):
    rows = con.execute(sql + " LIMIT ?", (MAX_ROWS + 1,)).fetchall()
    if len(rows) > MAX_ROWS:
        raise ValueError("review limit exceeded; use a smaller offline snapshot")
    return rows


def _assets(value: str) -> tuple[str, ...] | None:
    """Reject invalid source data; do not infer scope from repaired values."""
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return None
    if type(data) is not list or not data or len(data) > 80:
        return None
    if any(type(x) is not str or not x or x.strip() != x or len(x) > 253 for x in data):
        return None
    if len(data) != len(set(data)):
        return None
    return tuple(data)


def _covered(granted: str, requested: tuple[str, ...]) -> bool:
    """Conservative evidence of coverage, NOT runtime canonical authorization."""
    if granted in requested:
        return True
    try:
        child = ipaddress.ip_network(granted, strict=True)
    except ValueError:
        return False
    for root in requested:
        try:
            parent = ipaddress.ip_network(root, strict=True)
            if child.version == parent.version and child.subnet_of(parent):
                return True
        except ValueError:
            continue
    return False


def _candidate(grant: sqlite3.Row, request: sqlite3.Row) -> bool:
    if grant["client_id"] != request["client_id"]:
        return False
    if request["status"] != "approved" or request["requested_mode"] != "authorized_assessment":
        return False
    if not request["decided_at"] or not request["decided_by"]:
        return False
    if request["decided_by"] == request["requested_by"]:
        return False
    assets = _assets(request["requested_assets_json"])
    granted = _assets(grant["assets_json"])
    if assets is None or granted is None:
        return False
    try:
        risk = grant["max_risk"]
        approved_risk = request["requested_risk"]
        if type(risk) is not int or type(approved_risk) is not int:
            return False
        if not (1 <= risk <= approved_risk <= 4):
            return False
    except (ValueError, TypeError):
        return False
    return all(_covered(asset, assets) for asset in granted)


def _utc_window(grant: sqlite3.Row) -> str:
    try:
        start = datetime.fromisoformat(grant["valid_from"])
        end = datetime.fromisoformat(grant["valid_until"])
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            return "invalid"
        now = datetime.now(timezone.utc)
        return "future" if now < start else "expired" if now >= end else "within_window"
    except (TypeError, ValueError, OverflowError):
        return "invalid"


def _read_report(database: Path) -> dict:
    """Use one read-only SQLite transaction for an internally consistent view."""
    uri = database.resolve(strict=True).as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=4) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        clients = _rows(con, "SELECT client_id,name FROM clients ORDER BY name")
        engagements = _rows(con, "SELECT engagement_id,client_id,name,status FROM engagements ORDER BY created_at")
        requests = _rows(con, "SELECT request_id,client_id,requested_assets_json,requested_mode,requested_risk,status,requested_by,decided_by,decided_at FROM assessment_requests ORDER BY created_at")
        grants = _rows(con, "SELECT grant_id,client_id,engagement_id,assets_json,max_risk,valid_from,valid_until FROM authorization_grants ORDER BY created_at")
        con.rollback()

    by_client = {c["client_id"]: c["name"] for c in clients}
    by_engagement = {e["engagement_id"]: e for e in engagements}
    requests_by_client: dict[str, list] = defaultdict(list)
    for req in requests:
        requests_by_client[req["client_id"]].append(req)
    by_engagement_grants: dict[str, list] = defaultdict(list)
    for grant in grants:
        by_engagement_grants[grant["engagement_id"]].append(grant)

    counter = Counter()
    findings = []
    for engagement in engagements:
        own = engagement["client_id"]
        own_requests = requests_by_client[own]
        own_grants = by_engagement_grants[engagement["engagement_id"]]
        approved = sum(r["status"] == "approved" for r in own_requests)
        entry = {
            "client": by_client.get(own, "(missing client)"),
            "engagement": engagement["name"],
            "engagement_status": engagement["status"],
            "requests": len(own_requests),
            "approved_requests": approved,
            "grants": len(own_grants),
            "grant_findings": [],
        }
        if not own_grants:
            entry["attention"] = "No recorded grants; no authorization inferred."
        else:
            entry["attention"] = "Review existing grant records; none proves client/operator consent."
        for grant in own_grants:
            problems = ["UNBOUND_APPROVAL_REQUEST"]
            if grant["client_id"] != own:
                problems.append("TENANT_LINEAGE_MISMATCH")
            else:
                candidates = [r for r in own_requests if _candidate(grant, r)]
                if not candidates:
                    problems.append("NO_COMPATIBLE_APPROVED_REQUEST")
                elif len(candidates) > 1:
                    problems.append("AMBIGUOUS_APPROVED_REQUEST_MATCH")
                # Even exactly one candidate CANNOT bind this grant to that request.
            if _assets(grant["assets_json"]) is None:
                problems.append("INVALID_GRANT_ASSETS")
            window = _utc_window(grant)
            if window == "invalid":
                problems.append("INVALID_GRANT_WINDOW")
            elif window == "expired":
                problems.append("EXPIRED_GRANT_WINDOW")
            for flag in problems:
                counter[flag] += 1
            entry["grant_findings"].append({
                "grant_number": len(entry["grant_findings"]) + 1,
                "window": window,
                "flags": problems,
                "next_action": (
                    "Quarantine this record from client-visible authorization views; "
                    "require the domain source-owner lineage repair."
                    if "TENANT_LINEAGE_MISMATCH" in problems
                    else "Reconcile request identity, approved scope and genuine dual-party consent "
                    "through the domain source-owner workflow. Never issue or execute from this report."
                ),
            })
        if own_grants or own_requests:
            findings.append(entry)

    # Orphans cannot be safely attributed to any engagement or client.
    orphan_count = sum(g["engagement_id"] not in by_engagement for g in grants)
    counter["ORPHAN_GRANT"] = orphan_count
    report = {
        "format": "lightup.authorization_readiness_operator_v1",
        "disposition": "REVIEW_ONLY",
        "authority": AUTHORIZATION_FALSE.copy(),
        "limitations": [
            "Authenticated operator's local offline snapshot, not fresh consent evidence.",
            "There is no durable grant-to-approved-request foreign key in the current domain schema.",
            "A compatible requested asset/risk is only a conservative comparison; canonical scope, identity, ownership, approval provenance, and runtime revocation are not verified.",
            "A within_window grant is NOT currently authorized. Review does not issue, edit or revoke grants.",
            "All grant records remain unverified. Do not merge, deploy or scan on this report.",
        ],
        "summary": {
            "clients": len(clients),
            "engagements": len(engagements),
            "requests": len(requests),
            "grants": len(grants),
            "flag_counts": dict(sorted(counter.items())),
        },
        "engagements": findings,
    }
    return report


STYLE = """
:root{font:15px/1.5 system-ui,sans-serif;color:#e5edf5;background:#101729}
*{box-sizing:border-box}body{margin:0 auto;max-width:1380px;padding:28px 22px 80px}
header{border-bottom:1px solid #45526a;padding-bottom:18px;margin-bottom:24px}
h1{font-size:2.2rem;letter-spacing:-.04em;margin:4px 0}
h2{margin:0 0 8px}.sub{color:#b9cadb;max-width:930px}
.pill{display:inline-block;padding:5px 12px;border:1px solid #c9ab68;color:#f5da95;border-radius:24px;font-size:.8rem;font-weight:800}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:16px 0 30px}
.kpi{border:1px solid #354660;border-radius:12px;background:#17243a;padding:17px}
.kpi strong{display:block;font-size:2rem;color:#81d9c6}.kpi span{color:#b7c8d8}
.card{border:1px solid #425673;border-radius:14px;padding:21px;background:#17233a;margin-bottom:17px;break-inside:avoid}
.card h3{margin:0}.muted{color:#b7cadc}table{width:100%;border-collapse:collapse;margin-top:13px}
th,td{padding:11px;vertical-align:top;text-align:left;border-bottom:1px solid #35455c}
th{color:#bcd3e5;font-weight:700}.flag{display:inline-block;margin:2px 5px 2px 0;border:1px solid #a77176;color:#ffd5ca;border-radius:6px;padding:3px 7px;font-size:.8rem}
.warning{padding:15px;border-left:4px solid #e0a861;background:#34291d;margin:20px 0}
ol li{margin-bottom:7px}details{margin-top:16px}summary{cursor:pointer}
@media(max-width:750px){body{padding:15px}table{display:block;overflow-x:auto}.card{padding:14px}}
@media print{:root{background:white;color:black}.card,.kpi{background:white;color:black}.sub,.muted{color:#444}.flag{color:black}.pill{color:black}.kpi strong{color:black}body{padding:0}}
"""


def _render_html(report: dict) -> str:
    nonce = secrets.token_urlsafe(24)
    esc = lambda item: html.escape(str(item), quote=True)
    summary = report["summary"]
    cards = "".join(
        '<div class="kpi"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>'
        for label, value in (
            ("Clients", summary["clients"]),
            ("Engagements", summary["engagements"]),
            ("Requests", summary["requests"]),
            ("Unverified grants", summary["grants"]),
            ("Tenant mismatches", summary["flag_counts"].get("TENANT_LINEAGE_MISMATCH", 0)),
            ("Unmatched requests", summary["flag_counts"].get("NO_COMPATIBLE_APPROVED_REQUEST", 0)),
        )
    )
    blocks = []
    for record in report["engagements"]:
        trs = "".join(
            "<tr><td>" + esc(g["grant_number"]) + "</td><td>" + esc(g["window"]) +
            "</td><td>" + " ".join('<span class="flag">' + esc(flag) + "</span>" for flag in g["flags"]) +
            "</td><td>" + esc(g["next_action"]) + "</td></tr>"
            for g in record["grant_findings"]
        )
        table = (
            "<table><thead><tr><th>Record #</th><th>Time-window record</th><th>Review flags</th><th>Required next action</th></tr></thead>"
            "<tbody>" + trs + "</tbody></table>"
        ) if trs else '<p class="muted">No grant rows. No permission implied.</p>'
        blocks.append(
            '<section class="card"><h3>' + esc(record["client"]) + " / " + esc(record["engagement"]) + "</h3>"
            '<p class="muted">Engagement: ' + esc(record["engagement_status"]) +
            " · Requests: " + esc(record["requests"]) +
            " · Recorded approvals: " + esc(record["approved_requests"]) +
            " · Grants: " + esc(record["grants"]) + "</p>"
            "<p>" + esc(record["attention"]) + "</p>" + table + "</section>"
        )
    limits = "".join("<li>" + esc(l) + "</li>" for l in report["limitations"])
    csp = "default-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" content="' + esc(csp) + '">'
        "<title>LightUp · Authorization Readiness Desk</title>"
        '<style nonce="' + nonce + '">' + STYLE + "</style></head><body>"
        '<header><span class="pill">REVIEW ONLY · ZERO AUTHORITY</span>'
        "<h1>Authorization Readiness Desk</h1>"
        '<p class="sub">Private, authenticated operator triage of stored assessment requests '
        "and grant lineage. This is a static offline report, not permission or a security verdict.</p></header>"
        '<main><section class="grid">' + cards + "</section>"
        '<div class="warning"><strong>HOLD:</strong> The existing domain has no durable approved request → '
        "grant link. Even a compatible record is UNBOUND; independent client/operator consent, "
        "at-use revocation and all release gates remain mandatory. Never contact a target based on this export.</div>"
        "<h2>Engagement review queue</h2>" + ("".join(blocks) or "<p>No engagements with recorded requests/grants.</p>") +
        "<details><summary>Limits, mandatory owner work and data handling</summary><ol>" +
        limits + "</ol><p>Owner follow-ups: #177 request-to-grant binding, #829 grant tenant-lineage reads, "
        "#182 default web admission. This report repairs none of them.</p>"
        "<p>Contains private client/engagement names; keep mode 0600, do not host or share publicly.</p>"
        "</details></main></body></html>"
    )


def _save_new_private(path: Path, contents: str) -> None:
    if len(contents.encode("utf-8")) > MAX_OUTPUT:
        raise ValueError("report too large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as target:
            target.write(contents)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Private operator review; NEVER grants execution authority.")
    parser.add_argument("--db", required=True, help="existing LightUp database, not a new database")
    parser.add_argument("--email", required=True, help="operator account")
    parser.add_argument("--output", required=True, help="new private .html or .json file; never overwritten")
    args = parser.parse_args(argv)
    path = Path(args.output)
    db = Path(args.db)
    if not db.is_file() or not path.parent.is_dir() or path.suffix.lower() not in {".html", ".json"}:
        print("Existing LightUp database and new .html/.json file in a private directory required.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Interactive terminal required; password cannot be supplied as an argument.", file=sys.stderr)
        return 2
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("LightUp operator password: ")
        store = DomainStore(str(db))
        user = store.authenticate(args.email, password)
        del password
        if user is None:
            raise PermissionError("authentication failed")
        ctx = store.context_for_user(user.user_id)
        ctx.require_operator("authorization readiness review")
        report = _read_report(db)
        text = _render_html(report) if path.suffix.lower() == ".html" else json.dumps(
            report, ensure_ascii=False, indent=2
        ) + "\n"
        _save_new_private(path, text)
    except (PermissionError, AccountLockedError, ValueError, sqlite3.DatabaseError,
            OSError, EOFError, KeyboardInterrupt, GetPassWarning):
        print("HOLD: authentication, source integrity or private export requirements not met.", file=sys.stderr)
        return 2
    print("REVIEW_ONLY: private operator report created; no grant, consent, scan or release authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
