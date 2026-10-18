"""Authenticated, read-only operator grant-request selection preview.

Consumes the canonical source-owner #1570 approved_request_is_compatible,
without recording grants or touching scans, handlers, approvals or live targets.
INCUBATE / PLAN-LAB ONLY / REVIEW_ONLY / DRAFT-HOLD.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing, nullcontext
from datetime import datetime, timezone
import csv
from getpass import getpass, GetPassWarning
import hashlib
from html import escape
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import unicodedata
import warnings
from urllib.parse import quote

from .domain import AccountLockedError, DomainStore
from .grant_request_binding import (_asset, approved_request_is_compatible,
                                    assets_within_approved_request)

MAX_ROWS = 500
MAX_BYTES = 2_000_000
AUTHORITY = {
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "execution_allowed": False,
    "release_approved": False,
}


def _read_only(db: Path) -> sqlite3.Connection:
    """Opened only after actual operator authentication; never use in production."""
    uri = "file:" + quote(str(db.resolve()), safe="/") + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("BEGIN")
    return con


def _assets(raw: list[str]) -> tuple[str, ...]:
    if not 1 <= len(raw) <= 80 or any(type(x) is not str for x in raw):
        raise ValueError("1–80 explicit canonical literals required")
    if len(set(raw)) != len(raw):
        raise ValueError("duplicate proposed literals")
    for item in raw:
        kind, original = _asset(item)
        if kind == "host" and original != item:
            raise ValueError("hostname case must be already canonical")
        if kind == "network" and str(original) != (
            item if "/" in item else item + ("/32" if original.version == 4 else "/128")
        ):
            # Canonical explicit network spelling, no silently normalized CIDR.
            raise ValueError("IP/network must be in canonical spelling")
    return tuple(raw)


def _explain_source_mismatch(row: sqlite3.Row, *, client_id: str,
                             assets: tuple[str, ...], risk: int,
                             now: str, compatible: bool) -> list[str]:
    """Human-only classifications; never an alternative authorization evaluator."""
    if row["status"] != "approved":
        return ["NOT_ADMINISTRATIVELY_APPROVED"]
    reasons = []
    if row["requested_mode"] != "authorized_assessment":
        reasons.append("REQUEST_MODE_NOT_AUTHORIZED_ASSESSMENT")
    if (row["client_id"] != client_id
            or row["requester_role"] not in ("client_admin", "client_member")
            or row["requester_client"] != client_id
            or row["reviewer_role"] != "operator"
            or row["reviewer_client"] is not None
            or row["requested_by"] == row["decided_by"]):
        reasons.append("SOURCE_ROLE_OR_TENANT_PROVENANCE_MISMATCH")
    claimed_risk = row["requested_risk"]
    if type(claimed_risk) is not int or not (1 <= risk <= claimed_risk <= 4):
        reasons.append("PROPOSED_RISK_NOT_COVERED")
    if not assets_within_approved_request(row["requested_assets_json"], assets):
        reasons.append("PROPOSED_LITERAL_SCOPE_NOT_COVERED")
    try:
        created = datetime.fromisoformat(row["created_at"])
        decided = datetime.fromisoformat(row["decided_at"])
        observed = datetime.fromisoformat(now)
        if (any(dt.tzinfo is None or dt.utcoffset() is None
                for dt in (created, decided, observed))
                or not created <= decided <= observed):
            reasons.append("DECISION_CHRONOLOGY_INVALID")
    except (TypeError, ValueError, OverflowError):
        reasons.append("DECISION_CHRONOLOGY_INVALID")
    if compatible:
        # The installed owner predicate is the sole source of match truth.
        return []
    return reasons or ["SOURCE_OWNER_OTHER_INTEGRITY_CHECK_REQUIRED"]


def _private_output(path: Path, body: str) -> None:
    if len(body.encode("utf-8")) > MAX_BYTES:
        raise ValueError("bounded private report exceeded")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(body)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _source_snapshot(db: Path, *, engagement_id: str, client_id: str | None,
                     assets: tuple[str, ...], risk: int,
                     include_request_ids: bool, include_labels: bool, operator_user_id: str,
                     connection: sqlite3.Connection | None = None) -> dict:
    with (closing(_read_only(db)) if connection is None else nullcontext(connection)) as con:
        operator = con.execute(
            "SELECT role,client_id FROM users WHERE user_id=?",
            (operator_user_id,)
        ).fetchone()
        if operator is None or operator["role"] != "operator" or operator["client_id"] is not None:
            raise PermissionError("operator role no longer valid in persisted source")
        engagement = con.execute(
            "SELECT e.engagement_id, e.client_id, e.name, e.status, "
            "c.name AS client_name, c.status AS client_status "
            "FROM engagements AS e JOIN clients AS c ON c.client_id=e.client_id "
            "WHERE e.engagement_id=?", (engagement_id,)
        ).fetchone()
        if engagement is None:
            raise ValueError("unknown engagement")
        if client_id is not None and engagement["client_id"] != client_id:
            raise ValueError("selected tenant differs from actual engagement owner")
        if engagement["status"] == "closed" or engagement["client_status"] != "active":
            # Selecting a closed/inactive source never produces a shortlist.
            raise ValueError("closed engagement or inactive client: no candidates")
        operator_requests = con.execute(
            "SELECT r.*, issuer.role AS requester_role, "
            "issuer.client_id AS requester_client, "
            "reviewer.role AS reviewer_role, reviewer.client_id AS reviewer_client "
            "FROM assessment_requests AS r "
            "LEFT JOIN users AS issuer ON issuer.user_id=r.requested_by "
            "LEFT JOIN users AS reviewer ON reviewer.user_id=r.decided_by "
            "WHERE r.client_id=? ORDER BY r.created_at DESC LIMIT ?",
            (engagement["client_id"], MAX_ROWS + 1),
        ).fetchall()
        if len(operator_requests) > MAX_ROWS:
            raise ValueError("too many stored requests; narrow source offline")
        grants = con.execute(
            "SELECT grant_id,client_id,approved_request_id FROM authorization_grants "
            "WHERE engagement_id=? LIMIT ?", (engagement_id, MAX_ROWS + 1)
        ).fetchall()
        if len(grants) > MAX_ROWS:
            raise ValueError("too many stored grants; narrow source offline")
        if any(
            type(g["grant_id"]) is not str or not 1 <= len(g["grant_id"]) <= 180
            or (g["approved_request_id"] is not None
                and (type(g["approved_request_id"]) is not str
                     or not 1 <= len(g["approved_request_id"]) <= 180))
            for g in grants
        ):
            raise ValueError("malformed stored grant/request lineage identity")
        cross_tenant = sum(g["client_id"] != engagement["client_id"] for g in grants)
        if cross_tenant:
            # Do not expose even a plausible shortlist amid tenant corruption.
            raise ValueError("cross-tenant persisted grant lineage: source HOLD")
        bound = Counter(g["approved_request_id"] for g in grants
                        if g["approved_request_id"] is not None)
        legacy_grants = sum(g["approved_request_id"] is None for g in grants)

        now = datetime.now(timezone.utc).isoformat()
        items = []
        matched = []
        for ordinal, request in enumerate(operator_requests, 1):
            request_id = request["request_id"]
            if (type(request_id) is not str or not (1 <= len(request_id) <= 180)
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in request_id)):
                raise ValueError("malformed stored request identity")
            approved = request["status"] == "approved"
            compatible = approved and approved_request_is_compatible(
                request,
                client_id=engagement["client_id"],
                grant_assets=assets,
                grant_max_risk=risk,
                grant_created_at=now,
            )
            if compatible:
                matched.append(request["request_id"])
            reasons = _explain_source_mismatch(
                request, client_id=engagement["client_id"], assets=assets,
                risk=risk, now=now, compatible=compatible,
            )
            token = hashlib.sha256(
                ("lightup.private.request-review.v1:" + request["request_id"]).encode("utf-8")
            ).hexdigest()[:16]
            item = {
                "ordinal": ordinal,
                "private_reference": token,
                "request_id": request["request_id"] if include_request_ids else None,
                "stored_status": request["status"],
                "requested_risk": request["requested_risk"] if type(request["requested_risk"]) is int else None,
                "request_source_status": (
                    "candidate_review_only" if compatible else
                    "approved_but_not_compatible" if approved else
                    "not_administratively_approved"
                ),
                "previously_bound_grant_rows": bound[request["request_id"]],
                "review_flags_non_authorizing": reasons,
                "review_action": (
                    "Reconfirm independently with actual client and operator and "
                    "request-to-grant source owner; do not infer consent or grant authority."
                    if compatible else
                    "Resolve missing or mismatched approval, asset, risk, timing or "
                    "identity with the original owners; never silently widen scope."
                ),
            }
            items.append(item)

        # Bind this unsigned offline snapshot to the ORIGINAL stored request
        # and grant row values, not only the user's proposed scope parameters.
        # IDs are UUID-derived original stored identities; no source contents
        # are exported through this digest and it never proves authenticity.
        try:
            source_wire = json.dumps({
                "schema": "lightup.request-binding-source-rows.v1",
                "engagement": dict(engagement),
                "original_requests": [
                    dict(r) for r in sorted(operator_requests,
                                             key=lambda x: x["request_id"])
                ],
                "original_grants": [
                    dict(g) for g in sorted(grants, key=lambda x: x["grant_id"])
                ],
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
               allow_nan=False).encode("ascii")
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("malformed stored source record for fingerprint") from error
        if len(source_wire) > MAX_BYTES:
            raise ValueError("source revision too large for private review")
        source_revision = hashlib.sha256(source_wire).hexdigest()
        selection = hashlib.sha256(json.dumps(
            ["lightup.request-binding-review-selection.v1",
             engagement["client_id"], engagement_id, list(assets), risk],
            ensure_ascii=True, separators=(",", ":"),
        ).encode("ascii")).hexdigest()
        mismatch_reasons = Counter(
            reason for entry in items for reason in entry["review_flags_non_authorizing"]
        )
        summary = {
            "mismatch_reason_counts_non_authorizing": dict(sorted(mismatch_reasons.items())),
            "recorded_requests": len(operator_requests),
            "approved_candidate_matches": len(matched),
            "approved_but_not_compatible": sum(
                x["request_source_status"] == "approved_but_not_compatible" for x in items
            ),
            "not_administratively_approved": sum(
                x["request_source_status"] == "not_administratively_approved" for x in items
            ),
            "prior_stored_grant_rows": len(grants),
            "unbound_legacy_grant_rows": legacy_grants,
        }
        disposition = (
            "REVIEW_ONLY_SINGLE_CANDIDATE" if len(matched) == 1 else
            "HOLD_AMBIGUOUS_CANDIDATES" if len(matched) > 1 else
            "HOLD_NO_CANDIDATE"
        )
        report = {
            "format": "lightup.request_binding_preparation.v1",
            "disposition": disposition,
            "authority": dict(AUTHORITY),
            "source": {
                "source_owner_ref": "PR-1570",
                "request_selection_digest_unsigned": selection,
                "source_revision_sha256_unsigned": source_revision,
                "review_instant_utc": now,
                "engagement": engagement["name"] if include_labels else "Engagement 001",
                "client": engagement["client_name"] if include_labels else "Client 001",
                "requested_risk": risk,
                "proposed_asset_count": len(assets),
            },
            "summary": summary,
            "candidates": items,
            "caveats": [
                "This private operator-authenticated snapshot is NOT a client signature or permission.",
                "One matching administrative request does NOT issue a grant.",
                "Every request, issuer identity, proposed scope and risk must be rechecked "
                "inside the later source-owner write transaction.",
                "Consent must be independent and authenticated for both client/operator; "
                "revocation must be checked at actual use.",
                "No target access, scan, handler, issuer, release, revocation or grant was invoked.",
                "Legacy unbound grants and earlier grant rows are not proof of current authorization.",
            ],
        }
        return report


def _html(report: dict) -> str:
    def esc(v: object) -> str:
        return escape(str(v), quote=True)

    cells = []
    for row in report["candidates"]:
        cells.append("<tr>" + "".join(
            "<td>" + esc(v) + "</td>" for v in (
                row["ordinal"], row["private_reference"],
                row["request_id"] or "redacted",
                row["stored_status"], row["requested_risk"],
                row["request_source_status"],
                ", ".join(row["review_flags_non_authorizing"]) or "NO_RECORDED_MISMATCH",
                row["previously_bound_grant_rows"], row["review_action"],
            )
        ) + "</tr>")
    source, summary = report["source"], report["summary"]
    css = (":root{font:15px/1.5 system-ui;color:#e6eef9;background:#101729}"
           "body{max-width:1140px;margin:0 auto;padding:26px}"
           "h1{font-size:2.3rem;letter-spacing:-.03em}"
           "section{padding:20px;border:1px solid #405472;border-radius:12px;"
           "background:#1b2b40;margin:22px 0}p{color:#cbdcec}"
           "table{border-collapse:collapse;width:100%}"
           "td,th{padding:9px;text-align:left;border-bottom:1px solid #435874}"
           "td{overflow-wrap:anywhere}strong{color:#ffc79e}th{color:#cce4ff}"
           "@media(max-width:750px){body{padding:10px}table{display:block;overflow-x:auto}}"
           "@media print{body{background:white;color:black}section{background:white}"
           "strong,p{color:black}}")
    import base64
    sri = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'base-uri &#39;none&#39;; form-action &#39;none&#39;; '
        'style-src &#39;sha256-' + sri + '&#39;; '
        'connect-src &#39;none&#39;; script-src &#39;none&#39;; object-src &#39;none&#39;">'
        '<title>LightUp · Operator Request Binding Readiness</title>'
        "<style>" + css + "</style></head><body>"
        "<header><p>LIGHTUP / PRIVATE OPERATOR / REVIEW_ONLY</p>"
        "<h1>Approved-request selection readiness</h1>"
        "<p><strong>ADMINISTRATIVE MATCH ≠ CONSENT, GRANT OR EXECUTION AUTHORITY.</strong> "
        "Offline copy. No scan, no targeting, no mutation.</p></header>"
        "<section><h2>Source and proposed non-authorizing scope</h2><p>Client: "
        + esc(source["client"]) + " · Engagement: " + esc(source["engagement"]) +
        " · proposed assets (count only): " + str(source["proposed_asset_count"]) +
        " · proposed risk: " + str(source["requested_risk"]) + "</p>"
        "<p>Disposition: <strong>" + esc(report["disposition"]) + "</strong></p>"
        "<p>Original stored-row fingerprint (unsigned; private, NOT "
        "authentication): <code>" +
        esc(source["source_revision_sha256_unsigned"]) + "</code></p>"
        "<p>Stored requests: " + str(summary["recorded_requests"]) +
        " · matching candidates: " + str(summary["approved_candidate_matches"]) +
        " · stored grant rows: " + str(summary["prior_stored_grant_rows"]) +
        " · unbound legacy rows: " + str(summary["unbound_legacy_grant_rows"]) +
        "</p><p>Original source mismatch themes (human explanation only): "
        + esc(", ".join(k + ": " + str(v)
                        for k, v in summary["mismatch_reason_counts_non_authorizing"].items())
              or "No recorded mismatch categories") +
        "</p></section>"
        "<section><h2>Historical requests for independent review</h2>"
        "<div style='overflow-x:auto'><table><thead><tr><th>#</th><th>Private token</th>"
        "<th>Request ID (opt-in)</th><th>Admin status</th><th>Requested risk</th>"
        "<th>Offline match</th><th>Reasons (human only)</th><th>Previously linked stored grants</th><th>Human follow-up</th>"
        "</tr></thead><tbody>" + "".join(cells) +
        "</tbody></table></div></section><section><h2>Required human controls</h2><ol>"
        + "".join("<li>" + esc(v) + "</li>" for v in report["caveats"]) +
        "</ol></section><footer>DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY. "
        "Original hosted/VPS CI, security/privacy, real two-party consent and "
        "at-use revoke plus HUMAN GO stay mandatory.</footer></body></html>"
    )


def _safe_spreadsheet_cell(value: object) -> object:
    if type(value) is not str:
        return value
    # Inspect NFKC text while stripping zero-width controls and combining
    # format marks: a hidden mark before =, +, - or @ cannot hide a formula.
    inspection = unicodedata.normalize("NFKC", value)
    inspection = "".join(ch for ch in inspection if unicodedata.category(ch)
                         not in {"Mn", "Me", "Cf", "Cc"})
    inspection = inspection.lstrip()
    if inspection.startswith(("=", "+", "-", "@")) or value.startswith(
            ("\t", "\r", "\n", "\ufeff")):
        return "'" + value
    return value


def _csv(report: dict) -> str:
    stream = io.StringIO(newline="")
    w = csv.writer(stream, lineterminator="\r\n")
    cols = ("ordinal", "private_reference", "request_id", "stored_status",
            "requested_risk", "request_source_status", "review_flags_non_authorizing",
            "previously_bound_grant_rows")
    w.writerow(cols + ("review_only", "consent_verified", "grant_issued", "execution_allowed"))
    for row in report["candidates"]:
        values = [(";".join(row[k]) if k == "review_flags_non_authorizing" else
                   row[k] if row[k] is not None else "") for k in cols]
        # Every nonnumeric cell is escaped to prevent spreadsheet formulas.
        safe = [_safe_spreadsheet_cell(v) for v in values]
        w.writerow(safe + ["REVIEW_ONLY", "false", "false", "false"])
    return stream.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Original source read-only binding-preparation desk; NEVER issue grants.")
    parser.add_argument("--db", required=True, help="existing LightUp DB")
    parser.add_argument("--email", required=True, help="current persisted real operator")
    parser.add_argument("--engagement-id", required=True, help="real pre-existing engagement")
    parser.add_argument("--client-id", help="optional expected tenant consistency assertion")
    parser.add_argument("--asset", action="append", help="canonical proposed host/IP/CIDR literal; repeat")
    parser.add_argument("--risk", type=int, choices=range(1, 5))
    parser.add_argument("--scenarios-file", help="optional 2–8 bounded alternative risk/scope proposals JSON")
    parser.add_argument("--studio-proposal", action="append", help="import 1–8 original separately authored Studio v1 DRAFT_ONLY JSON files without editing source proposals")
    parser.add_argument("--output", required=True, help="new, private .json, .html, .csv or .md filename")
    parser.add_argument("--static-html", action="store_true",
                        help="original no-JavaScript HTML, instead of offline interactive operator desk")
    parser.add_argument("--include-request-ids", action="store_true", help="private original IDs for human reconciliation")
    parser.add_argument("--include-labels", action="store_true", help="private original client/engagement labels")
    args = parser.parse_args(argv)

    db, out = Path(args.db), Path(args.output)
    if (db.is_symlink() or not db.is_file() or not stat.S_ISREG(db.stat().st_mode)
            or out.suffix.lower() not in {".html", ".json", ".csv", ".md"}
            or out.exists() or not out.parent.is_dir()
            or not sys.stdin.isatty()):
        print("HOLD: require existing regular database, interactive operator and a new private output.", file=sys.stderr)
        return 2
    try:
        if args.studio_proposal:
            if args.scenarios_file is not None or args.asset is not None or args.risk is not None:
                raise ValueError("Studio import cannot mix with manually proposed assets/risk")
            from .request_binding_studio_import import read_studio_proposals
            proposals = read_studio_proposals([Path(x) for x in args.studio_proposal])
            if len(proposals) == 1:
                _, assets, risk = proposals[0]
                args.risk = risk
                scenarios = None
            else:
                scenarios = proposals
                assets = None
        elif args.scenarios_file is not None:
            if args.asset is not None or args.risk is not None:
                raise ValueError("scenario file cannot be mixed with single proposal flags")
            from .request_binding_scenarios import read_scenarios
            scenarios = read_scenarios(Path(args.scenarios_file))
            assets = None
        else:
            if args.asset is None or args.risk is None:
                raise ValueError("single scenario requires assets and risk")
            assets = _assets(args.asset)
            scenarios = None
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("LightUp operator password: ")
        # Existing source-owner credential lockout bookkeeping is preserved.
        store = DomainStore(str(db))
        user = store.authenticate(args.email, password)
        del password
        if user is None:
            raise PermissionError("invalid operator")
        ctx = store.context_for_user(user.user_id)
        ctx.require_operator("offline approved-request selection preview")
        kind = out.suffix.lower()
        if scenarios is not None:
            from .request_binding_scenarios import (
                compare_scenarios, format_html, format_csv, format_json
            )
            report = compare_scenarios(
                db, engagement_id=args.engagement_id, client_id=args.client_id,
                scenarios=scenarios, operator_user_id=user.user_id,
                include_request_ids=args.include_request_ids,
                include_labels=args.include_labels,
            )
            body = (format_html(report) if kind == ".html" else
                    format_csv(report) if kind == ".csv" else format_json(report))
        else:
            report = _source_snapshot(
                db, engagement_id=args.engagement_id, client_id=args.client_id,
                assets=assets, risk=args.risk,
                include_request_ids=args.include_request_ids,
                include_labels=args.include_labels,
                operator_user_id=user.user_id,
            )
            body = (_html(report) if kind == ".html" else
                    _csv(report) if kind == ".csv" else
                    json.dumps(report, indent=2, ensure_ascii=True) + "\n")
        if kind == ".html" and not args.static_html:
            from .request_binding_workspace import render
            body = render(report)
        if kind == ".md":
            from .request_binding_handoff import format_markdown
            body = format_markdown(report)
        _private_output(out, body)
    except (ValueError, PermissionError, AccountLockedError, sqlite3.DatabaseError,
            OSError, EOFError, KeyboardInterrupt, GetPassWarning):
        print("HOLD: operator authentication or original-source request-binding integrity.", file=sys.stderr)
        return 2
    print("REVIEW_ONLY: private request-binding shortlist; NO grant/consent/scan/execution/release.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
