"""Offline, authenticated operator-only authorization-readiness review.

No grant issuance, authorization decisions, execution, network traffic, or
database changes apart from existing authentication bookkeeping.
The report is a triage aid, never an authorization certificate.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from collections import Counter, defaultdict
from contextlib import closing
import csv
from datetime import datetime, timezone
from getpass import GetPassWarning, getpass
import html
import io
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


def _rows(con: sqlite3.Connection, sql: str, params: tuple = ()):
    rows = con.execute(sql + " LIMIT ?", (*params, MAX_ROWS + 1)).fetchall()
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


def _time(value: str) -> datetime | None:
    try:
        result = datetime.fromisoformat(value)
        return result if result.tzinfo is not None and result.utcoffset() is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _valid_requester(request: sqlite3.Row, users: dict) -> bool:
    user = users.get(request["requested_by"])
    return bool(
        user is not None and user["role"] in {"client_admin", "client_member"}
        and user["client_id"] == request["client_id"]
    )


def _trusted_request_origin(request: sqlite3.Row, users: dict) -> bool:
    """Current stored user roles are corroboration, never immutable consent proof."""
    requester = users.get(request["requested_by"])
    reviewer = users.get(request["decided_by"])
    return bool(
        _valid_requester(request, users) and reviewer is not None
        and reviewer["role"] == "operator" and reviewer["client_id"] is None
        and request["requested_by"] != request["decided_by"]
    )


def _candidate(grant: sqlite3.Row, request: sqlite3.Row, users: dict) -> bool:
    if grant["client_id"] != request["client_id"]:
        return False
    if request["status"] != "approved" or request["requested_mode"] != "authorized_assessment":
        return False
    if not request["decided_at"] or not request["decided_by"]:
        return False
    if not _trusted_request_origin(request, users):
        return False
    issued = _time(grant["created_at"])
    decided = _time(request["decided_at"])
    if issued is None or decided is None or decided >= issued:
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


def _record_identity(kind: str, record_id: str) -> str:
    """Stable private UUID-derived review key; never an authorization claim."""
    if type(record_id) is not str or not record_id or len(record_id) > 180:
        raise ValueError("stored review identity is missing or malformed")
    return hashlib.sha256(("lightup.readiness.identity.v1:" + kind + ":" + record_id).encode("utf-8")).hexdigest()


def _read_report(database: Path, *, client_id: str | None = None,
                 engagement_id: str | None = None) -> dict:
    """Read one operator-selected scope inside one bounded, read-only transaction.

    SQL-level selection avoids reading all other tenants before post-filtering,
    while grant selection follows the owning engagement rather than the duplicated
    (potentially corrupt) authorization_grants.client_id.
    """
    uri = database.resolve(strict=True).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=4)) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        columns = {
            info["name"] for info in con.execute(
                "PRAGMA table_info(authorization_grants)"
            ).fetchall()
        }
        # Compatible with both the old unbound SQLite schema and the future
        # owner-composed durable request→grant binding from #177.
        binding_projection = (
            "g.approved_request_id" if "approved_request_id" in columns
            else "NULL AS approved_request_id"
        )
        grant_projection = (
            "g.grant_id,g.client_id,g.engagement_id,g.assets_json,g.max_risk,"
            "g.valid_from,g.valid_until,g.created_at," + binding_projection
        )
        if engagement_id is not None:
            selected = con.execute(
                "SELECT client_id FROM engagements WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()
            if selected is None:
                raise ValueError("selected engagement missing")
            if client_id is not None and selected["client_id"] != client_id:
                raise ValueError("engagement does not belong to selected client")
            client_id = selected["client_id"]
        if client_id is not None:
            clients = _rows(con, "SELECT client_id,name FROM clients WHERE client_id=? ORDER BY name", (client_id,))
            if len(clients) != 1:
                raise ValueError("selected client missing")
            if engagement_id is not None:
                engagements = _rows(
                    con, "SELECT engagement_id,client_id,name,status FROM engagements "
                         "WHERE client_id=? AND engagement_id=? ORDER BY created_at",
                    (client_id, engagement_id),
                )
                grants = _rows(
                    con, "SELECT " + grant_projection + " FROM authorization_grants AS g "
                         "WHERE g.engagement_id=? ORDER BY g.created_at",
                    (engagement_id,),
                )
            else:
                engagements = _rows(
                    con, "SELECT engagement_id,client_id,name,status FROM engagements "
                         "WHERE client_id=? ORDER BY created_at", (client_id,),
                )
                grants = _rows(
                    con, "SELECT " + grant_projection + " FROM authorization_grants AS g "
                         "JOIN engagements AS e ON e.engagement_id=g.engagement_id "
                         "WHERE e.client_id=? ORDER BY g.created_at", (client_id,),
                )
            requests = _rows(
                con, "SELECT request_id,client_id,requested_assets_json,requested_mode,"
                     "requested_risk,status,requested_by,decided_by,decided_at,created_at "
                     "FROM assessment_requests WHERE client_id=? ORDER BY created_at",
                (client_id,),
            )
            users = _rows(
                con, "SELECT user_id,role,client_id FROM users WHERE user_id IN "
                     "(SELECT requested_by FROM assessment_requests WHERE client_id=? "
                     "UNION SELECT decided_by FROM assessment_requests WHERE client_id=?) "
                     "ORDER BY user_id", (client_id, client_id),
            )
        else:
            clients = _rows(con, "SELECT client_id,name FROM clients ORDER BY name")
            engagements = _rows(
                con, "SELECT engagement_id,client_id,name,status FROM engagements ORDER BY created_at")
            requests = _rows(
                con, "SELECT request_id,client_id,requested_assets_json,requested_mode,"
                     "requested_risk,status,requested_by,decided_by,decided_at,created_at "
                     "FROM assessment_requests ORDER BY created_at")
            grants = _rows(
                con, "SELECT " + grant_projection +
                     " FROM authorization_grants AS g ORDER BY g.created_at")
            users = _rows(con, "SELECT user_id,role,client_id FROM users ORDER BY user_id")
        con.rollback()

    by_client = {c["client_id"]: c["name"] for c in clients}
    users_by_id = {u["user_id"]: u for u in users}
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
        request_lineage_digest = hashlib.sha256(
            json.dumps([dict(r) for r in own_requests], ensure_ascii=True,
                       sort_keys=True, default=str, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        untrusted_approved = sum(
            r["status"] == "approved" and not _trusted_request_origin(r, users_by_id)
            for r in own_requests
        )
        entry = {
            "client": by_client.get(own, "(missing client)"),
            "engagement": engagement["name"],
            "engagement_status": engagement["status"],
            "requests": len(own_requests),
            "approved_requests": approved,
            "untrusted_approved_requests": untrusted_approved,
            "grants": len(own_grants),
            "grant_findings": [],
            "identity_key": _record_identity("engagement", engagement["engagement_id"]),
            "source_key": hashlib.sha256(
                json.dumps({"engagement": dict(engagement),
                            "requests_digest": request_lineage_digest,
                            "has_grants": bool(own_grants)}, ensure_ascii=True,
                           sort_keys=True, default=str).encode("ascii")
            ).hexdigest(),
        }
        if not own_grants:
            entry["attention"] = "No recorded grants; no authorization inferred."
        else:
            entry["attention"] = "Review existing grant records; none proves client/operator consent."
        for grant in own_grants:
            problems = []
            binding = "missing"
            bound_id = grant["approved_request_id"]
            if grant["client_id"] != own:
                problems.append("TENANT_LINEAGE_MISMATCH")
            if type(bound_id) is str and bound_id:
                bound = next(
                    (r for r in own_requests if r["request_id"] == bound_id), None
                )
                if (
                    grant["client_id"] == own
                    and bound is not None
                    and _candidate(grant, bound, users_by_id)
                ):
                    # Recorded administrative binding is coherent *on this
                    # point-in-time snapshot*. It does NOT sign consent,
                    # revoke permissions or confer execution authority.
                    binding = "recorded_coherent_review_only"
                else:
                    binding = "invalid"
                    problems.append("INVALID_APPROVED_REQUEST_BINDING")
            else:
                problems.append("UNBOUND_APPROVAL_REQUEST")
                if grant["client_id"] == own:
                    candidates = [
                        r for r in own_requests
                        if _candidate(grant, r, users_by_id)
                    ]
                    if not candidates:
                        problems.append("NO_COMPATIBLE_APPROVED_REQUEST")
                    elif len(candidates) > 1:
                        problems.append("AMBIGUOUS_APPROVED_REQUEST_MATCH")
                # A compatible candidate is NOT an actual persisted binding.
            if _time(grant["created_at"]) is None:
                problems.append("INVALID_GRANT_CREATION_TIME")
            if untrusted_approved:
                problems.append("UNTRUSTED_APPROVED_REQUEST_ORIGIN")
            if _assets(grant["assets_json"]) is None:
                problems.append("INVALID_GRANT_ASSETS")
            window = _utc_window(grant)
            if window == "invalid":
                problems.append("INVALID_GRANT_WINDOW")
            elif window == "expired":
                problems.append("EXPIRED_GRANT_WINDOW")
            for flag in problems:
                counter[flag] += 1
            # Stable *pseudonymous* exact-source fingerprint: never expose real IDs.
            # Any grant row, linked client request, time-window or flag change
            # changes this key, forcing fresh operator treatment on a new snapshot.
            grant_source_key = hashlib.sha256(
                json.dumps({"grant": dict(grant), "requests_digest": request_lineage_digest,
                            "window": window, "flags": problems}, ensure_ascii=True,
                           sort_keys=True, default=str).encode("ascii")
            ).hexdigest()
            entry["grant_findings"].append({
                "identity_key": _record_identity("grant", grant["grant_id"]),
                "source_key": grant_source_key,
                "grant_number": len(entry["grant_findings"]) + 1,
                "window": window,
                "binding": binding,
                "flags": problems,
                "next_action": (
                    "Quarantine this record from client-visible authorization views; "
                    "require the domain source-owner lineage repair."
                    if "TENANT_LINEAGE_MISMATCH" in problems
                    else "Escalate invalid or missing approved-request binding to the #177 source owner."
                    if binding != "recorded_coherent_review_only"
                    else "Stored request binding appears coherent on this snapshot only. "
                    "Independent client/operator consent, action-time revocation and release "
                    "remain unverified; never execute from this report."
                ),
            })
        if own_grants or own_requests:
            findings.append(entry)

    # Real client-submitted requests need a queue even BEFORE an engagement exists.
    # An operator-origin spoofed portal submission must never be promoted to grant
    # evidence; this is human triage only and changes no DomainStore record.
    request_queue = []
    request_history = []
    for request in requests:
        pending = request["status"] in {"submitted", "under_review"}
        approved = request["status"] == "approved"
        rejected = request["status"] == "rejected"
        flags = ["PENDING_OPERATOR_REVIEW" if pending else
                 "RECORDED_ADMINISTRATIVE_APPROVAL" if approved else
                 "RECORDED_ADMINISTRATIVE_REJECTION" if rejected else
                 "UNKNOWN_REQUEST_STATUS"]
        origin_valid = _valid_requester(request, users_by_id)
        if not origin_valid:
            flags.append("INVALID_CLIENT_REQUEST_ORIGIN")
        if approved and not _trusted_request_origin(request, users_by_id):
            flags.append("UNTRUSTED_ADMINISTRATIVE_APPROVAL")
        if _assets(request["requested_assets_json"]) is None:
            flags.append("INVALID_REQUEST_ASSETS")
        risk = request["requested_risk"]
        if type(risk) is not int or not (1 <= risk <= 4):
            flags.append("INVALID_REQUEST_RISK")
        if request["requested_mode"] != "authorized_assessment":
            flags.append("NON_AUTHORIZED_ASSESSMENT_MODE")
        created_at = _time(request["created_at"])
        if created_at is None:
            flags.append("INVALID_REQUEST_CREATION_TIME")
        if pending:
            for flag in flags:
                counter[flag] += 1
        item = {
            "identity_key": _record_identity("request", request["request_id"]),
            "source_key": hashlib.sha256(json.dumps(
                {"request": dict(request), "current_role_review_flags": flags},
                sort_keys=True, ensure_ascii=True,
                default=str, separators=(",", ":")
            ).encode("ascii")).hexdigest(),
            "request_number": len(request_history) + 1,
            "client": by_client.get(request["client_id"], "(missing client)"),
            "status": request["status"],
            "created_at": created_at.isoformat() if created_at is not None else "invalid",
            "flags": flags,
            "next_action": (
                "Escalate apparent operator-origin, missing or cross-tenant client request; "
                "do not approve, issue a grant, or infer consent."
                if not origin_valid else
                "Authenticate the genuine client request and review scope/risk independently; "
                "do not create a grant before domain request-to-grant binding is implemented."
                if pending else
                "Compare historical administrative decision with verified client intent. "
                "The stored state is not proof of client/operator consent or an executable grant."
            ),
        }
        request_history.append(item)
        if pending:
            request_queue.append(item)

    # Orphans cannot be safely attributed to any engagement or client.
    orphan_count = sum(g["engagement_id"] not in by_engagement for g in grants) if client_id is None else 0
    if client_id is None:
        counter["ORPHAN_GRANT"] = orphan_count
    report = {
        "format": "lightup.authorization_readiness_operator_v1",
        "disposition": "REVIEW_ONLY",
        "scope_fingerprint": hashlib.sha256(json.dumps(
            ["lightup.readiness.scope.v1", client_id or "all",
             engagement_id or "all"], separators=(",", ":")
        ).encode("utf-8")).hexdigest(),
        "scope_description": (
            "single_engagement" if engagement_id is not None else
            "single_client" if client_id is not None else "all_clients"
        ),
        "authority": AUTHORIZATION_FALSE.copy(),
        "limitations": [
            "Authenticated operator's local offline snapshot, not fresh consent evidence.",
            "Legacy schema may lack a durable grant-to-approved-request link; new schema binding is reviewed only and cannot prove independently authenticated consent.",
            "A candidate needs current user-role coherence and chronologically prior administrative approval; current roles cannot prove historical provenance, independent consent, or revocation.",
            "A compatible requested asset/risk is only a conservative comparison; canonical scope, identity, ownership, approval provenance, and runtime revocation are not verified.",
            "A within_window grant is NOT currently authorized. Review does not issue, edit or revoke grants.",
            "All grant records remain unverified. Do not merge, deploy or scan on this report.",
            "Request inbox records are client-wide and intentionally not linked to any particular engagement; administrative review does not authorize grants.",
            "Scoped exports intentionally omit unrelated tenant data and do not claim to inventory all orphan grants.",
            "Opaque source-key hashes support local action continuity only; they are unsigned pseudonyms, not identities, digital signatures or authorization.",
            "Stable identity-key hashes distinguish unchanged/changed/removed stored rows across two offline reports; they are not proof that a missing record was remediated.",
            "Reports must have matching exact selection scope fingerprints for offline comparison; report contents are unsigned/untrusted and never authorize real work.",
            "Historical submitted, approved or rejected request records are informational; transitions cannot prove authentic consent or entitlement to a scan.",
        ],
        "summary": {
            "clients": len(clients),
            "engagements": len(engagements),
            "requests": len(requests),
            "grants": len(grants),
            "pending_requests": len(request_queue),
            "flag_counts": dict(sorted(counter.items())),
        },
        "engagements": findings,
        "review_queue": request_queue,
        "request_history": request_history,
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



def _interactive_workspace(report: dict, nonce: str) -> str:
    """Bundle one exact database-derived review queue; no target or web backend."""
    snapshot = {
        "format": "lightup.authorization_casework_snapshot_v1",
        "disposition": "REVIEW_ONLY",
        "scope_fingerprint": report["scope_fingerprint"],
        "scope_description": report["scope_description"],
        "fingerprint": hashlib.sha256(
            json.dumps({"engagements": report["engagements"],
                        "review_queue": report["review_queue"],
                        "request_history": report["request_history"]},
                       ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")).encode("ascii")
        ).hexdigest(),
        "engagements": report["engagements"],
        "review_queue": report["review_queue"],
        "request_history": report["request_history"],
    }
    source = Path(__file__).with_name("authorization_casework.js").read_text("utf-8")
    compare_source = Path(__file__).with_name("authorization_snapshot_compare.js").read_text("utf-8")
    marker = "LIGHTUP_SNAPSHOT_B64_PLACEHOLDER"
    if source.count(marker) != 1:
        raise ValueError("offline casework asset missing its bounded snapshot placeholder")
    encoded = base64.b64encode(json.dumps(snapshot, ensure_ascii=True,
                         separators=(",", ":")).encode("ascii")).decode("ascii")
    # The untrusted database values only ever enter a base64 string literal,
    # never raw HTML/script syntax; JS uses textContent for all case values.
    source = source.replace(marker, encoded, 1)
    ui = r'''
    <section class="workspace" aria-label="Offline operator remediation actions">
      <h2>Operator follow-up workspace</h2>
      <p class="sub">Sort and assign the real stored-source problems above. This is local
      documentation only — a task marked "locally documented" is NOT an authorized
      assessment, a resolved grant defect, consent, revocation, or a verified remediation.</p>
      <div class="actions">
        <label>Search cases<input id="workspaceSearch" type="search" placeholder="Client, engagement, issue or owner"></label>
        <label>Local status<select id="workspaceState">
          <option value="all">All</option><option value="open">Open</option>
          <option value="working">Working</option><option value="escalated">Escalated</option>
          <option value="locally_documented">Locally documented (NOT authorized)</option>
        </select></label>
        <label class="toggle"><input id="workspaceCritical" type="checkbox">Critical concerns only</label>
      </div>
      <p class="muted" id="workspaceTotals"></p>
      <div class="workspaceBulk">
        <label>Bulk owner (unassigned filtered cases only)
          <input id="workspaceBulkOwner" maxlength="90" autocomplete="off" placeholder="Responsible team or operator">
        </label>
        <button id="workspaceBulkAssign" type="button">Assign filtered unassigned</button>
        <button id="workspaceBulkEscalate" type="button">Escalate filtered unresolved</button>
      </div>
      <div class="workspaceGrid">
        <nav id="workspaceCases" class="caseList" aria-label="Authorization cases"></nav>
        <div id="workspaceEditor" class="caseEditor">
          <h3 id="workspaceTitle"></h3>
          <div id="workspaceFlags"></div>
          <p id="workspaceNotice" class="warning"></p>
          <div class="editorGrid">
            <label>Local follow-up status<select id="workspaceStatus">
              <option value="open">Open</option><option value="working">Working</option>
              <option value="escalated">Escalated</option>
              <option value="locally_documented">Locally documented — NOT authorized</option>
            </select></label>
            <label>Responsible operator/team<input id="workspaceOwner" maxlength="90" autocomplete="off"></label>
            <label>Ticket reference<input id="workspaceTicket" maxlength="120" autocomplete="off"></label>
            <label>Follow-up due date<input id="workspaceDue" type="date"></label>
          </div>
          <label>Operator notes (private)<textarea id="workspaceNotes" maxlength="2000" rows="4"></textarea></label>
          <label>Local resolution / next escalation (NOT a source change)
            <textarea id="workspaceResolution" maxlength="1200" rows="3"></textarea></label>
          <p class="muted">The imported database findings and original flags are read-only.
          Only task notes/status change, in browser memory. No automatic autosave.</p>
        </div>
      </div>
      <div class="workspaceExports">
        <button id="workspaceExport" type="button">Export action plan JSON</button>
        <button id="workspaceCsv" type="button">Export filtered actions CSV</button>
        <label class="importLabel">Import same-snapshot action plan
          <input id="workspaceImport" type="file" accept=".json,application/json"></label>
      </div>
      <p id="workspaceUnsaved" class="muted" role="status">No local edits yet</p>
      <p id="workspaceFeedback" class="muted" aria-live="polite">
        This report is an unsigned, sensitive private offline copy. No network, storage,
        service, grant, client consent, execution or automatic synchronization.
      </p>
    </section>
    <section class="workspace" aria-label="Authorization snapshot comparison">
      <h2>Source change review</h2>
      <p class="sub">Compare two genuine operator-exported JSON snapshots of exactly the
      same client/engagement selection. Detect newly recorded, changed, unchanged
      and no-longer-present rows without treating any disappearance as remediation
      or grant authorization. The earlier report is untrusted and unsigned.</p>
      <div class="workspaceExports">
        <label class="importLabel">Prior private LightUp JSON report (max 2 MiB)
          <input id="snapshotCompareImport" type="file" accept=".json,application/json"></label>
        <label>Show<select id="snapshotCompareFilter">
          <option value="all">All changes</option><option value="new">New</option>
          <option value="changed">Changed</option><option value="absent">Absent (NOT fixed)</option>
          <option value="unchanged">Unchanged</option>
        </select></label>
        <button id="snapshotCompareExport" type="button">Export change handoff Markdown</button>
      </div>
      <p class="muted" id="snapshotCompareTotals">No previous report selected.</p>
      <p class="muted" id="snapshotCompareFeedback" aria-live="polite">
        Prior source copies cannot prove valid consent, grants, historical identity
        or resolution. No network or database writes.
      </p>
      <div id="snapshotCompareRows" class="changeList"></div>
    </section>'''
    css = r'''
    .workspace{border-top:2px solid #375067;margin-top:32px;padding:24px 0}
    .actions,.workspaceExports,.workspaceBulk{display:flex;gap:13px;flex-wrap:wrap;align-items:end;margin:18px 0}
    label{display:block;font-size:.87rem;font-weight:700;color:#dfecfa}
    input,textarea,select{display:block;width:100%;border:1px solid #63738b;
      background:#0e1829;color:#fff;border-radius:8px;padding:10px;margin-top:5px;font:inherit}
    textarea{resize:vertical;max-width:100%}
    input:focus,textarea:focus,select:focus,button:focus{outline:2px solid #8de6d2;outline-offset:2px}
    .actions label{min-width:180px;flex:1}.toggle{display:flex;gap:9px;align-items:center}
    .toggle input{width:auto}.workspaceGrid{display:grid;grid-template-columns:minmax(240px,1fr) minmax(360px,2fr);gap:16px}
    .caseList{display:grid;gap:8px;align-content:start;max-height:720px;overflow-y:auto}
    .caseChoice{display:grid;gap:3px;text-align:left;border:1px solid #455a76;
      background:#14233a;color:#f3f8ff;padding:14px;border-radius:11px;cursor:pointer}
    .caseChoice.selected{border-color:#7de6c9;background:#213f47}
    .caseChoice small{overflow-wrap:anywhere}
    .caseEditor{border:1px solid #455a76;background:#142239;padding:18px;border-radius:12px}
    .caseEditor h3{margin-top:0;overflow-wrap:anywhere}.caseEditor>label{margin-top:15px}
    .editorGrid{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin:18px 0}
    .workspaceExports button,.workspaceBulk button,.importLabel{background:#244254;color:#e8fafa;cursor:pointer;
      border:1px solid #70b9ac;border-radius:8px;padding:11px 15px;font-weight:750}
    .workspaceBulk label{flex:1;min-width:260px}
    .changeList{display:grid;gap:10px;margin-top:18px;max-height:720px;overflow:auto}
    .changeCard{border:1px solid #465d7c;background:#14253c;border-radius:9px;padding:15px;overflow-wrap:anywhere}
    .changeCard p{margin:7px 0;color:#bfd2e3}
    .changeCard strong{color:#f1f8ff}
    .importLabel input{max-width:310px;font-size:.82rem}
    @media(max-width:800px){.workspaceGrid{grid-template-columns:1fr}.editorGrid{grid-template-columns:1fr}}
    @media print{.workspace{display:none}}
    '''
    return (ui + '<style nonce="' + nonce + '">' + css + '</style>'
            + '<script nonce="' + nonce + '">' + compare_source + '</script>'
            + '<script nonce="' + nonce + '">' + source + '</script>')


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
            ("Pending review", summary["pending_requests"]),
            ("Unverified grants", summary["grants"]),
            ("Tenant mismatches", summary["flag_counts"].get("TENANT_LINEAGE_MISMATCH", 0)),
            ("Unmatched requests", summary["flag_counts"].get("NO_COMPATIBLE_APPROVED_REQUEST", 0)),
        )
    )
    blocks = []
    for record in report["engagements"]:
        trs = "".join(
            "<tr><td>" + esc(g["grant_number"]) + "</td><td>" + esc(g["window"]) +
            "</td><td>" + esc(g["binding"]) +
            "</td><td>" + " ".join('<span class="flag">' + esc(flag) + "</span>" for flag in g["flags"]) +
            "</td><td>" + esc(g["next_action"]) + "</td></tr>"
            for g in record["grant_findings"]
        )
        table = (
            "<table><thead><tr><th>Record #</th><th>Time-window record</th><th>Request binding (review-only)</th><th>Review flags</th><th>Required next action</th></tr></thead>"
            "<tbody>" + trs + "</tbody></table>"
        ) if trs else '<p class="muted">No grant rows. No permission implied.</p>'
        blocks.append(
            '<section class="card"><h3>' + esc(record["client"]) + " / " + esc(record["engagement"]) + "</h3>"
            '<p class="muted">Engagement: ' + esc(record["engagement_status"]) +
            " · Requests: " + esc(record["requests"]) +
            " · Recorded approvals: " + esc(record["approved_requests"]) +
            " · Untrusted approved request origins: " + esc(record["untrusted_approved_requests"]) +
            " · Grants: " + esc(record["grants"]) + "</p>"
            "<p>" + esc(record["attention"]) + "</p>" + table + "</section>"
        )
    requests = "".join(
        "<tr><td>" + esc(item["request_number"]) + "</td><td>" + esc(item["client"]) +
        "</td><td>" + esc(item["created_at"]) + "</td><td>" + esc(item["status"]) +
        "</td><td>" + " ".join('<span class="flag">' + esc(flag) + "</span>" for flag in item["flags"]) +
        "</td><td>" + esc(item["next_action"]) + "</td></tr>"
        for item in report["review_queue"]
    )
    request_inbox = (
        '<table><thead><tr><th>Request #</th><th>Client</th><th>Created UTC</th>'
        '<th>Status</th><th>Review flags</th><th>Next action</th></tr></thead>'
        '<tbody>' + requests + '</tbody></table>'
    ) if requests else '<p class="muted">No pending client assessment requests in this snapshot.</p>'
    limits = "".join("<li>" + esc(l) + "</li>" for l in report["limitations"])
    csp = "default-src 'none'; style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
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
        "<h2>Pending client requests — operator review required</h2>" + request_inbox +
        "<h2>Engagement review queue</h2>" + ("".join(blocks) or "<p>No engagements with recorded requests/grants.</p>") +
        "<details><summary>Limits, mandatory owner work and data handling</summary><ol>" +
        limits + "</ol><p>Owner follow-ups: #177 request-to-grant binding, #829 grant tenant-lineage reads, "
        "#182 default web admission. This report repairs none of them.</p>"
        "<p>Contains private client/engagement names; keep mode 0600, do not host or share publicly.</p>"
        "</details>" + _interactive_workspace(report, nonce) + "</main></body></html>"
    )



def _pseudonymize_labels(report: dict) -> None:
    """Replace display labels without changing any source decisions or case flags.

    Aliases are report-local only; do not claim cross-snapshot stable identities.
    Manually authored operator notes can still contain personal/sensitive data.
    """
    labels: dict[str, str] = {}
    for index, entry in enumerate(report["engagements"], 1):
        real_client = entry["client"]
        if real_client not in labels:
            labels[real_client] = "Client " + str(len(labels) + 1).zfill(3)
        entry["client"] = labels[real_client]
        entry["engagement"] = "Engagement " + str(index).zfill(3)
    for item in report["request_history"]:
        client = item["client"]
        if client not in labels:
            labels[client] = "Client " + str(len(labels) + 1).zfill(3)
        item["client"] = labels[client]
    report["labels_redacted"] = True
    report["limitations"].append(
        "Display client/engagement labels are report-local pseudonyms; "
        "counts and findings remain from the original authenticated tenant scope. "
        "Operator-entered notes may still contain sensitive information."
    )


def _csv_cell(value) -> str:
    """Neutralize sheet formulas and embedded record boundaries in local CSV export."""
    value = str(value)
    # Whitespace/control stripping prevents a leading newline/tab hiding = + - @.
    value = "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in value)
    value = value.strip()
    if value and value[0] in "=+-@":
        return "'" + value
    return value


def _render_csv(report: dict) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow([
        "disposition", "record_type", "client", "engagement", "engagement_status",
        "requests", "approved_requests", "untrusted_approved_requests",
        "grant_record_number", "recorded_window", "binding_review_only", "review_flags", "next_action",
    ])
    for e in report["engagements"]:
        grants = e["grant_findings"] or [{
            "grant_number": "", "window": "", "flags": ["NO_GRANT_RECORD"],
            "next_action": "No grant record. No scope authorization is inferred.",
        }]
        for grant in grants:
            writer.writerow([_csv_cell(v) for v in (
                "REVIEW_ONLY", "grant", e["client"], e["engagement"], e["engagement_status"],
                e["requests"], e["approved_requests"], e["untrusted_approved_requests"],
                grant["grant_number"], grant["window"], grant["binding"], ";".join(grant["flags"]),
                grant["next_action"],
            )])
    for request in report["review_queue"]:
        writer.writerow([_csv_cell(v) for v in (
            "REVIEW_ONLY", "client_request", request["client"], "No engagement binding",
            request["status"], "", "", "", request["request_number"], "not a grant",
            "not a grant", ";".join(request["flags"]), request["next_action"],
        )])
    # Even empty reports remain explicitly non-authorizing; column A is always REVIEW_ONLY.
    if not report["engagements"] and not report["review_queue"]:
        writer.writerow(["REVIEW_ONLY", "none", "", "", "", "", "", "", "", "",
                         "", "NO_REVIEW_RECORDS", "No authorization inferred."])
    return stream.getvalue()


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
    parser.add_argument("--client-id", help="limit sensitive export to one exact existing client")
    parser.add_argument("--engagement-id", help="limit export to one engagement, optionally with --client-id")
    parser.add_argument("--redact-labels", action="store_true", help="replace client/engagement names with report-local aliases")
    parser.add_argument("--output", required=True, help="new private .html, .json or .csv file; never overwritten")
    args = parser.parse_args(argv)
    path = Path(args.output)
    db = Path(args.db)
    if not db.is_file() or not path.parent.is_dir() or path.suffix.lower() not in {".html", ".json", ".csv"}:
        print("Existing LightUp database and new .html/.json/.csv file in a private directory required.", file=sys.stderr)
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
        report = _read_report(db, client_id=args.client_id, engagement_id=args.engagement_id)
        if args.redact_labels:
            _pseudonymize_labels(report)
        extension = path.suffix.lower()
        if extension == ".html":
            text = _render_html(report)
        elif extension == ".csv":
            text = _render_csv(report)
        else:
            text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        _save_new_private(path, text)
    except (PermissionError, AccountLockedError, ValueError, sqlite3.DatabaseError,
            OSError, EOFError, KeyboardInterrupt, GetPassWarning):
        print("HOLD: authentication, source integrity or private export requirements not met.", file=sys.stderr)
        return 2
    print("REVIEW_ONLY: private operator report created; no grant, consent, scan or release authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
