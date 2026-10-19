#!/usr/bin/env python3
"""Original LightUp Casebook: offline PRIVATE multi-snapshot HUMAN review.

No account login, database connection, permission assertion, grant, or scan.
Consumes only previously exported ORIGINAL source-owner Casebook v1 packets.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import html
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys

KIND = "lightup.auth_casebook.v1"
COUNTS = (
    "requests", "engagements", "grants", "risk_approvals",
    "grant_link_hold", "risk_tenant_hold", "case_attention_hold",
    "foreign_tenant_row_count", "recorded_window_review",
    "risk_provenance_hold", "pending_risk_review",
)
FAMILIES = (
    ("requests", "request_id", ("status", "requested_mode", "requested_risk", "created_at", "decision_recorded")),
    ("engagements", "engagement_id", ("status", "created_at")),
    ("grants", "grant_id", ("engagement_id", "approved_request_id", "request_link_observation",
                          "max_risk", "valid_from", "valid_until", "validity_observation")),
    ("risk_approvals", "approval_id", ("engagement_id", "status", "requested_risk",
                                      "source_tenant_matches", "decision_recorded",
                                      "decision_provenance_observation")),
)
# Exact categories emitted by the pinned original source owner's Casebook.
# Unrecognized user-provided review labels are never adopted as source truth.
SOURCE_ENUMS = {
    ("requests", "status"): {"submitted", "under_review", "approved", "rejected"},
    ("requests", "requested_mode"): {
        "analysis_only", "passive_discovery", "lab_autonomous", "authorized_assessment"
    },
    ("engagements", "status"): {
        "draft", "authorization_pending", "authorized", "running",
        "remediation", "retest", "closed"
    },
    ("grants", "request_link_observation"): {
        "HOLD_TENANT_OR_ENGAGEMENT_MISMATCH", "HOLD_NO_REQUEST_BINDING",
        "HOLD_REQUEST_SOURCE_MISSING", "HOLD_REQUEST_NOT_APPROVED",
        "REQUEST_SCOPE_COMPATIBLE_UNVERIFIED",
        "HOLD_REQUEST_SCOPE_OR_PROVENANCE_MISMATCH",
    },
    ("grants", "validity_observation"): {
        "EXPIRED_RECORDED_WINDOW", "FUTURE_RECORDED_WINDOW",
        "HOLD_INVALID_RECORDED_WINDOW", "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY",
    },
    ("risk_approvals", "status"): {"pending", "approved", "denied"},
    ("risk_approvals", "decision_provenance_observation"): {
        "HOLD_RISK_SOURCE_IDENTITY_OR_STATUS", "RISK_DECISION_PENDING_REVIEW",
        "HOLD_RISK_PENDING_WITH_DECISION", "HOLD_RISK_DECIDER_PROVENANCE",
        "RISK_DECISION_RECORDED_UNVERIFIED",
    },
    ("case_overview", "attention"): {
        "HOLD_SOURCE_PROVENANCE", "RISK_DECISION_PENDING_SOURCE_REVIEW",
        "HOLD_CLOSED_ENGAGEMENT_WITH_GRANTS", "EXPIRED_GRANT_SOURCE_REVIEW",
        "FUTURE_GRANT_SOURCE_REVIEW", "REVIEW_ONLY_UNVERIFIED_GRANT_LINK",
        "NO_GRANT_RECORDED",
    },
    ("case_overview", "next_review_action"): {
        "RECONCILE_PERSISTED_PROVENANCE",
        "REVIEW_OUTSTANDING_ORIGINAL_RISK_REQUEST", "REVIEW_CLOSED_ENGAGEMENT",
        "REVIEW_ORIGINAL_GRANT_WINDOW", "CHECK_ORIGINAL_GRANT_WINDOW",
        "CONFIRM_SEPARATE_CONSENT_AND_AT_USE_REVOCATION",
        "REVIEW_REQUEST_BEFORE_ANY_GRANT",
    },
}

AUTH_FLAGS = (
    "source_authenticated", "client_consent_verified", "operator_consent_verified",
    "authorization_granted", "execution_allowed", "release_approved",
)
TOP_FIELDS = (
    "schema", "status", "source", "as_of", "client_id",
    "requests", "engagements", "grants", "risk_approvals",
    "case_overview", "declared_counts", *AUTH_FLAGS,
)
ROW_FIELDS = {
    "requests": ("request_id", "status", "requested_mode", "requested_risk",
                 "created_at", "decision_recorded"),
    "engagements": ("engagement_id", "status", "created_at"),
    "grants": ("grant_id", "engagement_id", "approved_request_id",
               "request_link_observation", "max_risk", "valid_from", "valid_until",
               "validity_observation"),
    "risk_approvals": ("approval_id", "engagement_id", "status", "requested_risk",
                       "source_tenant_matches", "decision_recorded",
                       "decision_provenance_observation"),
    "case_overview": ("engagement_id", "status", "grant_count", "risk_record_count",
                      "attention", "next_review_action"),
}
CSS = """*{box-sizing:border-box}body{margin:auto;max-width:1320px;padding:32px 24px;
font-family:system-ui,sans-serif;background:#101828;color:#e7efff;line-height:1.5}
h1{font-size:2.3rem}h2{color:#91e9da;margin-top:38px}h3{color:#c9daf5}
p{max-width:950px;color:#c1cbe0}.danger{padding:14px 18px;background:#402d27;
border:2px solid #d1a376;border-radius:12px}.muted{color:#c1cbe0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card{background:#1c2a40;border:1px solid #394c66;border-radius:12px;padding:14px}
.card strong{display:block;font-size:1.6rem;color:#91e9da}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin:18px 0}
th,td{padding:10px;vertical-align:top;text-align:left;border-bottom:1px solid #41516a;overflow-wrap:anywhere}
th{background:#233651;position:sticky;top:0}a{color:#91e9da}.scroll{overflow:auto}
.warn{color:#f6c99f}.pill{font-size:.7rem;border:1px solid #7b98ab;padding:3px 6px;border-radius:6px}
svg{width:100%;max-width:1000px;height:270px;background:#19263a;border:1px solid #374d63;border-radius:12px}
svg text{font-size:12px;fill:#d5e8fa}svg .axis{stroke:#526987;stroke-width:1}
svg .line{fill:none;stroke:#7ee7d1;stroke-width:3}svg .dot{fill:#d3ee91}
footer{margin-top:40px;border-top:1px solid #364963;padding-top:20px;color:#95a9c3}
@media(max-width:720px){body{padding:14px}table{font-size:.77rem}th,td{padding:7px}}
"""


class Hold(ValueError):
    pass


def fail(condition: bool, message: str) -> None:
    if not condition:
        raise Hold(message)


def exact_dict(value: object, fields: tuple[str, ...]) -> dict:
    fail(type(value) is dict and set(value) == set(fields), "unrecognized original record shape")
    return value


def identity(value: object, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    fail(type(value) is str and 1 <= len(value) <= 180
         and value.strip() == value
         and value[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
         and all(32 < ord(c) < 127 for c in value), "invalid source identifier")
    return value


def source_text(value: object, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    fail(type(value) is str and len(value) <= 180
         and all(ord(c) >= 32 and ord(c) != 127 for c in value),
         "malformed source text")
    return value


def strict_number(value: object) -> int:
    fail(type(value) is int and 0 <= value <= 200, "invalid source count")
    return value


def timestamp(value: object) -> datetime:
    fail(type(value) is str and 1 <= len(value) <= 80, "invalid timestamp")
    try:
        d = datetime.fromisoformat(value)
    except (ValueError, TypeError, OverflowError):
        raise Hold("invalid source timestamp") from None
    fail(d.tzinfo is not None and d.utcoffset() is not None, "naive timestamp")
    return d


def pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise Hold("duplicate JSON source key")
        result[key] = value
    return result


def admit(data: object) -> dict:
    doc = exact_dict(data, TOP_FIELDS)
    fail(doc["schema"] == KIND and doc["status"] == "REVIEW_ONLY"
         and doc["source"] == "original_persisted_domain_unverified",
         "not an original Casebook v1 review packet")
    for name in AUTH_FLAGS:
        fail(doc[name] is False, "source claims unsupported authority")
    identity(doc["client_id"])
    timestamp(doc["as_of"])
    indexes = {}
    for family, id_key, _ in FAMILIES:
        rows = doc[family]
        fail(type(rows) is list and len(rows) <= 200, "source batch overflow")
        index: dict[str, dict] = {}
        for row in rows:
            exact_dict(row, ROW_FIELDS[family])
            key = identity(row[id_key])
            fail(key not in index, "duplicate original record identity")
            for field in ROW_FIELDS[family]:
                val = row[field]
                if field in ("requested_risk", "max_risk"):
                    fail(type(val) is int and 0 <= val <= 5, "noncanonical risk")
                elif field in ("decision_recorded", "source_tenant_matches"):
                    fail(type(val) is bool, "noncanonical Boolean")
                elif field == "engagement_id" and family != "engagements":
                    identity(val, nullable=True)
                elif field == "approved_request_id":
                    identity(val, nullable=True)
                elif field not in ("requested_risk", "max_risk", "decision_recorded",
                                   "source_tenant_matches"):
                    source_text(val)
                expected = SOURCE_ENUMS.get((family, field))
                if expected is not None:
                    fail(type(val) is str and val in expected,
                         "unknown original source category")
            index[key] = row
        indexes[family] = index
    cases = doc["case_overview"]
    fail(type(cases) is list and len(cases) == len(doc["engagements"]),
         "incomplete original caseboard")
    seen = set()
    for row in cases:
        exact_dict(row, ROW_FIELDS["case_overview"])
        key = identity(row["engagement_id"])
        fail(key in indexes["engagements"] and key not in seen,
             "foreign or duplicated caseboard engagement")
        seen.add(key)
        for value in ("status", "attention", "next_review_action"):
            source_text(row[value])
            categories = SOURCE_ENUMS.get(("case_overview", value))
            if categories is None:
                categories = SOURCE_ENUMS.get(("engagements", value))
            fail(row[value] in categories, "unknown original HUMAN case category")
        for value in ("grant_count", "risk_record_count"):
            strict_number(row[value])
        fail(row["status"] == indexes["engagements"][key]["status"],
             "caseboard source status mismatch")
        fail(row["grant_count"] == sum(v["engagement_id"] == key for v in doc["grants"])
             and row["risk_record_count"] == sum(v["engagement_id"] == key for v in doc["risk_approvals"]),
             "caseboard count mismatch")
    count = exact_dict(doc["declared_counts"], COUNTS)
    for field in COUNTS:
        strict_number(count[field])
    for family in indexes:
        fail(count[family] == len(indexes[family]), "invalid declared family totals")
    fail(count["grant_link_hold"] ==
         sum(str(g["request_link_observation"]).startswith("HOLD_") for g in doc["grants"]),
         "invalid grant-link HOLD count")
    fail(count["recorded_window_review"] ==
         sum(g["validity_observation"] != "WITHIN_RECORDED_WINDOW_NOT_AUTHORITY"
             for g in doc["grants"]), "invalid grant window count")
    fail(count["risk_tenant_hold"] ==
         sum(r["source_tenant_matches"] is False for r in doc["risk_approvals"]),
         "invalid risk tenancy count")
    fail(count["risk_provenance_hold"] ==
         sum(str(r["decision_provenance_observation"]).startswith("HOLD_")
             for r in doc["risk_approvals"]), "invalid risk provenance count")
    fail(count["pending_risk_review"] ==
         sum(r["decision_provenance_observation"] == "RISK_DECISION_PENDING_REVIEW"
             for r in doc["risk_approvals"]), "invalid pending risk count")
    fail(count["case_attention_hold"] ==
         sum(c["attention"].startswith("HOLD_") for c in cases),
         "invalid case HOLD count")
    return doc


def read_private(path: Path) -> tuple[dict, bytes]:
    parent = path.parent
    folder = parent.lstat()
    fail(stat.S_ISDIR(folder.st_mode) and not stat.S_ISLNK(folder.st_mode)
         and folder.st_mode & 0o077 == 0, "input folder must be owner-private")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        fail(stat.S_ISREG(info.st_mode) and info.st_size <= 524288
             and info.st_mode & 0o077 == 0, "input must be bounded private regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(524289)
        fail(2 <= len(raw) <= 524288, "invalid packet size")
        try:
            obj = json.loads(raw.decode("utf-8", errors="strict"),
                             object_pairs_hook=pairs_no_duplicates,
                             parse_constant=lambda _: (_ for _ in ()).throw(Hold("nonfinite JSON")))
        except (UnicodeError, json.JSONDecodeError):
            raise Hold("invalid JSON source bytes") from None
        return admit(obj), raw
    finally:
        os.close(fd)


def changes(previous: dict, later: dict) -> list[dict]:
    """ID-specific original-declaration differences; never real chronology or revocation."""
    out = []
    for family, field, tracked in FAMILIES:
        a = {r[field]: r for r in previous[family]}
        b = {r[field]: r for r in later[family]}
        for key in sorted(a.keys() | b.keys()):
            if key not in a:
                label, changed = "APPEARED", "source declaration"
            elif key not in b:
                label, changed = "ABSENT", "source declaration"
            else:
                keys = [name for name in tracked if a[key][name] != b[key][name]]
                if not keys:
                    continue
                label, changed = "FIELDS_CHANGED", ",".join(keys)
            out.append({
                "family": family, "local_source_id": key,
                "change": label, "changed_fields": changed,
            })
    return out


def case_queue(docs: list[dict]) -> list[dict]:
    """PRIVATE HUMAN original Casebook source queue. Never a live grant status."""
    by_id: dict[str, list[tuple[int, dict]]] = {}
    for ordinal, doc in enumerate(docs, start=1):
        for row in doc["case_overview"]:
            by_id.setdefault(row["engagement_id"], []).append((ordinal, row))
    queue = []
    for key, appearances in by_id.items():
        ordinal, latest = appearances[-1]
        changes = sum(
            a["attention"] != b["attention"] or
            a["next_review_action"] != b["next_review_action"]
            for (_, a), (_, b) in zip(appearances, appearances[1:])
        )
        if latest["attention"].startswith("HOLD_"):
            priority = 0
        elif latest["attention"] == "RISK_DECISION_PENDING_SOURCE_REVIEW":
            priority = 1
        elif latest["attention"] in ("EXPIRED_GRANT_SOURCE_REVIEW",
                                      "FUTURE_GRANT_SOURCE_REVIEW"):
            priority = 2
        else:
            priority = 3
        queue.append({
            "local_original_engagement_id": key,
            "latest_observed_ordinal": ordinal,
            "source_status": latest["status"],
            "source_attention": latest["attention"],
            "source_next_human_action": latest["next_review_action"],
            "observed_packet_appearances": len(appearances),
            "human_attention_transitions": changes,
            "latest_grant_count": latest["grant_count"],
            "latest_risk_record_count": latest["risk_record_count"],
            "source_only_priority_group": priority,
        })
    queue.sort(key=lambda item: (
        item["source_only_priority_group"], -item["human_attention_transitions"],
        -item["latest_grant_count"], item["local_original_engagement_id"]
    ))
    return queue


def csv_text(rows: list[list[object]]) -> str:
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerows(rows)
    return out.getvalue()


def safe(value: object) -> str:
    return html.escape(str(value), quote=True)


def make_chart(docs: list[dict]) -> str:
    values = [doc["declared_counts"]["grant_link_hold"]
              + doc["declared_counts"]["case_attention_hold"]
              + doc["declared_counts"]["risk_provenance_hold"] for doc in docs]
    peak = max(1, *values)
    coords = [(40 + i * 900 / (len(values)-1), 215 - x * 170 / peak)
              for i, x in enumerate(values)]
    points = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    dots = "".join(
        f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="5">'
        f'<title>Packet {i+1}: {values[i]} original HOLD appearances</title></circle>'
        f'<text x="{x:.1f}" y="247" text-anchor="middle">{i+1}</text>'
        for i, (x,y) in enumerate(coords))
    return ('<svg viewBox="0 0 1000 270" role="img" '
            'aria-label="Original-source HOLD appearances by operator-selected packet order; not verified chronology">'
            '<line class="axis" x1="25" x2="975" y1="215" y2="215"/>'
            f'<polyline class="line" points="{points}"/>{dots}</svg>')


def table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join("<th scope=\"col\">" + safe(x) + "</th>" for x in headers)
    body = "".join("<tr>" + "".join("<td>" + safe(cell) + "</td>" for cell in row)
                   + "</tr>" for row in rows)
    return "<div class=\"scroll\"><table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table></div>"


def html_page(docs: list[dict], delta: list[list[dict]], *, public: bool) -> str:
    counters = ["Packet ordinal", *COUNTS]
    values = [[i+1, *(doc["declared_counts"][name] for name in COUNTS)]
              for i, doc in enumerate(docs)]
    all_changes = [[i+2, row["family"], row["change"], row["local_source_id"],
                    row["changed_fields"]] for i, changeset in enumerate(delta)
                   for row in changeset]
    summary = ["LightUp · anonymous review counter appearances" if public
               else "LightUp · PRIVATE original Casebook multi-snapshot review",
               "<p>Operator-selected ordinal order is NOT signed chronology. "
               "Original Casebook outputs are PRIVATE unverified source declarations. "
               "A missing grant is NOT proof of revocation. No real authorization, consent, "
               "evidence, scan, account or release action is performed.</p>",
               '<p class="danger"><strong>DRAFT / HOLD — NOT AN AUTHORIZATION OR ASSESSMENT.</strong> '
               "No PASS, fixes, target access, current client/operator consent or revocation-at-use "
               "can be concluded from these snapshots. Original source owners, CI, security and HUMAN GO required.</p>",
               "<h2>Source-declared HOLD appearance trend</h2>", make_chart(docs),
               "<p class=\"muted\">Counts combine grant-link HOLD, case attention HOLD and risk provenance HOLD. "
               "These can refer to overlapping records, and changed coverage can explain deltas. "
               "The graph is not a measured security-risk trend.</p>",
               "<h2>Anonymous source record count series</h2>", table(counters, values)]
    if public:
        summary.append("<h2>Changed source-record appearances by ordinal</h2>")
        counts = Counter((i + 2, row["family"], row["change"]) for i, group in enumerate(delta)
                         for row in group)
        summary.append(table(["Packet ordinal", "Family", "Source declaration", "Count"],
                             [[*k, v] for k, v in sorted(counts.items())]))
        summary.append("<p>Anonymous aggregate still may be sensitive for small groups; treat as PRIVATE.</p>")
    else:
        summary.extend([
            "<h2>PRIVATE original identifiers and literal source changes</h2>",
            "<p>Only open this private file on a trusted machine. Identifiers were copied from "
            "locally selected ORIGINAL Casebook snapshots; no original assets, credentials, "
            "customer names, notes or execution tokens appear.</p>",
            table(["Later packet ordinal", "Source family", "Change", "Original source ID",
                   "Changed source fields"], all_changes),
            "<h2>PRIVATE original per-engagement HUMAN next-action queue</h2>",
            "<p>This is a source-reported human attention ranking, NOT risk or authorization priority. "
            "Identifiers and original human actions never enter anonymous handoffs.</p>",
            table(["Original engagement ID", "Latest ordinal", "Original attention",
                   "Original recommended human action", "Source status",
                   "Packet appearances", "Attention changes"],
                  [[row["local_original_engagement_id"],
                    row["latest_observed_ordinal"], row["source_attention"],
                    row["source_next_human_action"], row["source_status"],
                    row["observed_packet_appearances"], row["human_attention_transitions"]]
                   for row in case_queue(docs)]),
        ])
    digest = hashlib.sha256(("\n"+CSS+"\n").encode("utf-8")).digest()
    import base64
    style_hash = base64.b64encode(digest).decode("ascii")
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta name="referrer" content="no-referrer">'
            '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
            "style-src &#39;sha256-" + style_hash + "&#39;; "
            'img-src &#39;none&#39;; connect-src &#39;none&#39;; '
            'script-src &#39;none&#39;; frame-src &#39;none&#39;; object-src &#39;none&#39;">'
            '<title>LightUp original Casebook HUMAN history HOLD</title>'
            "<style>\n" + CSS + "\n</style></head><body><h1>" +
            safe(summary[0]) + "</h1>" + "".join(summary[1:]) +
            "<footer>Offline · original human review only · no authority · source-owner unchanged</footer></body></html>")


def generate(docs: list[dict]) -> dict[str, bytes]:
    delta = [changes(a,b) for a,b in zip(docs, docs[1:])]
    fail(sum(len(group) for group in delta) <= 3200,
         "large private source change series requires narrower selected snapshots")
    counts_rows: list[list[object]] = [["packet_ordinal", *COUNTS]]
    for i, doc in enumerate(docs):
        counts_rows.append([i + 1, *(doc["declared_counts"][x] for x in COUNTS)])
    aggregate = {
        "kind": "lightup.casebook_anonymous_history",
        "version": 1, "disposition": "HUMAN_REVIEW_ONLY_HOLD",
        "authority": False, "packet_count": len(docs),
        "snapshots": [
            {"ordinal": i + 1, **{x: doc["declared_counts"][x] for x in COUNTS}}
            for i, doc in enumerate(docs)
        ],
        "difference_counts": [
            {"earlier_ordinal": i + 1, "later_ordinal": i + 2,
             "added": sum(x["change"] == "APPEARED" for x in delta[i]),
             "absent": sum(x["change"] == "ABSENT" for x in delta[i]),
             "changed": sum(x["change"] == "FIELDS_CHANGED" for x in delta[i])}
            for i in range(len(delta))
        ],
        "source_authenticated": False, "client_consent_verified": False,
        "operator_consent_verified": False, "authorization_granted": False,
        "execution_allowed": False, "release_approved": False,
    }
    private_rows = [["later_ordinal", "family", "source_declaration", "source_record_id",
                     "changed_source_fields"]]
    for i, group in enumerate(delta):
        private_rows.extend([[i+2, item["family"], item["change"], item["local_source_id"],
                              item["changed_fields"]] for item in group])
    human = [
        "LightUp — ORIGINAL CASEBOOK private HUMAN snapshot history",
        "DRAFT / HOLD; NOT AUTHORIZED; NO SCAN; NO VERDICT.",
        "Packet ordinals are operator-selected, not trustworthy dates.",
        "Absent grants never prove revocation; identical records never prove consent.",
        "Original source declarations can be tampered with; no authentic source seal.",
        "",
    ]
    for i, doc in enumerate(docs):
        human.append(f"Ordinal {i + 1} — requests {len(doc['requests'])}, engagements "
                     f"{len(doc['engagements'])}, grants {len(doc['grants'])}, "
                     f"risk decisions {len(doc['risk_approvals'])}; "
                     f"case HOLD {doc['declared_counts']['case_attention_hold']}")
        if i:
            human.append(f"  Compared with previous ordinal: "
                         f"{Counter(v['change'] for v in delta[i-1])}")
    human.append("\nNext HUMAN action: inspect original source under current authenticated "
                 "permissions, verify independent client/operator consent and at-use "
                 "revocation, and resolve any source HOLD with the original owner. "
                 "No authority is derived from this document.\n")
    queue = case_queue(docs)
    queue_fields = (
        "local_original_engagement_id", "latest_observed_ordinal",
        "source_status", "source_attention", "source_next_human_action",
        "observed_packet_appearances", "human_attention_transitions",
        "latest_grant_count", "latest_risk_record_count", "source_only_priority_group",
    )
    private_queue = csv_text([list(queue_fields)] +
                             [[entry[field] for field in queue_fields] for entry in queue])
    return {
        "private-human-case-queue.csv": private_queue.encode(),
        "index.html": html_page(docs,delta,public=False).encode("utf-8"),
        "anonymous.html": html_page(docs,delta,public=True).encode("utf-8"),
        "anonymous-counts.json": (json.dumps(aggregate, indent=2,sort_keys=True)+"\n").encode(),
        "anonymous-counts.csv": csv_text(counts_rows).encode(),
        "private-source-changes.csv": csv_text(private_rows).encode(),
        "human-followup.txt": "\n".join(human).encode(),
    }


def publish(folder: Path, artifacts: dict[str, bytes]) -> None:
    # User must select a new basename in an already-private parent. Exclusive;
    # never overwrite, follow symlinks or mutate original source packets.
    parent_info = folder.parent.lstat()
    fail(stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode)
         and parent_info.st_mode & 0o077 == 0, "output parent must be owner-private")
    folder.mkdir(mode=0o700, exist_ok=False)
    try:
        for filename, data in artifacts.items():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(folder / filename, flags, 0o600)
            with os.fdopen(descriptor, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
        directory_fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        shutil.rmtree(folder)
        raise


def selected_original_files(inputs: list[Path] | None, packet_dir: Path | None) -> list[Path]:
    """One strict private directory, or explicitly chosen private original files."""
    if packet_dir is None:
        fail(inputs is not None and 2 <= len(inputs) <= 12,
             "require 2-12 original source packets")
        return inputs
    metadata = packet_dir.lstat()
    fail(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
         and metadata.st_mode & 0o077 == 0, "private packet directory refused")
    children = sorted(packet_dir.iterdir(), key=lambda item: item.name)
    fail(2 <= len(children) <= 12, "private packet batch must contain 2-12 originals")
    expected = [f"casebook-{ordinal:02d}.json"
                for ordinal in range(1, len(children) + 1)]
    fail([item.name for item in children] == expected,
         "private packet directory contains unknown or missing originals")
    return children


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HUMAN-only private casebook history from 2–12 ORIGINAL v1 exports; no authority")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--input", type=Path, action="append",
                           help="Owner-private 0600 original Casebook JSON in selected order")
    selection.add_argument("--packet-dir", type=Path,
                           help="PRIVATE 0700 directory containing exactly casebook-01.json...-12.json")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW folder under owner-private parent (never overwrite)")
    args = parser.parse_args()
    try:
        paths = selected_original_files(args.input, args.packet_dir)
        fail(len({str(p.absolute()) for p in paths}) == len(paths),
             "duplicate source path")
        # Admission is whole-batch BEFORE creating any destination.
        admitted = [read_private(p) for p in paths]
        packets = [doc for doc, _ in admitted]
        client = packets[0]["client_id"]
        fail(all(p["client_id"] == client for p in packets),
             "cross-tenant source packets cannot be joined")
        artifacts = generate(packets)
        private_inventory = {
            "kind": "lightup.casebook_private_source_inventory",
            "version": 1,
            "disposition": "HUMAN_REVIEW_ONLY_HOLD",
            "authority": False,
            "source_authenticated": False,
            "snapshots": [
                {"ordinal": index + 1, "source_sha256": hashlib.sha256(raw).hexdigest(),
                 "source_bytes": len(raw)}
                for index, (_, raw) in enumerate(admitted)
            ],
        }
        artifacts["private-source-inventory.json"] = (
            json.dumps(private_inventory, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        publish(args.output_dir, artifacts)
    except (Hold, FileNotFoundError, PermissionError, OSError, ValueError, TypeError):
        print("HOLD: private original source/admission/publication refused; no release "
              "or authorization claimed.", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: owner-private original Casebook HISTORY created. "
          "No consent, scan, grant, verdict or execution authority.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
