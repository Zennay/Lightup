#!/usr/bin/env python3
"""Source-minimal OFFLINE PRIVATE HUMAN workload capacity assumption desk.

These are human-proposed dates and roles, not booked meetings, staff assignments,
verified findings, authorization, approval or an execution schedule.
"""
from __future__ import annotations

import base64
from collections import defaultdict
import csv
from hashlib import sha256
from html import escape
import io


class CapacityHold(ValueError):
    """Private capacity configuration cannot be admitted."""


MAX_PER_ROLE_DAY = 128
STYLE = (
    "*{box-sizing:border-box}body{font:16px/1.5 system-ui,sans-serif;background:#f3f5f8;"
    "color:#17212f;margin:0 auto;max-width:1250px;padding:1.5rem}"
    "header,section{background:#fff;border:1px solid #cbd5e1;border-radius:10px;"
    "padding:1.3rem;margin-bottom:1rem}.hold{padding:.8rem;background:#fff7ed;"
    "border-left:5px solid #a16207;font-weight:750}.note{color:#475569}"
    "table{border-collapse:collapse;width:100%;font-size:.87rem}th,td{border:1px solid #d6dfeb;"
    "padding:.55rem;text-align:left;vertical-align:top}th{background:#eef2f7}"
    ".scroll{overflow-x:auto}a{color:#07549d}li{margin:.35rem 0}"
    "tr.excess td{background:#fff3e6;font-weight:600}"
    "@media print{body{background:white;max-width:none;padding:.3rem}"
    "header,section{break-inside:avoid}table{font-size:9pt}}"
)


def configure(enabled, default_limit, assignments, roles):
    """Explicit assumption only: no inference from real staffing or identities."""
    if not enabled:
        if default_limit is not None or assignments:
            raise CapacityHold("capacity limits require explicit PRIVATE capacity desk")
        return None
    if type(default_limit) is not int or not 1 <= default_limit <= MAX_PER_ROLE_DAY:
        raise CapacityHold("capacity desk needs explicit 1–128 proposed items per role/day")
    result = {role: default_limit for role in roles}
    touched = set()
    for entry in assignments:
        if type(entry) is not str or entry.count("=") != 1:
            raise CapacityHold("role capacity must be an exact neutral role=integer")
        role, raw_limit = entry.split("=", 1)
        if (role not in result or role in touched or not raw_limit.isascii()
                or not raw_limit.isdigit() or len(raw_limit) > 3):
            raise CapacityHold("duplicate or unknown proposed neutral role capacity")
        limit = int(raw_limit)
        if not 1 <= limit <= MAX_PER_ROLE_DAY:
            raise CapacityHold("role capacity must be between 1 and 128")
        touched.add(role)
        result[role] = limit
    return result


def collect(rows, limits, roles):
    """Aggregate previously admitted, optionally filtered source rows only."""
    groups = defaultdict(list)
    undated = defaultdict(list)
    for item in rows:
        role = item["next_role"]
        if role not in limits:
            raise CapacityHold("unknown original proposed role")
        if item["review_date"] is None:
            undated[role].append(item)
        else:
            groups[(item["review_date"], role)].append(item)
    records = []
    for (day, role), members in sorted(
        groups.items(), key=lambda entry: (entry[0][0], roles.index(entry[0][1]))
    ):
        demand = len(members)
        proposed_limit = limits[role]
        records.append({
            "day": day,
            "role": role,
            "items": demand,
            "declared_daily_limit": proposed_limit,
            "items_above_declared_limit": max(0, demand - proposed_limit),
            "source_agenda_count": len({entry["agenda_slot"] for entry in members}),
            "members": sorted(members, key=lambda entry: (entry["agenda_slot"], entry["source_slot"])),
        })
    return records, undated


def render_private_capacity(rows, reference_day, limits, roles):
    """CSP-pinned local HTML and exact PRIVATE ordinal spreadsheet, never anonymous."""
    records, undated = collect(rows, limits, roles)
    all_over = sum(row["items_above_declared_limit"] for row in records)
    undated_count = sum(len(items) for items in undated.values())
    nonempty_over = sum(row["items_above_declared_limit"] > 0 for row in records)
    fixed = (
        "<p class='note'>A limit is an operator's declared number of HUMAN discussion "
        "items per suggested role per proposed day, NOT real staffing. An excess is a "
        "comparison with that hypothetical limit, NOT proof of an actual schedule "
        "conflict, assignment, verified finding, consent or urgency.</p>"
    )
    def ordinal_link(item):
        number = ("A" + str(item["agenda_slot"]).zfill(2) +
                  "/S" + str(item["source_slot"]).zfill(2))
        anchor = ("assessment-portfolio-private.html#agenda-" +
                  str(item["agenda_slot"]) + "-slot-" + str(item["source_slot"]))
        return "<a href='" + escape(anchor, quote=True) + "'>" + escape(number) + "</a>"

    table_rows = []
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow((
        "original_proposed_day", "suggested_neutral_role", "proposed_human_items",
        "operator_declared_items_per_role_day", "items_above_operator_assumption",
        "distinct_agenda_slots", "original_source_ordinals", "authority_status",
    ))
    for record in records:
        links = ", ".join(ordinal_link(row) for row in record["members"])
        source_ids = ";".join(
            "A" + str(row["agenda_slot"]).zfill(2) + "/S" + str(row["source_slot"]).zfill(2)
            for row in record["members"]
        )
        table_rows.append(
            ("<tr class='excess'>" if record["items_above_declared_limit"] else "<tr>") +
            "<td>" + escape(record["day"]) + "</td><td>" + escape(record["role"]) +
            "</td><td>" + str(record["items"]) + "</td><td>" +
            str(record["declared_daily_limit"]) + "</td><td>" +
            str(record["items_above_declared_limit"]) + "</td><td>" +
            str(record["source_agenda_count"]) + "</td><td>" + links + "</td></tr>"
        )
        writer.writerow((
            record["day"], record["role"], record["items"], record["declared_daily_limit"],
            record["items_above_declared_limit"], record["source_agenda_count"],
            source_ids, "REVIEW_ONLY",
        ))
    undated_rows = []
    for role in roles:
        members = sorted(undated.get(role, []), key=lambda row: (row["agenda_slot"], row["source_slot"]))
        if not members:
            continue
        ids = ", ".join(ordinal_link(row) for row in members)
        source_ids = ";".join(
            "A" + str(row["agenda_slot"]).zfill(2) + "/S" + str(row["source_slot"]).zfill(2)
            for row in members
        )
        undated_rows.append("<tr><td>" + escape(role) + "</td><td>" +
                            str(len(members)) + "</td><td>" + ids + "</td></tr>")
        writer.writerow(("", role, len(members), "", "", 
                         len({row["agenda_slot"] for row in members}),
                         source_ids, "REVIEW_ONLY"))
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'sha256-" + style_hash + "'; script-src 'none'; connect-src 'none'; "
        "img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN capacity assumption desk</title>"
        "<style>" + STYLE + "</style></head><body>"
        "<header><p>LightUp · Assessment Runtime · OFFLINE / PRIVATE</p>"
        "<h1>HUMAN workload versus manually declared limits</h1>"
        "<div class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · HOLD · NOT AUTHORIZED</div>"
        "<p>Original planning reference " + escape(reference_day.isoformat()) +
        "; " + str(len(rows)) + " original HUMAN items in the selected view. "
        + str(nonempty_over) + " role/day groups exceed operator-declared assumptions; "
        + str(all_over) + " proposed items above hypothetical limits; "
        + str(undated_count) + " items with no original proposed day.</p>" + fixed + "</header>"
        "<section><h2>Manually entered proposed daily limits</h2><p>" +
        "; ".join(escape(role) + ": " + str(limits[role]) for role in roles) +
        " HUMAN items per proposed day. These are inputs, not observed capacity.</p></section>"
        "<section><h2>Original proposed days</h2>" +
        ("<div class='scroll'><table><thead><tr><th>Proposed day</th><th>Neutral role</th>"
         "<th>HUMAN items</th><th>Declared limit</th><th>Over assumption</th>"
         "<th>Agenda slots</th><th>Open original ordinals</th></tr></thead><tbody>" +
         "".join(table_rows) + "</tbody></table></div>" if table_rows
         else "<p>No dated HUMAN rows match this selection; never infer completion.</p>") +
        "</section><section><h2>Unscheduled original HUMAN items</h2><p class='note'>"
        "These items have no original proposed date and are never assigned a "
        "synthetic day, counted as daily capacity usage, or silently discarded.</p>" +
        ("<div class='scroll'><table><thead><tr><th>Neutral role</th><th>Items</th>"
         "<th>Open original ordinals</th></tr></thead><tbody>" +
         "".join(undated_rows) + "</tbody></table></div>" if undated_rows
         else "<p>None visible in this selection. This is not completion.</p>") +
        "</section><footer class='note'>Original source ordinals and planning "
        "assumptions are PRIVATE. No network, grants, dispatch, verified review, "
        "approved scope, client/operator consent or assessment.</footer></body></html>"
    )
    return (
        ("assessment-portfolio-private-capacity.html", html.encode("utf-8")),
        ("assessment-portfolio-private-capacity.csv", buffer.getvalue().encode("utf-8")),
    )


def render_private_capacity_comparison(rows, reference_day, current_limits,
                                       alternative_limits, roles):
    """Two explicitly supplied HUMAN capacity *assumptions*, not actual schedules."""
    records, undated = collect(rows, current_limits, roles)
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow((
        "original_proposed_day", "suggested_neutral_role", "human_items",
        "first_declared_daily_limit", "first_items_above_assumption",
        "alternative_declared_daily_limit", "alternative_items_above_assumption",
        "alternative_minus_first_excess", "original_source_ordinals",
        "authority_status",
    ))
    rows_html = []
    first_total = other_total = 0
    for record in records:
        role, day = record["role"], record["day"]
        demand = record["items"]
        first_over = max(0, demand - current_limits[role])
        other_over = max(0, demand - alternative_limits[role])
        first_total += first_over
        other_total += other_over
        source = ";".join(
            "A" + str(item["agenda_slot"]).zfill(2) + "/S" +
            str(item["source_slot"]).zfill(2) for item in record["members"]
        )
        links = " ".join(
            "<a href='assessment-portfolio-private.html#agenda-" +
            str(item["agenda_slot"]) + "-slot-" + str(item["source_slot"]) +
            "'>A" + str(item["agenda_slot"]).zfill(2) + "/S" +
            str(item["source_slot"]).zfill(2) + "</a>"
            for item in record["members"]
        )
        diff = other_over - first_over
        rows_html.append(
            "<tr><td>" + escape(day) + "</td><td>" + escape(role) +
            "</td><td>" + str(demand) + "</td><td>" + str(current_limits[role]) +
            "</td><td>" + str(first_over) + "</td><td>" +
            str(alternative_limits[role]) + "</td><td>" + str(other_over) +
            "</td><td>" + str(diff) + "</td><td>" + links + "</td></tr>"
        )
        writer.writerow((
            day, role, demand, current_limits[role], first_over,
            alternative_limits[role], other_over, diff, source, "REVIEW_ONLY",
        ))
    undated_total = sum(len(items) for items in undated.values())
    # An undated source never becomes a made-up daily capacity charge.
    for role in roles:
        items = sorted(undated.get(role, []),
                       key=lambda row: (row["agenda_slot"], row["source_slot"]))
        if not items:
            continue
        source = ";".join(
            "A" + str(item["agenda_slot"]).zfill(2) + "/S" +
            str(item["source_slot"]).zfill(2) for item in items
        )
        writer.writerow(("", role, len(items), "", "", "", "", "", source, "REVIEW_ONLY"))
    style_hash = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'sha256-" + style_hash + "'; script-src 'none'; "
        "connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN capacity assumption comparison</title>"
        "<style>" + STYLE + "</style></head><body>"
        "<header><h1>Two operator-declared HUMAN capacity scenarios</h1>"
        "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW ONLY · NOT AUTHORIZED</p>"
        "<p>Planning reference " + escape(reference_day.isoformat()) +
        ". Total source-derived items above manually stated per-role/day "
        "assumptions: first " + str(first_total) + ", alternative " +
        str(other_total) + ", arithmetic difference " + str(other_total - first_total) +
        ". " + str(undated_total) + " original items have no proposed day "
        "and were not charged to either daily limit.</p>"
        "<p class='note'>Only original, optionally focused source rows are counted. "
        "The numbers compare TWO hypothetical HUMAN discussion capacities, "
        "not actual availability, confirmed meetings, completed fixes or authorization. "
        "A lower number is not a validated operational improvement.</p></header>"
        "<section><h2>Original proposed day x neutral role</h2>" +
        ("<div class='scroll'><table><thead><tr><th>Proposed day</th><th>Role</th>"
         "<th>Items</th><th>First limit</th><th>First above</th><th>Alternative limit</th>"
         "<th>Alternative above</th><th>Alternative minus first</th>"
         "<th>Original ordinals</th></tr></thead><tbody>" + "".join(rows_html) +
         "</tbody></table></div>" if rows_html
         else "<p>No dated original HUMAN items match this selection. Not completion.</p>") +
        "</section><section><h2>Original assumptions by fixed role</h2><ul>" +
        "".join(
            "<li>" + escape(role) + ": first " + str(current_limits[role]) +
            ", alternative " + str(alternative_limits[role]) +
            " proposed items per role/day</li>" for role in roles
        ) +
        "</ul></section><footer class='note'>PRIVATE local arithmetic only; "
        "no network, model, scan, grant, source identity, client/operator consent "
        "or live dispatch.</footer></body></html>"
    )
    return (
        ("assessment-portfolio-private-capacity-comparison.html", html.encode("utf-8")),
        ("assessment-portfolio-private-capacity-comparison.csv",
         out.getvalue().encode("utf-8")),
    )
