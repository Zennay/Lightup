"""Offline multi-packet HUMAN follow-up capacity board for held LightUp lab reviews.

Consumes 2-8 already-created, exact-source-bound PRIVATE annotated review ZIPs.
Never scans, authenticates, authorizes, dispatches, edits sources or grants consent.
All output remains PRIVATE and non-authorizing, including aggregate counts/dates.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import date
from hashlib import sha256
from html import escape
from io import BytesIO, StringIO
import json
import os
import stat
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo, ZIP_DEFLATED

from assessment_runtime_review_handoff_cli_20261018 import _write_exclusive
from assessment_runtime_verify_pack_cli_20261018 import (
    ARCHIVE_LIMIT, ANNOTATED_CAPS, _json, inspect_bytes,
)

STAGES = ("todo", "investigating", "waiting", "planned", "reviewed")
ROUTES = ("unassigned", "lab-runtime", "scope-review",
          "evidence-review", "independent-review")
PRIORITIES = ("Critical drift", "High drift", "Review drift", "No regression")
MAX_ARCHIVE = 350_000
AUTH = {
    "source_authenticated": False,
    "authorized": False,
    "consent_verified": False,
    "dispatch_allowed": False,
    "release_allowed": False,
}


def _private_snapshot(path: str) -> bytes:
    """No symlinked components, hardlinks, non-owner files or unstable reads."""
    parts = os.path.abspath(path).split(os.sep)
    if not parts[-1]:
        raise ValueError("invalid source filename")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(os.sep, flags | os.O_DIRECTORY)
    try:
        for component in parts[1:-1]:
            next_dir = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = next_dir
        fd = os.open(parts[-1], flags | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=directory)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o077 or not 0 < before.st_size <= ARCHIVE_LIMIT):
                raise ValueError("unsafe private source")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(ARCHIVE_LIMIT + 1)
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size,
                                  s.st_mtime_ns, s.st_ctime_ns, s.st_mode)
            if (not raw or len(raw) != before.st_size
                    or len(raw) > ARCHIVE_LIMIT or identity(before) != identity(after)):
                raise ValueError("mutated private source")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _admit(raw: bytes, packet_number: int):
    """Inspect the exact source snapshot before reading human-only fields."""
    status = inspect_bytes(raw)
    with ZipFile(BytesIO(raw)) as archive:
        if set(archive.namelist()) != set(ANNOTATED_CAPS):
            raise ValueError("annotated PRIVATE source required")
        original = archive.read("review-desk.json")
        saved = _json(archive.read("saved-human-review.json"))
    if type(saved) is not dict or type(saved.get("cases")) is not list:
        raise ValueError("invalid saved review")
    version = saved.get("schema")
    if version not in ("lightup-offline-human-triage-v1",
                       "lightup-offline-human-triage-v2"):
        raise ValueError("unsupported saved review")
    rows = []
    for ordinal, item in enumerate(saved["cases"], 1):
        route = item.get("routing_group", "unassigned")
        stage = item["human_stage"]
        priority = item["priority"]
        due = item["follow_up_date"]
        if (stage not in STAGES or route not in ROUTES or priority not in PRIORITIES
                or item["case"] != "Case %02d" % ordinal):
            raise ValueError("unexpected human row")
        # The source inspector already validated the canonical date and each
        # source comparison; no original scenario identity leaves this function.
        rows.append({
            "packet": "Packet %02d" % packet_number,
            "case": "Case %02d" % ordinal,
            "priority": priority,
            "source_status": item["source_status"],
            "routing_group": route,
            "human_stage": stage,
            "follow_up_date": due,
            "regression_count": len(item["metric_regressions"]),
        })
    return status, sha256(original).hexdigest(), rows


def _board(packets: list[bytes], max_per_group: int | None, reference: str | None):
    rows = []
    seen_sources = set()
    statuses = []
    for index, raw in enumerate(packets, 1):
        status, source_digest, selected = _admit(raw, index)
        # Multiple human revisions of the SAME original source are alternatives,
        # not independent cases to silently double count.
        if source_digest in seen_sources:
            raise ValueError("duplicate original comparison across packets")
        seen_sources.add(source_digest)
        statuses.append(status)
        rows.extend(selected)
    open_rows = [row for row in rows if row["human_stage"] != "reviewed"]
    groups = defaultdict(list)
    for row in open_rows:
        groups[(row["follow_up_date"] or "undated", row["routing_group"])].append(row)
    loads = []
    for (due, route), members in sorted(groups.items()):
        count = len(members)
        loads.append({
            "follow_up_date": due,
            "routing_group": route,
            "open_items": count,
            "declared_capacity": max_per_group,
            "above_declared_capacity": (
                max(0, count - max_per_group) if max_per_group is not None else None
            ),
        })
    overdue = (sum(1 for row in open_rows
                   if row["follow_up_date"] and row["follow_up_date"] < reference)
               if reference else None)
    return {
        "schema": "lightup.private_human_capacity.v1",
        "purpose": "OFFLINE_HUMAN_PLANNING_ONLY",
        "comparison_status": "HOLD" if "HOLD" in statuses else "REVIEW_ONLY",
        "packet_count": len(packets),
        "human_work_rows": len(rows),
        "open_work_rows": len(open_rows),
        "reviewed_rows": len(rows) - len(open_rows),
        "undated_open_rows": sum(row["follow_up_date"] is None for row in open_rows),
        "reference_date": reference,
        "overdue_open_rows": overdue,
        "declared_capacity_per_route_date": max_per_group,
        "capacity_note": "User-declared hypothetical count; not staffing or assignments.",
        "human_stages": {name: sum(r["human_stage"] == name for r in rows)
                         for name in STAGES},
        "routing_groups": {name: sum(r["routing_group"] == name for r in rows)
                           for name in ROUTES},
        "priorities": {name: sum(r["priority"] == name for r in rows)
                       for name in PRIORITIES},
        "route_date_loads": loads,
        "rows": rows,
        **AUTH,
    }


def _csv(board: dict) -> bytes:
    stream = StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    columns = ("packet", "case", "priority", "source_status",
               "routing_group", "human_stage", "follow_up_date",
               "regression_count")
    writer.writerow(columns)
    for row in board["rows"]:
        writer.writerow([row[key] if row[key] is not None else "" for key in columns])
    return stream.getvalue().encode("utf-8")


def _priority_route_loads(board: dict):
    """Count open HUMAN rows by source-reported priority, date and route."""
    counts = Counter(
        (row["priority"], row["follow_up_date"] or "undated",
         row["routing_group"])
        for row in board["rows"] if row["human_stage"] != "reviewed"
    )
    priority_order = {name: index for index, name in enumerate(PRIORITIES)}
    route_order = {name: index for index, name in enumerate(ROUTES)}
    return sorted(
        ((priority, day, route, count)
         for (priority, day, route), count in counts.items()),
        key=lambda item: (priority_order[item[0]], item[1], route_order[item[2]]),
    )


def _summary_csv(board: dict) -> bytes:
    """Export fixed-vocabulary aggregate and date/route load rows."""
    stream = StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("section", "category", "count", "follow_up_date",
                     "routing_group", "open_items", "declared_capacity",
                     "above_declared_capacity", "reference_date",
                     "overdue_open_rows"))
    reference = board["reference_date"] or ""
    overdue = ("" if board["overdue_open_rows"] is None
               else board["overdue_open_rows"])
    for name in PRIORITIES:
        writer.writerow(("priority", name, board["priorities"][name],
                         "", "", "", "", "", reference, overdue))
    for name in STAGES:
        writer.writerow(("human_stage", name, board["human_stages"][name],
                         "", "", "", "", "", reference, overdue))
    for name in ROUTES:
        writer.writerow(("routing_group", name, board["routing_groups"][name],
                         "", "", "", "", "", reference, overdue))
    for item in board["route_date_loads"]:
        writer.writerow((
            "route_date_load", "", "", item["follow_up_date"],
            item["routing_group"], item["open_items"],
            "" if item["declared_capacity"] is None else item["declared_capacity"],
            "" if item["above_declared_capacity"] is None else item["above_declared_capacity"],
            reference, overdue,
        ))
    for priority, day, route, count in _priority_route_loads(board):
        writer.writerow((
            "priority_route_date_load", priority, count, day, route, count,
            "", "", reference, overdue,
        ))
    return stream.getvalue().encode("utf-8")


def _html(board: dict) -> bytes:
    headings = ("Packet", "Case", "Priority", "Source", "Route", "Stage",
                "Follow-up", "Regressions")
    keys = ("packet", "case", "priority", "source_status", "routing_group",
            "human_stage", "follow_up_date", "regression_count")
    header = "".join("<th scope='col'>%s</th>" % escape(key) for key in headings)
    body = "".join(
        "<tr>" + "".join("<td>%s</td>" % escape(str(row[key] if row[key] is not None else "—"))
                          for key in keys) + "</tr>"
        for row in board["rows"]
    )
    priority_rows = "".join(
        "<tr><th scope='row'>%s</th><td>%d</td></tr>" %
        (escape(name), board["priorities"][name]) for name in PRIORITIES
    )
    stage_rows = "".join(
        "<tr><th scope='row'>%s</th><td>%d</td></tr>" %
        (escape(name), board["human_stages"][name]) for name in STAGES
    )
    route_rows = "".join(
        "<tr><th scope='row'>%s</th><td>%d</td></tr>" %
        (escape(name), board["routing_groups"][name]) for name in ROUTES
    )
    load_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % tuple(
            escape(str(item[key] if item[key] is not None else "unspecified"))
            for key in ("follow_up_date", "routing_group", "open_items",
                        "above_declared_capacity")
        ) for item in board["route_date_loads"]
    )
    priority_load_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%d</td></tr>" %
        (escape(priority), escape(day), count)
        for priority, day, route, count in _priority_route_loads(board)
        for _ in (None,)
    )
    # Keep the route visible in the table while preserving fixed vocabulary.
    priority_load_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>" %
        (escape(priority), escape(day), escape(route), count)
        for priority, day, route, count in _priority_route_loads(board)
    )
    overdue_text = (
        "Not computed: no explicit reference date supplied."
        if board["overdue_open_rows"] is None
        else "%d open rows overdue relative to %s." %
             (board["overdue_open_rows"], board["reference_date"])
    )
    content = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        " style-src 'unsafe-inline'; connect-src 'none'; form-action 'none';"
        " base-uri 'none'\"><title>LightUp PRIVATE human capacity</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;"
        "margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%%}"
        "th,td{border:1px solid #9ba5b4;padding:.45rem;text-align:left}"
        "tr{break-inside:avoid} .warning{border-left:5px solid #ab5500;padding:1rem}"
        ".summaries{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}"
        "@media print{body{font-size:10pt}}</style></head><body>"
        "<h1>LightUp · PRIVATE human capacity</h1>"
        "<p class='warning'><strong>%s · HUMAN PLANNING ONLY · NOT AUTHORIZED</strong>"
        " Source packets are untrusted. No scan, grant, consent, source verification,"
        " staffing decision, dispatch or release is implied.</p>"
        "<p>%d packets · %d work rows · %d open · %d reviewed · %d undated.</p>"
        "<p>%s</p>"
        "<p>Capacity is a hypothetical operator-supplied row limit per date/route."
        " Rows are declared human work, not unique vulnerabilities or owners."
        " Packet ordinals are input order, never authenticated source identity.</p>"
        "<div class='summaries'><section><h2>Priority distribution</h2><table>"
        "<thead><tr><th>Source priority</th><th>Rows</th></tr></thead><tbody>%s</tbody></table></section>"
        "<section><h2>HUMAN stage distribution</h2><table>"
        "<thead><tr><th>Self-reported stage</th><th>Rows</th></tr></thead><tbody>%s</tbody></table></section>"
        "<section><h2>Routing distribution</h2><table>"
        "<thead><tr><th>Self-reported route</th><th>Rows</th></tr></thead><tbody>%s</tbody></table></section></div>"
        "<h2>Open row load by date and route</h2><table><thead><tr>"
        "<th>Date</th><th>Route</th><th>Open</th><th>Above hypothetical limit</th>"
        "</tr></thead><tbody>%s</tbody></table>"
        "<h2>Open load by source priority, date and route</h2><table><thead><tr>"
        "<th>Source priority</th><th>Date</th><th>Route</th><th>Open</th>"
        "</tr></thead><tbody>%s</tbody></table>"
        "<h2>All HUMAN review rows</h2><table><thead><tr>%s</tr></thead>"
        "<tbody>%s</tbody></table>"
        "<p>PRIVATE offline export: keep dates/counts confidential. No source"
        " IDs, original finding text, hashes or target details exported.</p>"
        "</body></html>"
    ) % (escape(board["comparison_status"]), board["packet_count"],
         board["human_work_rows"], board["open_work_rows"],
         board["reviewed_rows"], board["undated_open_rows"],
         escape(overdue_text), priority_rows, stage_rows, route_rows,
         load_rows, priority_load_rows, header, body)
    return content.encode("utf-8")

def _render(board: dict) -> bytes:
    json_bytes = json.dumps(board, ensure_ascii=True, sort_keys=True,
                            separators=(",", ":"), allow_nan=False).encode("ascii")
    csv_bytes = _csv(board)
    summary_csv_bytes = _summary_csv(board)
    html_bytes = _html(board)
    manifest_bytes = json.dumps({
        "format": "lightup.private_human_capacity_pack.v2",
        "comparison_status": board["comparison_status"],
        "human_work_rows": board["human_work_rows"],
        "capacity_json_sha256": sha256(json_bytes).hexdigest(),
        "capacity_csv_sha256": sha256(csv_bytes).hexdigest(),
        "capacity_summary_csv_sha256": sha256(summary_csv_bytes).hexdigest(),
        "capacity_html_sha256": sha256(html_bytes).hexdigest(),
        **AUTH,
    }, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    instructions = (
        "LIGHTUP PRIVATE HUMAN CAPACITY / NO AUTHORITY\n"
        "Open capacity.html offline or import capacity.csv, capacity-summary.csv / capacity.json.\n"
        "Only original reviewed HUMAN rows were counted, never claims of evidence.\n"
        "Repeated original comparison identities are rejected, not aggregated.\n"
        "Packet labels reflect manual CLI argument order; dates and stages are\n"
        "self-reported plans. Hypothetical limits are not actual human availability.\n"
        "Never use these files for scanning, grants, consent or release decisions.\n"
        "All files are sensitive private HUMAN planning outputs.\n"
    ).encode("utf-8")
    buffer = BytesIO()
    with ZipFile(buffer, "w") as output:
        for name, payload in (("READ-ME.txt", instructions),
                              ("manifest.json", manifest_bytes),
                              ("capacity.json", json_bytes),
                              ("capacity.csv", csv_bytes),
                              ("capacity-summary.csv", summary_csv_bytes),
                              ("capacity.html", html_bytes)):
            if not payload or len(payload) > 250_000:
                raise ValueError("output member exceeds limit")
            member = ZipInfo(name, date_time=(2026, 10, 23, 0, 0, 0))
            member.compress_type = ZIP_DEFLATED
            member.external_attr = 0o600 << 16
            output.writestr(member, payload)
    result = buffer.getvalue()
    if len(result) > MAX_ARCHIVE:
        raise ValueError("capacity archive exceeds limit")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+", help="2–8 distinct original annotated PRIVATE review ZIPs")
    parser.add_argument("--output", help="New private ZIP path; never overwrite")
    parser.add_argument("--preview-only", action="store_true",
                        help="Aggregate counts in memory; no output directory or file")
    parser.add_argument("--capacity-per-group", type=int, default=None,
                        help="Optional hypothetical row count per date and route (1–64)")
    parser.add_argument("--reference-date",
                        help="Explicit YYYY-MM-DD reference for overdue counts, no system clock")
    args = parser.parse_args(argv)
    try:
        if not 2 <= len(args.packages) <= 8:
            raise ValueError("packet count outside bound")
        if (args.capacity_per_group is not None
                and not 1 <= args.capacity_per_group <= 64):
            raise ValueError("invalid hypothetical capacity")
        if args.reference_date is not None:
            if (len(args.reference_date) != 10
                    or date.fromisoformat(args.reference_date).isoformat()
                    != args.reference_date):
                raise ValueError("non-canonical reference date")
        raw = [_private_snapshot(path) for path in args.packages]
        board = _board(raw, args.capacity_per_group, args.reference_date)
        if args.preview_only:
            if args.output is not None:
                raise ValueError("preview cannot publish output")
            print("PRIVATE_HUMAN_CAPACITY_PREVIEW — " + board["comparison_status"]
                  + "; packets=" + str(board["packet_count"])
                  + "; open_rows=" + str(board["open_work_rows"])
                  + "; reviewed_rows=" + str(board["reviewed_rows"])
                  + "; undated_open=" + str(board["undated_open_rows"])
                  + "; NOT AUTHORIZED")
            return 2 if board["comparison_status"] == "REVIEW_ONLY" else 3
        if not args.output:
            raise ValueError("an output path is required")
        _write_exclusive(args.output, _render(board))
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError, RuntimeError,
            EOFError, NotImplementedError, BadZipFile, LargeZipFile):
        print("PRIVATE_HUMAN_CAPACITY_HOLD")
        return 3
    print("PRIVATE_HUMAN_CAPACITY_WRITTEN — " + board["comparison_status"]
          + "; UNSIGNED; NOT AUTHORIZED")
    return 2 if board["comparison_status"] == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())