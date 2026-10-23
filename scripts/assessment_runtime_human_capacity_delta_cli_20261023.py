#!/usr/bin/env python3
"""Compare two already-verified PRIVATE HUMAN capacity ZIPs offline, counts only.

Each ZIP is independently admitted by the ORIGINAL read-only capacity inspector.
The operator-supplied order is not verified chronology or common-source identity.
No network, scanner, consent, authority, subprocess or source mutation.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from hashlib import sha256
from html import escape
from io import BytesIO, StringIO
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED, BadZipFile, LargeZipFile
import csv
import json
import sys

from assessment_runtime_human_capacity_cli_20261023 import (
    AUTH, PRIORITIES, ROUTES, STAGES, MAX_ARCHIVE, _private_snapshot,
)
from assessment_runtime_human_capacity_inspect_cli_20261023 import inspect
from assessment_runtime_review_handoff_cli_20261018 import _write_exclusive
from assessment_runtime_verify_pack_cli_20261018 import _json

KIND = "lightup.private_human_capacity_aggregate_delta.v1"
MAX_RESULT = 450_000
ALLOWED_MEMBERS = {
    "READ-ME.txt": 2_048,
    "manifest.json": 4_096,
    "delta.json": 220_000,
    "delta.csv": 220_000,
    "delta.html": 240_000,
}
COUNT_KINDS = {
    "summary": ("packet_count", "human_work_rows", "open_work_rows",
                "reviewed_rows", "undated_open_rows"),
    "stage": STAGES,
    "route": ROUTES,
    "priority": PRIORITIES,
}
REPORT_KEYS = frozenset({
    "schema", "purpose", "comparison_status", "earlier_status", "later_status",
    "earlier_reference_date", "later_reference_date",
    "same_reference_date", "earlier_hypothetical_capacity",
    "later_hypothetical_capacity", "same_hypothetical_capacity",
    "chronology_verified", "common_source_verified", "rows",
    *AUTH,
})
ROW_KEYS = frozenset({"kind", "label", "earlier", "later", "change"})
MANIFEST_KEYS = frozenset({
    "schema", "comparison_status", "delta_json_sha256",
    "delta_csv_sha256", "delta_html_sha256", *AUTH,
})


def _original_capacity(path: str) -> dict:
    raw = _private_snapshot(path)
    inspect(raw)  # Original exact full six-member source admission, not reinvented.
    with ZipFile(BytesIO(raw)) as archive:
        return _json(archive.read("capacity.json"))


def _rows(a: dict, b: dict) -> list[dict]:
    result = []
    for kind, labels in COUNT_KINDS.items():
        for label in labels:
            before = (a[label] if kind == "summary" else a[
                {"stage": "human_stages", "route": "routing_groups",
                 "priority": "priorities"}[kind]][label])
            after = (b[label] if kind == "summary" else b[
                {"stage": "human_stages", "route": "routing_groups",
                 "priority": "priorities"}[kind]][label])
            result.append(dict(kind=kind, label=label, earlier=before,
                               later=after, change=after-before))
    # These are separate source-reported HUMAN workload summaries, never
    # a joined case timeline or verified trend in an identical cohort.
    first = {(x["follow_up_date"], x["routing_group"]): x["open_items"]
             for x in a["route_date_loads"]}
    second = {(x["follow_up_date"], x["routing_group"]): x["open_items"]
              for x in b["route_date_loads"]}
    for day, route in sorted(first.keys() | second.keys()):
        before, after = first.get((day, route), 0), second.get((day, route), 0)
        result.append(dict(kind="date_route", label=day+" / "+route,
                           earlier=before, later=after, change=after-before))
    return result


def _compare(a: dict, b: dict) -> dict:
    return {
        "schema": KIND,
        "purpose": "PRIVATE_AGGREGATE_HUMAN_DISCUSSION_ONLY",
        "comparison_status": ("HOLD" if "HOLD" in (
            a["comparison_status"], b["comparison_status"]) else "REVIEW_ONLY"),
        "earlier_status": a["comparison_status"],
        "later_status": b["comparison_status"],
        "earlier_reference_date": a["reference_date"],
        "later_reference_date": b["reference_date"],
        "same_reference_date": (a["reference_date"] == b["reference_date"]),
        "earlier_hypothetical_capacity": a["declared_capacity_per_route_date"],
        "later_hypothetical_capacity": b["declared_capacity_per_route_date"],
        "same_hypothetical_capacity": (
            a["declared_capacity_per_route_date"] ==
            b["declared_capacity_per_route_date"]),
        "chronology_verified": False,
        "common_source_verified": False,
        "rows": _rows(a, b),
        **AUTH,
    }


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _csv(report: dict) -> bytes:
    stream = StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(("section", "category", "earlier", "later", "change"))
    for row in report["rows"]:
        writer.writerow((row["kind"], row["label"], row["earlier"],
                         row["later"], row["change"]))
    return stream.getvalue().encode("utf-8")


def _html(report: dict) -> bytes:
    rows = "".join(
        "<tr><td>"+escape(item["kind"])+"</td><th scope='row'>"+
        escape(item["label"])+"</th><td>"+str(item["earlier"])+
        "</td><td>"+str(item["later"])+"</td><td>"+
        ("%+d" % item["change"])+"</td></tr>"
        for item in report["rows"]
    )
    matched_reference = "same literal reference" if report["same_reference_date"] else (
        "DIFFERENT reference day / overdue comparisons are not valid")
    matched_capacity = "same hypothetical limit" if report["same_hypothetical_capacity"] else (
        "DIFFERENT hypothetical capacity / overload comparisons are not valid")
    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'none'; script-src 'none'; connect-src 'none'; "
        "img-src 'none'; frame-src 'none'; base-uri 'none'\">"
        "<title>LightUp PRIVATE HUMAN capacity aggregate comparison</title>"
        "</head><body><main><h1>PRIVATE HUMAN capacity snapshots · review only</h1>"
        "<p>Literal input order is OPERATOR-SELECTED, not verified chronology. "
        "Snapshots may represent different original cases and cannot prove that "
        "work was completed, risk removed, or real capacity exists.</p>"
        "<p>Status: "+escape(report["comparison_status"])+". "
        +escape(matched_reference)+". "+escape(matched_capacity)+".</p>"
        "<p>Only aggregate counts and declared date/route load. "
        "No original finding, target, source hash, case or person included. "
        "PRIVATE numeric cohorts and dates may nevertheless be sensitive.</p>"
        "<table border='1'><caption>Self-reported HUMAN aggregate differences, "
        "not verified trends</caption><thead><tr><th>Dimension</th>"
        "<th>Aggregate category</th><th>Earlier (manually named)</th>"
        "<th>Later (manually named)</th><th>Arithmetic change</th></tr></thead>"
        "<tbody>"+rows+"</tbody></table><p>Source and chronology verified: FALSE. "
        "Authenticated authority, consent, dispatch and release: FALSE.</p>"
        "</main></body></html>"
    )
    return page.encode("utf-8")


def _render(report: dict) -> bytes:
    members = {
        "delta.json": _canonical(report),
        "delta.csv": _csv(report),
        "delta.html": _html(report),
        "READ-ME.txt": (
            b"LIGHTUP PRIVATE HUMAN CAPACITY DELTA / NO AUTHORITY\n"
            b"Operator-ordered snapshots; never verified chronology or common source.\n"
            b"Only private aggregate HUMAN discussion, no scans or grants.\n"
        ),
    }
    manifest = {
        "schema": "lightup.private_human_capacity_delta_pack.v1",
        "comparison_status": report["comparison_status"],
        **{name.replace(".", "_")+"_sha256": sha256(members[name]).hexdigest()
           for name in ("delta.json", "delta.csv", "delta.html")},
        **AUTH,
    }
    # Deliberate exact known manifest names: no dynamic source paths or secrets.
    members["manifest.json"] = _canonical(manifest)
    result = BytesIO()
    with ZipFile(result, "w") as archive:
        for name in ("READ-ME.txt", "manifest.json", "delta.json",
                     "delta.csv", "delta.html"):
            value = members[name]
            if not 0 < len(value) <= ALLOWED_MEMBERS[name]:
                raise ValueError("bounded aggregate member exceeded")
            entry = ZipInfo(name, date_time=(2026, 10, 23, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o600 << 16
            archive.writestr(entry, value)
    raw = result.getvalue()
    if len(raw) > MAX_RESULT:
        raise ValueError("bounded aggregate package exceeded")
    return raw


def _inspect_delta(raw: bytes) -> tuple[str, int]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESULT:
        raise ValueError("invalid delta bundle")
    with ZipFile(BytesIO(raw)) as archive:
        info = archive.infolist()
        if len(info) != len(ALLOWED_MEMBERS) or set(archive.namelist()) != set(ALLOWED_MEMBERS):
            raise ValueError("unknown delta layout")
        contents = {}
        for item in info:
            if (item.is_dir() or item.flag_bits & 1
                    or item.compress_type != ZIP_DEFLATED
                    or not 0 < item.file_size <= ALLOWED_MEMBERS[item.filename]):
                raise ValueError("invalid private delta member")
            payload = archive.read(item)
            if len(payload) != item.file_size:
                raise ValueError("truncated private member")
            contents[item.filename] = payload
    report = _json(contents["delta.json"])
    manifest = _json(contents["manifest.json"])
    if (type(report) is not dict or set(report) != REPORT_KEYS
            or report["schema"] != KIND
            or report["purpose"] != "PRIVATE_AGGREGATE_HUMAN_DISCUSSION_ONLY"
            or report["comparison_status"] not in ("HOLD", "REVIEW_ONLY")
            or report["earlier_status"] not in ("HOLD", "REVIEW_ONLY")
            or report["later_status"] not in ("HOLD", "REVIEW_ONLY")
            or report["comparison_status"] != (
                "HOLD" if "HOLD" in (report["earlier_status"], report["later_status"])
                else "REVIEW_ONLY")
            or report["chronology_verified"] is not False
            or report["common_source_verified"] is not False
            or any(report[key] is not False for key in AUTH)):
        raise ValueError("unknown source/authority state")
    for field, same in (("reference_date", "same_reference_date"),
                        ("hypothetical_capacity", "same_hypothetical_capacity")):
        before = report["earlier_"+field]
        after = report["later_"+field]
        if type(report[same]) is not bool or report[same] != (before == after):
            raise ValueError("invalid stated comparability")
        if field == "reference_date":
            for v in (before, after):
                if v is not None and (type(v) is not str or len(v) != 10
                                      or not v[:4].isdigit() or v[4] != "-"
                                      or v[7] != "-"):
                    raise ValueError("invalid declared date")
        elif any(v is not None and (type(v) is not int or not 1 <= v <= 64)
                 for v in (before, after)):
            raise ValueError("invalid hypothetical capacity")
    rows = report["rows"]
    if type(rows) is not list or not len(rows) <= 1200:
        raise ValueError("invalid delta rows")
    expected = {(kind, label) for kind, labels in COUNT_KINDS.items() for label in labels}
    encountered = set()
    previous = None
    for row in rows:
        if type(row) is not dict or set(row) != ROW_KEYS:
            raise ValueError("invalid aggregate row")
        kind, label = row["kind"], row["label"]
        if (type(kind) is not str or type(label) is not str
                or len(label) > 100 or (kind, label) in encountered):
            raise ValueError("invalid aggregate dimension")
        encountered.add((kind, label))
        if kind == "date_route":
            if " / " not in label:
                raise ValueError("invalid date/route dimension")
            day, route = label.split(" / ", 1)
            if route not in ROUTES or (day != "undated" and
                                      (len(day) != 10 or day[4] != "-" or day[7] != "-")):
                raise ValueError("invalid bounded date/route")
            if previous is not None and label <= previous:
                raise ValueError("unordered private date/route")
            previous = label
        elif (kind, label) not in expected:
            raise ValueError("unknown aggregate category")
        if (any(type(row[k]) is not int or not 0 <= row[k] <= 512
                for k in ("earlier", "later"))
                or type(row["change"]) is not int
                or row["change"] != row["later"]-row["earlier"]):
            raise ValueError("impossible aggregate change")
    if not expected.issubset(encountered):
        raise ValueError("missing required aggregate")
    # Basic independent accounting; cannot verify common case identity.
    def value(field):
        return next(r for r in rows if r["kind"] == "summary" and r["label"] == field)
    for column in ("earlier", "later"):
        if (value("human_work_rows")[column] !=
                value("open_work_rows")[column]+value("reviewed_rows")[column]
                or value("undated_open_rows")[column] > value("open_work_rows")[column]):
            raise ValueError("invalid source-free aggregate accounting")
    if (type(manifest) is not dict or set(manifest) != MANIFEST_KEYS
            or manifest["schema"] != "lightup.private_human_capacity_delta_pack.v1"
            or manifest["comparison_status"] != report["comparison_status"]
            or any(manifest[key] is not False for key in AUTH)):
        raise ValueError("invalid manifest")
    for name in ("delta.json", "delta.csv", "delta.html"):
        if manifest[name.replace(".", "_")+"_sha256"] != sha256(contents[name]).hexdigest():
            raise ValueError("altered aggregate member")
    if (contents["delta.json"] != _canonical(report)
            or contents["delta.csv"] != _csv(report)
            or contents["delta.html"] != _html(report)
            or not contents["READ-ME.txt"].startswith(
                b"LIGHTUP PRIVATE HUMAN CAPACITY DELTA / NO AUTHORITY\n")):
        raise ValueError("noncanonical private aggregate package")
    return report["comparison_status"], len(rows)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--earlier", help="PRIVATE original capacity ZIP A (manual order)")
    parser.add_argument("--later", help="PRIVATE original capacity ZIP B (manual order)")
    parser.add_argument("--output", help="New PRIVATE aggregate delta ZIP (exclusive)")
    parser.add_argument("--preview-only", action="store_true",
                        help="Return counts without writing")
    parser.add_argument("--inspect", help="Read-only admission of existing aggregate delta ZIP")
    args = parser.parse_args(argv)
    try:
        if args.inspect:
            if args.earlier or args.later or args.output or args.preview_only:
                raise ValueError("inspect mode is independent")
            status, count = _inspect_delta(_private_snapshot(args.inspect))
            print("PRIVATE_HUMAN_DELTA_INTACT — "+status+"; dimensions="+str(count)+
                  "; UNSIGNED; NOT AUTHORIZED")
            return 2 if status == "REVIEW_ONLY" else 3
        if not args.earlier or not args.later:
            raise ValueError("two explicitly selected original capacity ZIPs required")
        first = _private_snapshot(args.earlier)
        second = _private_snapshot(args.later)
        if sha256(first).digest() == sha256(second).digest():
            raise ValueError("identical source snapshots do not form a distinct comparison")
        report = _compare(_original_capacity_bytes(first), _original_capacity_bytes(second))
        if args.preview_only:
            if args.output:
                raise ValueError("preview must not write an output")
            print("PRIVATE_HUMAN_DELTA_PREVIEW — "+report["comparison_status"]+
                  "; dimensions="+str(len(report["rows"]))+
                  "; SAME_REFERENCE="+str(report["same_reference_date"])+
                  "; SAME_CAPACITY="+str(report["same_hypothetical_capacity"])+
                  "; SOURCES/CHRONOLOGY_UNVERIFIED; NOT AUTHORIZED")
            return 2 if report["comparison_status"] == "REVIEW_ONLY" else 3
        if not args.output:
            raise ValueError("output path required")
        _write_exclusive(args.output, _render(report))
        print("PRIVATE_HUMAN_DELTA_WRITTEN — "+report["comparison_status"]+
              "; UNSIGNED; NOT AUTHORIZED")
        return 2 if report["comparison_status"] == "REVIEW_ONLY" else 3
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError, RuntimeError,
            EOFError, NotImplementedError, BadZipFile, LargeZipFile):
        print("PRIVATE_HUMAN_DELTA_HOLD")
        return 3


def _original_capacity_bytes(raw: bytes) -> dict:
    inspect(raw)  # Re-admit precisely the already opened source bytes.
    with ZipFile(BytesIO(raw)) as archive:
        return _json(archive.read("capacity.json"))


if __name__ == "__main__":
    raise SystemExit(main())
