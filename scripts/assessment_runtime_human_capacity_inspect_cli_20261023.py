"""Offline read-only reopen of a PRIVATE LightUp HUMAN capacity ZIP.

Verifies the fixed local bundle, its unsigned byte checks and exact aggregate
row accounting. It cannot authenticate inputs, grant consent or release work.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from hashlib import sha256
from io import BytesIO
import json
import sys
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZIP_DEFLATED

from assessment_runtime_human_capacity_cli_20261023 import (
    AUTH, MAX_ARCHIVE, PRIORITIES, ROUTES, STAGES, _csv, _summary_csv, _html,
    _private_snapshot,
)
from assessment_runtime_verify_pack_cli_20261018 import _json

MEMBERS = {
    "READ-ME.txt": 4_096,
    "manifest.json": 8_192,
    "capacity.json": 250_000,
    "capacity.csv": 250_000,
    "capacity-summary.csv": 100_000,
    "capacity.html": 250_000,
}
BOARD_KEYS = frozenset((
    "schema", "purpose", "comparison_status", "packet_count",
    "human_work_rows", "open_work_rows", "reviewed_rows",
    "undated_open_rows", "reference_date", "overdue_open_rows",
    "declared_capacity_per_route_date", "capacity_note", "human_stages",
    "routing_groups", "priorities", "route_date_loads", "rows", *AUTH,
))
ROW_KEYS = frozenset((
    "packet", "case", "priority", "source_status", "routing_group",
    "human_stage", "follow_up_date", "regression_count",
))
MANIFEST_KEYS = frozenset((
    "format", "comparison_status", "human_work_rows",
    "capacity_json_sha256", "capacity_csv_sha256",
    "capacity_summary_csv_sha256", "capacity_html_sha256",
    *AUTH,
))


def _day(value):
    return (type(value) is str and len(value) == 10
            and date.fromisoformat(value).isoformat() == value)


def _inspect_board(board):
    if type(board) is not dict or set(board) != BOARD_KEYS:
        raise ValueError("unknown board schema")
    if (board["schema"] != "lightup.private_human_capacity.v1"
            or board["purpose"] != "OFFLINE_HUMAN_PLANNING_ONLY"
            or board["comparison_status"] not in ("HOLD", "REVIEW_ONLY")
            or type(board["packet_count"]) is not int
            or not 2 <= board["packet_count"] <= 8
            or any(board[key] is not False for key in AUTH)):
        raise ValueError("invalid private board")
    cap = board["declared_capacity_per_route_date"]
    reference = board["reference_date"]
    if cap is not None and (type(cap) is not int or not 1 <= cap <= 64):
        raise ValueError("invalid hypothetical capacity")
    if reference is not None and not _day(reference):
        raise ValueError("invalid explicit reference date")
    rows = board["rows"]
    if type(rows) is not list or not 2 <= len(rows) <= 512:
        raise ValueError("invalid row count")
    encountered = set()
    packet_positions = defaultdict(list)
    for row in rows:
        if type(row) is not dict or set(row) != ROW_KEYS:
            raise ValueError("invalid human row")
        packet, case = row["packet"], row["case"]
        if (type(packet) is not str or not packet.startswith("Packet ")
                or type(case) is not str or not case.startswith("Case ")):
            raise ValueError("invalid anonymized ordinal")
        try:
            number = int(packet.removeprefix("Packet "))
            ordinal = int(case.removeprefix("Case "))
        except ValueError:
            raise ValueError("non-numeric ordinal") from None
        if (packet != "Packet %02d" % number or case != "Case %02d" % ordinal
                or not 1 <= number <= board["packet_count"]
                or not 1 <= ordinal <= 64
                or row["priority"] not in PRIORITIES
                or row["source_status"] not in ("HOLD", "REVIEW_ONLY")
                or row["routing_group"] not in ROUTES
                or row["human_stage"] not in STAGES
                or type(row["regression_count"]) is not int
                or not 0 <= row["regression_count"] <= 16):
            raise ValueError("invalid source-reported human entry")
        due = row["follow_up_date"]
        if due is not None and not _day(due):
            raise ValueError("invalid date")
        if (number, ordinal) in encountered:
            raise ValueError("duplicate source ordinal")
        encountered.add((number, ordinal))
        packet_positions[number].append(ordinal)
    if sorted(packet_positions) != list(range(1, board["packet_count"] + 1)):
        raise ValueError("missing original packet")
    if any(ordinals != list(range(1, len(ordinals) + 1))
           for ordinals in packet_positions.values()):
        raise ValueError("modified original ordinal sequence")
    if ([r["packet"] for r in rows] !=
            sorted([r["packet"] for r in rows])):
        raise ValueError("packet order changed")
    if board["comparison_status"] != (
            "HOLD" if any(r["source_status"] == "HOLD" for r in rows)
            else "REVIEW_ONLY"):
        raise ValueError("comparison status mismatch")
    open_rows = [row for row in rows if row["human_stage"] != "reviewed"]
    expected = {
        "human_work_rows": len(rows),
        "open_work_rows": len(open_rows),
        "reviewed_rows": len(rows) - len(open_rows),
        "undated_open_rows": sum(r["follow_up_date"] is None for r in open_rows),
    }
    for key, value in expected.items():
        if type(board[key]) is not int or board[key] != value:
            raise ValueError("human accounting mismatch")
    for field, names, key in (
            ("human_stage", STAGES, "human_stages"),
            ("routing_group", ROUTES, "routing_groups"),
            ("priority", PRIORITIES, "priorities")):
        supplied = board[key]
        if type(supplied) is not dict or set(supplied) != set(names):
            raise ValueError("unknown aggregate category")
        counts = Counter(r[field] for r in rows)
        for name in names:
            if type(supplied[name]) is not int or supplied[name] != counts[name]:
                raise ValueError("aggregate category mismatch")
    overdue = (sum(1 for row in open_rows
                   if row["follow_up_date"] and row["follow_up_date"] < reference)
               if reference else None)
    if board["overdue_open_rows"] != overdue:
        raise ValueError("overdue estimate mismatch")
    groups = defaultdict(int)
    for row in open_rows:
        groups[(row["follow_up_date"] or "undated", row["routing_group"])] += 1
    expected_loads = [
        {
            "follow_up_date": day,
            "routing_group": route,
            "open_items": count,
            "declared_capacity": cap,
            "above_declared_capacity": max(0, count - cap) if cap is not None else None,
        }
        for (day, route), count in sorted(groups.items())
    ]
    if board["route_date_loads"] != expected_loads:
        raise ValueError("source planning load mismatch")
    if board["capacity_note"] != (
            "User-declared hypothetical count; not staffing or assignments."):
        raise ValueError("missing planning disclaimer")


def inspect(raw: bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ARCHIVE:
        raise ValueError("invalid archive")
    with ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) != len(MEMBERS) or set(archive.namelist()) != set(MEMBERS):
            raise ValueError("unknown private artifact layout")
        contents = {}
        for entry in entries:
            if (entry.is_dir() or entry.flag_bits & 1
                    or entry.compress_type != ZIP_DEFLATED
                    or not 0 < entry.file_size <= MEMBERS[entry.filename]):
                raise ValueError("invalid private member")
            contents[entry.filename] = archive.read(entry)
            if len(contents[entry.filename]) != entry.file_size:
                raise ValueError("incomplete member")
    board = _json(contents["capacity.json"])
    manifest = _json(contents["manifest.json"])
    _inspect_board(board)
    if type(manifest) is not dict or set(manifest) != MANIFEST_KEYS:
        raise ValueError("invalid manifest")
    if (manifest["format"] != "lightup.private_human_capacity_pack.v2"
            or manifest["comparison_status"] != board["comparison_status"]
            or manifest["human_work_rows"] != board["human_work_rows"]
            or any(manifest[key] is not False for key in AUTH)):
        raise ValueError("status/authority mismatch")
    for key, name in (("capacity_json_sha256", "capacity.json"),
                      ("capacity_csv_sha256", "capacity.csv"),
                      ("capacity_summary_csv_sha256", "capacity-summary.csv"),
                      ("capacity_html_sha256", "capacity.html")):
        if manifest[key] != sha256(contents[name]).hexdigest():
            raise ValueError("modified output member")
    canonical = json.dumps(board, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("ascii")
    if (contents["capacity.json"] != canonical
            or contents["capacity.csv"] != _csv(board)
            or contents["capacity-summary.csv"] != _summary_csv(board)
            or contents["capacity.html"] != _html(board)
            or not contents["READ-ME.txt"].startswith(
                b"LIGHTUP PRIVATE HUMAN CAPACITY / NO AUTHORITY\n")):
        raise ValueError("noncanonical offline export")
    return board["comparison_status"], board["packet_count"], board["human_work_rows"]


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("PRIVATE_HUMAN_CAPACITY_REOPEN_HOLD")
        return 3
    try:
        status, packets, rows = inspect(_private_snapshot(args[0]))
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError, RuntimeError,
            EOFError, NotImplementedError, BadZipFile, LargeZipFile):
        print("PRIVATE_HUMAN_CAPACITY_REOPEN_HOLD")
        return 3
    print("PRIVATE_HUMAN_CAPACITY_INTACT — " + status
          + "; packets=" + str(packets) + "; rows=" + str(rows)
          + "; UNSIGNED; NOT AUTHORIZED")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())