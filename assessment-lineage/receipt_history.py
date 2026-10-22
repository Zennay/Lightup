#!/usr/bin/env python3
"""Compare 2–12 PRIVATE source receipts as a bounded human-selected history.

This reads only the original canonical receipts. It never reads the source
catalogs or reports named inside them, runs a comparator, or authorizes work.
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import stat
import sys
import unicodedata
from pathlib import Path

from compare_receipts import decode_receipt
from private_workroom import FLAGS, open_parent_nofollow, read_private

MIN_RECEIPTS = 2
MAX_RECEIPTS = 12
MAX_INPUT = 8_192
MAX_SELECTION = 32_768
MAX_JSON = 65_536
MAX_HTML = 65_536
MAX_CSV = 262_144
OUTPUT_JSON = "lightup-private-lineage-receipt-history.json"
OUTPUT_HTML = "lightup-private-lineage-receipt-history.html"
OUTPUT_CSV = "lightup-private-lineage-receipt-history.csv"


def hold() -> None:
    raise ValueError("HOLD: invalid, changed or ambiguous PRIVATE receipt history")


def stable_receipts(paths: list[Path]) -> tuple[list[bytes], list[dict]]:
    realpaths = [os.path.realpath(path) for path in paths]
    if len(set(realpaths)) != len(realpaths):
        hold()
    raw_values = [read_private(path, MAX_INPUT) for path in paths]
    receipts = [decode_receipt(raw) for raw in raw_values]
    # Re-open the same original bytes before any result is rendered or published.
    if any(read_private(path, MAX_INPUT) != raw for path, raw in zip(paths, raw_values)):
        hold()
    return raw_values, receipts


def read_receipt_selection(path: Path) -> tuple[bytes, list[Path]]:
    """Read a private, LF-delimited, manually ordered list of original receipt paths."""
    raw = read_private(path, MAX_SELECTION)
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        hold()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        hold()
    names = text.split("\n")[:-1]
    if (not MIN_RECEIPTS <= len(names) <= MAX_RECEIPTS
            or len(set(names)) != len(names)):
        hold()
    paths = []
    for name in names:
        if (not name.startswith(os.sep) or os.path.normpath(name) != name
                or not 1 <= len(name) <= 2_048 or any(
                    unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp")
                    for char in name
                )):
            hold()
        paths.append(Path(name))
    if len({os.path.realpath(path) for path in paths}) != len(paths):
        hold()
    return raw, paths


def confirm_original_inputs(
    paths: list[Path], expected: list[bytes],
    selection_path: Path | None = None, selection_raw: bytes | None = None,
) -> None:
    if any(read_private(path, MAX_INPUT) != raw for path, raw in zip(paths, expected)):
        hold()
    if selection_path is not None:
        if selection_raw is None:
            hold()
        current_raw, current_paths = read_receipt_selection(selection_path)
        if current_raw != selection_raw or current_paths != paths:
            hold()


def compose_history(receipts: list[dict]) -> dict:
    if not MIN_RECEIPTS <= len(receipts) <= MAX_RECEIPTS:
        hold()

    source_set = set()
    for receipt in receipts:
        source_set.update(receipt["reports_sha256"])
    ordered_sources = sorted(source_set)
    # These short labels are private, packet-local aliases. They are not
    # anonymization and must never be treated as source identities.
    labels = {digest: f"Source {index:02d}" for index, digest in enumerate(ordered_sources, 1)}

    snapshots = []
    for index, receipt in enumerate(receipts):
        previous = receipts[index - 1] if index else None
        current = receipt["reports_sha256"]
        previous_sources = previous["reports_sha256"] if previous else []
        current_unique = set(current)
        previous_unique = set(previous_sources)
        seen_before_current = set().union(*(set(item["reports_sha256"]) for item in receipts[:index]))
        seen_before_previous = set().union(*(set(item["reports_sha256"]) for item in receipts[:index - 1]))
        first_seen = current_unique - seen_before_current
        reappeared = ((current_unique - previous_unique) & seen_before_previous) if previous else set()
        duplicates = len(current_unique) != len(current)
        snapshots.append({
            "manual_plan_number": index + 1,
            "report_count": receipt["report_count"],
            "catalog_bytes_changed_from_previous": (
                receipt["catalog_sha256"] != previous["catalog_sha256"] if previous else None
            ),
            "human_draft_bytes_changed_from_previous": (
                receipt["human_draft_sha256"] != previous["human_draft_sha256"] if previous else None
            ),
            "workroom_bytes_changed_from_previous": (
                receipt["workroom_sha256"] != previous["workroom_sha256"] if previous else None
            ),
            "report_slot_order_changed_from_previous": (
                current != previous_sources if previous else None
            ),
            "new_unique_sources_from_previous": (
                len(current_unique - previous_unique) if previous else None
            ),
            "first_seen_unique_sources": len(first_seen),
            "reappeared_unique_sources_from_previous": len(reappeared),
            "absent_unique_sources_from_previous": (
                len(previous_unique - current_unique) if previous else None
            ),
            "duplicate_source_fingerprints": duplicates,
            "human_selected_order_not_proven_chronology": True,
            **{flag: False for flag in FLAGS},
            "origin_verified": False,
            "operator_identity_verified": False,
            "client_consent_verified": False,
            "human_go": False,
        })

    intervals = []
    for index in range(1, len(receipts)):
        before = receipts[index - 1]
        after = receipts[index]
        old = before["reports_sha256"]
        new = after["reports_sha256"]
        old_unique_set, new_unique_set = set(old), set(new)
        seen_before_current = set().union(*(set(item["reports_sha256"]) for item in receipts[:index]))
        seen_before_previous = set().union(*(set(item["reports_sha256"]) for item in receipts[:index - 1]))
        first_seen = new_unique_set - seen_before_current
        reappeared = (new_unique_set - old_unique_set) & seen_before_previous
        old_unique = len(old_unique_set) == len(old)
        new_unique = len(new_unique_set) == len(new)
        unique = old_unique and new_unique
        old_positions = {digest: slot for slot, digest in enumerate(old, 1)}
        new_positions = {digest: slot for slot, digest in enumerate(new, 1)}
        old_only = [slot for slot, digest in enumerate(old, 1) if digest not in new_positions]
        new_only = [slot for slot, digest in enumerate(new, 1) if digest not in old_positions]
        moved = []
        if unique:
            moved = [
                {"source_label": labels[digest], "from_slot": slot, "to_slot": new_positions[digest]}
                for slot, digest in enumerate(old, 1)
                if digest in new_positions and new_positions[digest] != slot
            ]
        intervals.append({
            "from_manual_plan": index,
            "to_manual_plan": index + 1,
            "catalog_bytes_changed": before["catalog_sha256"] != after["catalog_sha256"],
            "human_draft_bytes_changed": before["human_draft_sha256"] != after["human_draft_sha256"],
            "workroom_bytes_changed": before["workroom_sha256"] != after["workroom_sha256"],
            "report_slot_order_changed": old != new,
            "before_report_slots": len(old),
            "after_report_slots": len(new),
            "new_unique_sources": len(new_unique_set - old_unique_set),
            "first_seen_unique_sources": len(first_seen),
            "reappeared_unique_sources": len(reappeared),
            "first_seen_source_labels": [labels[digest] for digest in sorted(first_seen)],
            "reappeared_source_labels": [labels[digest] for digest in sorted(reappeared)],
            "absent_unique_sources": len(old_unique_set - new_unique_set),
            "old_only_slots": old_only,
            "new_only_slots": new_only,
            "duplicate_source_fingerprints": not unique,
            "uniquely_moved_sources": moved,
            "manual_order_not_authenticated_chronology": True,
            **{flag: False for flag in FLAGS},
            "origin_verified": False,
            "operator_identity_verified": False,
            "client_consent_verified": False,
            "human_go": False,
        })

    source_rows = []
    for digest in ordered_sources:
        positions_by_snapshot = []
        for receipt in receipts:
            positions = [
                slot for slot, value in enumerate(receipt["reports_sha256"], 1)
                if value == digest
            ]
            positions_by_snapshot.append(positions)
        present = [index + 1 for index, positions in enumerate(positions_by_snapshot) if positions]
        reappeared_slots = [
            right for left, right in zip(present, present[1:]) if right - left > 1
        ]
        longest_streak = current_streak = 0
        for positions in positions_by_snapshot:
            if positions:
                current_streak += 1
                longest_streak = max(longest_streak, current_streak)
            else:
                current_streak = 0
        source_rows.append({
            "source_label": labels[digest],
            "manual_snapshots_present": present,
            "slots_by_manual_snapshot": positions_by_snapshot,
            "reappeared_after_gap_in_snapshots": reappeared_slots,
            "duplicate_within_snapshots": [
                index + 1 for index, positions in enumerate(positions_by_snapshot)
                if len(positions) > 1
            ],
            "first_selected_snapshot": present[0],
            "last_selected_snapshot": present[-1],
            "longest_consecutive_presence_streak": longest_streak,
            "longest_absence_gap_between_appearances": max(
                (right - left - 1 for left, right in zip(present, present[1:])), default=0
            ),
            "gaps_between_selected_snapshots": len(reappeared_slots),
        })

    return {
        "schema": "lightup.private_lineage_receipt_history.v1",
        "status": "PRIVATE_HUMAN_REVIEW_ONLY",
        "manual_snapshot_count": len(receipts),
        "unique_receipt_source_fingerprints": len(ordered_sources),
        "snapshots": snapshots,
        "adjacent_intervals": intervals,
        "source_presence_history": source_rows,
        "source_fingerprints_omitted": True,
        "source_paths_omitted": True,
        "source_content_omitted": True,
        "human_selected_order_not_proven_chronology": True,
        "missing_source_not_remediated": True,
        **{flag: False for flag in FLAGS},
        "origin_verified": False,
        "operator_identity_verified": False,
        "client_consent_verified": False,
        "human_go": False,
    }


def json_bytes(history: dict) -> bytes:
    raw = (json.dumps(history, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_JSON:
        hold()
    return raw


def csv_bytes(history: dict) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow((
        "source_label", "manual_snapshot_number", "present", "selected_slots",
        "first_seen_here", "reappeared_after_gap", "consecutive_presence_streak_ending_here",
        "longest_consecutive_presence_streak", "longest_absence_gap_between_appearances",
        "duplicate_within_snapshot", "first_selected_snapshot", "last_selected_snapshot",
        "gaps_between_selected_snapshots",
    ))
    for source in history["source_presence_history"]:
        present_slots = set(source["manual_snapshots_present"])
        reappeared_slots = set(source["reappeared_after_gap_in_snapshots"])
        for snapshot, slots in enumerate(source["slots_by_manual_snapshot"], 1):
            streak = 0
            cursor = snapshot
            while cursor in present_slots:
                streak += 1
                cursor -= 1
            writer.writerow((
                source["source_label"], snapshot, "true" if slots else "false",
                ";".join(str(slot) for slot in slots) if slots else "",
                "true" if snapshot == source["first_selected_snapshot"] else "false",
                "true" if snapshot in reappeared_slots else "false",
                streak, source["longest_consecutive_presence_streak"],
                source["longest_absence_gap_between_appearances"],
                "true" if len(slots) > 1 else "false",
                source["first_selected_snapshot"], source["last_selected_snapshot"],
                source["gaps_between_selected_snapshots"],
            ))
    raw = output.getvalue().encode("utf-8")
    if len(raw) > MAX_CSV:
        hold()
    return raw


def render_html(history: dict) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)

    def cell(value: object) -> str:
        if value is None:
            return "—"
        if type(value) is bool:
            return "Yes" if value else "No"
        if isinstance(value, list):
            return ", ".join(str(v) for v in value) if value else "None"
        return str(value)

    snapshot_keys = (
        ("manual_plan_number", "Manual snapshot"),
        ("report_count", "Selected report slots"),
        ("catalog_bytes_changed_from_previous", "Catalog changed"),
        ("human_draft_bytes_changed_from_previous", "HUMAN draft changed"),
        ("workroom_bytes_changed_from_previous", "Workroom changed"),
        ("report_slot_order_changed_from_previous", "Report slots/order changed"),
        ("new_unique_sources_from_previous", "New or returning sources vs prior"),
        ("first_seen_unique_sources", "First seen in selected order"),
        ("reappeared_unique_sources_from_previous", "Reappeared after a gap"),
        ("absent_unique_sources_from_previous", "Absent source fingerprints"),
        ("duplicate_source_fingerprints", "Duplicate fingerprints"),
    )
    interval_keys = (
        ("from_manual_plan", "From"),
        ("to_manual_plan", "To"),
        ("catalog_bytes_changed", "Catalog changed"),
        ("human_draft_bytes_changed", "HUMAN draft changed"),
        ("workroom_bytes_changed", "Workroom changed"),
        ("report_slot_order_changed", "Slots/order changed"),
        ("new_unique_sources", "New or returning sources vs prior"),
        ("first_seen_unique_sources", "First-seen sources"),
        ("reappeared_unique_sources", "Reappeared after a gap"),
        ("first_seen_source_labels", "First-seen packet-local labels"),
        ("reappeared_source_labels", "Reappeared packet-local labels"),
        ("absent_unique_sources", "Absent source fingerprints"),
        ("old_only_slots", "Prior-only slots"),
        ("new_only_slots", "Later-only slots"),
        ("duplicate_source_fingerprints", "Movement ambiguous"),
        ("uniquely_moved_sources", "Unique source movements"),
    )
    source_keys = (
        ("source_label", "Packet-local source label"),
        ("manual_snapshots_present", "Snapshots present"),
        ("slots_by_manual_snapshot", "Selected slots per snapshot"),
        ("reappeared_after_gap_in_snapshots", "Reappeared after a gap"),
        ("duplicate_within_snapshots", "Duplicate slots within snapshot"),
        ("first_selected_snapshot", "First selected snapshot"),
        ("last_selected_snapshot", "Last selected snapshot"),
        ("longest_consecutive_presence_streak", "Longest consecutive presence streak"),
        ("longest_absence_gap_between_appearances", "Longest absence gap between appearances"),
        ("gaps_between_selected_snapshots", "Gaps"),
    )

    def table(headers: tuple, rows: list[dict], *, interval: bool = False) -> str:
        out = ["<div class='scroll'><table><thead><tr>"]
        out.extend("<th scope='col'>" + esc(label) + "</th>" for _, label in headers)
        out.append("</tr></thead><tbody>")
        for row in rows:
            out.append("<tr>")
            for key, _label in headers:
                value = row[key]
                if interval and key == "uniquely_moved_sources":
                    value = "; ".join(
                        f"{item['source_label']}: {item['from_slot']} → {item['to_slot']}"
                        for item in value
                    ) or "None"
                elif key == "slots_by_manual_snapshot":
                    value = " | ".join(
                        f"{index + 1}: {','.join(map(str, slots)) if slots else '—'}"
                        for index, slots in enumerate(value)
                    )
                out.append("<td>" + esc(cell(value)) + "</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        return "".join(out)

    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; "
        "object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>PRIVATE receipt history — REVIEW ONLY</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1500px;margin:2rem auto;padding:1rem;color:#203047}"
        ".hold{border-left:5px solid #98611c;background:#fff2d9;padding:1rem}.scroll{overflow-x:auto}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}th,td{border:1px solid #aab8c7;"
        "padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf3f8}"
        "@media print{body{margin:0;font-size:10px}.scroll{overflow:visible}tr{break-inside:avoid}}</style>"
        "</head><body><h1>PRIVATE source-receipt history</h1>"
        "<p class='hold'><strong>REVIEW_ONLY / HOLD.</strong> The snapshots are ordered by the operator, "
        "not authenticated timestamps. These unsigned receipt fingerprints establish only local byte "
        "equality, not original authorship, chronology, assessment validity, remediation, consent, "
        "authorization or release. Missing sources are not remediated or cleared. Keep this report private.</p>"
        "<p>Manual snapshots: <strong>" + esc(history["manual_snapshot_count"]) + "</strong>. "
        "Unique source fingerprints in this packet: <strong>" +
        esc(history["unique_receipt_source_fingerprints"]) + "</strong>. "
        "Full fingerprints, source paths, original content, case IDs and private notes are omitted. "
        "Packet-local labels are correlation aids, not anonymization.</p>"
        "<h2>Per-snapshot summary</h2>" + table(snapshot_keys, history["snapshots"]) +
        "<h2>Adjacent snapshot changes</h2>" + table(interval_keys, history["adjacent_intervals"], interval=True) +
        "<h2>Source presence across the selected snapshots</h2>" + table(source_keys, history["source_presence_history"]) +
        "<p>Catalog/HUMAN-draft/workroom changes are byte-difference indicators only. A report source "
        "missing from a later selected snapshot may be intentionally omitted or selected differently; "
        "no deletion, fix, revocation, or evidence status is inferred. Duplicate fingerprints make "
        "slot movement ambiguous. No scanner, network, comparator, target, grant, or external service "
        "is invoked. All authority and HUMAN GO flags remain false.</p></body></html>\n"
    ).encode("utf-8")
    if len(page) > MAX_HTML:
        hold()
    return page


def safe_output_dir(output_dir: Path, input_paths: list[Path]) -> tuple[int, set[str]]:
    out_real = os.path.realpath(output_dir)
    for path in input_paths:
        source_parent = os.path.realpath(path.parent)
        try:
            common = os.path.commonpath((out_real, source_parent))
        except ValueError:
            hold()
        # The output directory must be a separate sibling tree, never the
        # input folder, an ancestor of it, or nested inside it.
        if common in (out_real, source_parent):
            hold()
    fd, _ = open_parent_nofollow(output_dir / "history-placeholder")
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        hold()
    return fd, set(os.listdir(fd))


def main(argv: list[str]) -> int:
    cli = argparse.ArgumentParser(
        description="Offline PRIVATE 2–12 receipt history; no assessment or source access"
    )
    cli.add_argument("--output-dir", required=True, type=Path,
                     help="Existing owner-owned exact-mode-0700 directory outside all receipt directories")
    cli.add_argument("--verify-existing", action="store_true",
                     help="Reopen the exact existing three-file packet read-only")
    cli.add_argument("--receipts-file", type=Path,
                     help="Owner-private mode-0600 LF-delimited list of 2–12 canonical absolute receipt paths")
    cli.add_argument("receipts", nargs="*",
                     help="2–12 owner-private canonical receipt JSON files in manually selected order")
    args = cli.parse_args(argv)
    if bool(args.receipts_file) == bool(args.receipts):
        cli.error("supply either positional receipt paths or --receipts-file, not both")
    selection_path = args.receipts_file
    selection_raw = None
    if selection_path is not None:
        selection_raw, paths = read_receipt_selection(selection_path)
        if os.path.realpath(selection_path) in {os.path.realpath(path) for path in paths}:
            cli.error("receipt-selection file must be separate from the listed receipts")
    else:
        paths = [Path(value) for value in args.receipts]
        if not MIN_RECEIPTS <= len(paths) <= MAX_RECEIPTS:
            cli.error("two to twelve original PRIVATE receipt files are required")
    raw_receipts, receipts = stable_receipts(paths)
    history = compose_history(receipts)
    outputs = {
        OUTPUT_JSON: json_bytes(history),
        OUTPUT_HTML: render_html(history),
        OUTPUT_CSV: csv_bytes(history),
    }
    safety_inputs = paths + ([selection_path] if selection_path is not None else [])
    output_fd, existing = safe_output_dir(args.output_dir, safety_inputs)
    created: list[str] = []
    try:
        if args.verify_existing:
            if existing != set(outputs):
                hold()
            for name, expected in outputs.items():
                if read_private(args.output_dir / name, len(expected)) != expected:
                    hold()
            confirm_original_inputs(paths, raw_receipts, selection_path, selection_raw)
            print("PRIVATE receipt-history packet matches exact selected original receipts; REVIEW_ONLY.")
            return 0
        if existing:
            hold()
        confirm_original_inputs(paths, raw_receipts, selection_path, selection_raw)
        try:
            for name, content in outputs.items():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=output_fd)
                created.append(name)
                with os.fdopen(fd, "wb", closefd=True) as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(output_fd)
        except BaseException:
            for name in reversed(created):
                os.unlink(name, dir_fd=output_fd)
            os.fsync(output_fd)
            raise
    finally:
        os.close(output_fd)
    print("PRIVATE 2–12 snapshot history created (HTML/JSON/CSV); REVIEW_ONLY, not authorized.")
    print("Source fingerprints omitted; no scan, grant, consent or release.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        print("HOLD: invalid/changed PRIVATE receipts or unsafe output. No authority granted.",
              file=sys.stderr)
        raise SystemExit(2) from None
