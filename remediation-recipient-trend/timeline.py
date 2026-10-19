#!/usr/bin/env python3
"""Recipient-only OFFLINE local HUMAN workload history from 2–12 full cockpits.

Works only on the existing source-free owner-private operating cockpit handoff,
never original customer packets, evidence, identifiers or authorization.
Ordinal order is operator-selected, NOT authenticated historical time.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

import trend

board = trend.board
review = trend.review
workspace = trend.workspace
triage = trend.triage
verify = trend.verify
read_cockpit = trend.read_cockpit

KIND = "lightup.private_human_recipient_workload_series"
WARNING = (
    "PRIVATE unsigned HUMAN aggregate work series only. Selected order is NOT "
    "authenticated chronology and source/client cohorts or individual cases "
    "CANNOT be matched using these handoffs. No increase/decrease in HUMAN "
    "counts proves a fix, risk reduction, retest, identity, consent or authority."
)
ORDERING = "operator_selected_ordinal_not_authenticated_time"
COHORT = "UNKNOWN_NOT_MATCHED"
MIN_SNAPSHOTS = 2
MAX_SNAPSHOTS = 12


def compose(docs: list[dict]) -> dict:
    review.require(type(docs) is list and
                   MIN_SNAPSHOTS <= len(docs) <= MAX_SNAPSHOTS,
                   "Expected 2 to 12 complete source-free private cockpits")
    summary = [trend.aggregate(item) for item in docs]
    rows = [{"ordinal": idx, "counts": record}
            for idx, record in enumerate(summary, 1)]
    transitions = [{
        "from_ordinal": idx,
        "to_ordinal": idx + 1,
        "delta_right_minus_left": trend.difference(summary[idx - 1], summary[idx])
    } for idx in range(1, len(summary))]
    return {
        "kind": KIND, "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "ordering": ORDERING,
        "cohort_identity": COHORT,
        "snapshots": rows,
        "adjacent_user_order_deltas": transitions,
    }


def safe_count(number: int) -> str:
    return str(number)


def render(data: dict) -> bytes:
    rows = data["snapshots"]
    changes = data["adjacent_user_order_deltas"]
    latest = rows[-1]["counts"]
    total = latest["questions"]
    cards = []
    for row in rows:
        counts = row["counts"]
        idx = row["ordinal"]
        maxval = max(1, counts["questions"])
        cards.append(
            "<tr><th scope='row'>Selected packet " + str(idx) + "</th>" +
            "<td>" + str(counts["slots"]) + "</td>" +
            "<td>" + str(counts["questions"]) + "</td>" +
            "<td>" + str(counts["pending"]) + "</td>" +
            "<td><progress aria-label='Local HUMAN pending workload, packet " +
            str(idx) + "' value='" + str(counts["pending"]) +
            "' max='" + str(maxval) + "'></progress></td></tr>"
        )
    change_rows = []
    for change in changes:
        delta = change["delta_right_minus_left"]
        change_rows.append(
            "<tr><th scope='row'>" + str(change["from_ordinal"]) + " → " +
            str(change["to_ordinal"]) + "</th><td>" +
            ("%+d" % delta["questions"]) + "</td><td>" +
            ("%+d" % delta["pending"]) + "</td><td>" +
            ("%+d" % delta["stages"]["answered_human"]) + "</td><td>" +
            ("%+d" % delta["human_attention_groups"]) + "</td></tr>"
        )
    reason_list = []
    for reason, count in sorted(latest["reasons"].items(),
                                key=lambda item: (-item[1], item[0])):
        if not count:
            continue
        review.require(reason in board.ADVICE, "Unknown native original HUMAN reason")
        reason_list.append("<li><strong>" + str(count) + " local occurrence(s): " +
                           board.safe(reason) + "</strong>. " +
                           board.safe(board.ADVICE[reason]) + "</li>")
    if not reason_list:
        reason_list.append("<li>No local pending HUMAN reasons were included in "
                           "the last handoff; no security conclusion follows.</li>")
    body = (
        "<section><h2>" + str(len(rows)) + " owner-selected offline handoffs</h2>"
        "<p>Each packet was independently admitted using the existing native "
        "source-free receiver before local counts were compared. "
        "Different packets MAY represent different client cohorts and repeat "
        "the same underlying cases. Counts are by source slot, not unique cases. "
        "The selected slot order is not independently authenticated time.</p>"
        "<table><thead><tr><th>Packet ordinal</th><th>Source slots</th>"
        "<th>HUMAN questions</th><th>Pending</th>"
        "<th>Relative pending share</th></tr></thead><tbody>" +
        "".join(cards) + "</tbody></table></section>"
        "<section><h2>Adjacent ordinal changes — arithmetic only</h2>"
        "<p>No original-case joins or verified retests. A decrease may "
        "indicate a different client population rather than progress.</p>"
        "<table><thead><tr><th>Selected pair</th><th>Questions Δ</th>"
        "<th>Pending Δ</th><th>Locally answered Δ</th>"
        "<th>Attention group Δ</th></tr></thead><tbody>" +
        "".join(change_rows) + "</tbody></table></section>"
        "<section><h2>Latest selected packet — original-owner HUMAN questions</h2>"
        "<p>" + str(latest["pending"]) + " locally pending out of " +
        str(total) + " HUMAN questions. Reasons may overlap and "
        "must be followed up ONLY through the trusted original private owner.</p>"
        "<ul>" + "".join(reason_list) + "</ul></section>" +
        full_stage_reason_matrix(data) +
        "<section><h2>Separate authentic sources required for real progress</h2>"
        "<ol><li>Ask the source owner whether each packet represents the same "
        "original client/cohort and unchanged case membership.</li>"
        "<li>Check original timestamps and custody independently; these "
        "source-free packets do not authenticate chronological order.</li>"
        "<li>Separately review original findings, evidence and authorized "
        "retesting. This report never verifies remediation.</li></ol></section>"
    )
    return board.shell(body, "LightUp PRIVATE HUMAN Multi-Packet Workload")


def full_stage_reason_matrix(data: dict) -> str:
    """Readable all-packet HUMAN-only stage/reason grid, no joined cases."""
    packets = data["snapshots"]
    headers = "".join("<th scope='col'>Packet " + str(row["ordinal"]) +
                      "</th>" for row in packets)
    def section(kind: str, names: tuple[str, ...]) -> str:
        lines = []
        for name in names:
            cell = "".join("<td>" + str(row["counts"][kind][name]) + "</td>"
                           for row in packets)
            lines.append("<tr><th scope='row'>" + board.safe(name) +
                         "</th>" + cell + "</tr>")
        return ("<table><thead><tr><th>HUMAN " + board.safe(kind) +
                "</th>" + headers + "</tr></thead><tbody>" +
                "".join(lines) + "</tbody></table>")
    return ("<section><h2>All selected packets: local HUMAN stages</h2>"
            "<p>Slots may represent different source/client populations. "
            "Each cell is a local category count only, not the same underlying cases.</p>"
            "<div style='overflow-x:auto'>" +
            section("stages", tuple(sorted(triage.STAGES))) + "</div></section>"
            "<section><h2>All selected packets: pending HUMAN reason occurrences</h2>"
            "<p>A single original HUMAN question can contain multiple reasons.</p>"
            "<div style='overflow-x:auto'>" +
            section("reasons", tuple(sorted(triage.REASONS))) + "</div></section>")


def csv_view(data: dict) -> bytes:
    import csv
    import io
    stream = io.StringIO(newline="")
    out = csv.writer(stream, lineterminator="\n")
    out.writerow(("ordinal", "source_slots", "human_questions", "pending",
                  "answered_human", "reuse_attention_groups"))
    for row in data["snapshots"]:
        c = row["counts"]
        out.writerow((row["ordinal"], c["slots"], c["questions"],
                      c["pending"], c["stages"]["answered_human"],
                      c["human_attention_groups"]))
    return stream.getvalue().encode("utf-8")


def next_actions(data: dict) -> bytes:
    last = data["snapshots"][-1]["counts"]
    recent = data["adjacent_user_order_deltas"][-1]["delta_right_minus_left"]
    lines = [
        "# PRIVATE HUMAN multi-handoff discussion only",
        "",
        WARNING,
        "",
        "## Snapshot arithmetic",
        "",
        "Received " + str(len(data["snapshots"])) +
        " selected complete packets. Their original sources or client "
        "populations are NOT proven identical.",
        "Last selected packet: " + str(last["slots"]) +
        " source slots; " + str(last["pending"]) + " local pending HUMAN questions.",
        "Latest adjacent pending arithmetic change: " +
        ("%+d" % recent["pending"]) + ".",
        "",
        "## Human follow-up (not authorized security actions)",
        "",
    ]
    ranked = sorted(((key, total) for key, total in last["reasons"].items()
                     if total > 0), key=lambda pair: (-pair[1], pair[0]))
    if not ranked:
        lines.append("- No human reasons reported in the selected last packet; "
                     "this is not evidence of security remediation.")
    for reason, total in ranked:
        review.require(reason in board.ADVICE, "Unrecognized native HUMAN follow-up")
        lines.append("- " + str(total) + " local " + reason + ": " +
                     board.ADVICE[reason])
    lines += [
        "",
        "Ask the original source owner to reconcile source population and "
        "retention of the ORIGINAL PRIVATE evidence before interpreting changes.",
        "Request a separate authorized retest and actual authenticated approvals "
        "through existing processes if remediation is being considered.",
        "Never treat this offline summary as consent, proof of fix, or trusted "
        "source identity.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def artifacts(data: dict) -> dict[str, bytes]:
    return {
        "index.html": render(data),
        "series.json": workspace.pretty(data),
        "series.csv": csv_view(data),
        "human-followup.md": next_actions(data),
    }


def publish(sources: list[Path], output: Path) -> dict:
    review.require(MIN_SNAPSHOTS <= len(sources) <= MAX_SNAPSHOTS and
                   output.is_absolute() and len(set(sources)) == len(sources) and
                   all(output != p and output.parent != p and
                       output not in p.parents and p not in output.parents
                       for p in sources),
                   "Output must be separate and original packet folders distinct")
    triage.private_parent(output)
    docs = []
    inventory = []
    seen_packets = set()
    for folder in sources:
        doc, manifest, raw = trend.admit_received(folder)
        token = hashlib.sha256(manifest + b"\x00" + raw).digest()
        review.require(token not in seen_packets,
                       "Duplicate exact private recipient packet, not a new revision")
        seen_packets.add(token)
        docs.append(doc)
        inventory.append((folder, manifest, raw))
    result = compose(docs)
    payloads = artifacts(result)
    manifest = {
        "kind": KIND + ".local_receipt",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_COUNTS_ONLY",
        **{flag: False for flag in review.FLAGS},
        "warning": WARNING,
        "files": {name: {
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        } for name, raw in sorted(payloads.items())},
    }
    # No report is visible until every original complete native source-free
    # packet has been re-admitted, not just individual unsigned JSON bytes.
    for folder, prior_manifest, prior_json in inventory:
        _, latest_manifest, latest_json = trend.admit_received(folder)
        review.require(prior_manifest == latest_manifest and
                       prior_json == latest_json,
                       "Original private receiver packet changed during review")
    workspace.publish_bundle(output, payloads, workspace.pretty(manifest))
    return {"snapshot_count": len(docs),
            "last_pending": result["snapshots"][-1]["counts"]["pending"],
            "report_files": len(payloads) + 1}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an offline PRIVATE 2–12-packet HUMAN workload series "
                    "from complete canonical source-free owner handoffs")
    parser.add_argument("--cockpit", type=Path, action="append", required=True,
                        help="Complete PRIVATE native source-free cockpit (repeat 2–12)")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW 0700 private report directory")
    args = parser.parse_args()
    try:
        result = publish(args.cockpit, args.output_dir)
        print("REVIEW_ONLY: private source-free HUMAN workload series created; " +
              str(result["snapshot_count"]) + " chosen packets, " +
              str(result["last_pending"]) +
              " local pending HUMAN questions in the final packet.")
        print("Packet order/cohort authenticity, fix, retest and consent UNKNOWN.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: complete private source-free packets cannot be compared.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
