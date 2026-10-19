#!/usr/bin/env python3
"""Compare TWO exact-source local HUMAN boards without claiming case progress."""
from __future__ import annotations
import argparse
import csv
import html
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-portfolio"))
import portfolio
import action_board

import return_to_studio

NOTICE = (
    "SELF-DECLARED LOCAL HUMAN ROUTING DIFFERENCES ONLY. Identical numeric "
    "ordinals do not identify original cases; local before/after is not "
    "authenticated chronology, client evidence, verified remediation, "
    "consent, scan authority, risk reduction, release or a retest result."
)


def compare(session_path: Path, earlier_board: Path, later_board: Path) -> dict:
    # Each private source independently admits through the unchanged original
    # entire session+board exact-ordinal and numeric packet schema, flags false.
    old = action_board.board_import(earlier_board, session_path)
    new = action_board.board_import(later_board, session_path)
    portfolio.require(len(old) == len(new) and 1 <= len(new) <= 12)
    changes = []
    for i, (a, b) in enumerate(zip(old, new), 1):
        portfolio.require(
            a["packet_ordinal_not_original_case"] ==
            b["packet_ordinal_not_original_case"] == i
            and a["source_type"] == b["source_type"]
            and a["anonymous_slot_appearances_not_unique"] ==
            b["anonymous_slot_appearances_not_unique"]
            and a["unverified_pending_human_questions"] ==
            b["unverified_pending_human_questions"]
        )
        if (a["local_followup_action_code"], a["local_planning_state_code"]) == (
            b["local_followup_action_code"], b["local_planning_state_code"]
        ):
            continue
        changes.append({
            "local_ordinal_not_original_case": i,
            "earlier_local_action": a["local_followup_action_code"],
            "later_local_action": b["local_followup_action_code"],
            "earlier_local_state": a["local_planning_state_code"],
            "later_local_state": b["local_planning_state_code"],
            "action_changed": a["local_followup_action_code"] !=
                              b["local_followup_action_code"],
            "state_changed": a["local_planning_state_code"] !=
                             b["local_planning_state_code"],
        })
    portfolio.require(bool(changes))  # No apparent difference is not evidence.
    return {
        "kind": "lightup.private_human_local_routing_numeric_ordinal_diff",
        "schema_version": 1,
        "disposition": "LOCAL_HUMAN_ROUTING_COMPARISON_DRAFT_HOLD_NO_AUTHORITY",
        "anonymous_packet_appearances_not_unique_cases": len(new),
        "ordinal_appearances_with_local_changes": len(changes),
        "ordinals_with_action_changes": sum(c["action_changed"] for c in changes),
        "ordinals_with_state_changes": sum(c["state_changed"] for c in changes),
        "not_modified_ordinal_appearances_not_evidence_of_stability":
            len(new) - len(changes),
        "locally_compared_changes": changes,
        "warning": NOTICE,
        **{f: False for f in portfolio.FLAGS},
    }


def report(summary: dict) -> bytes:
    rows = []
    for x in summary["locally_compared_changes"]:
        rows.append("<tr><th>%d</th><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                    (x["local_ordinal_not_original_case"],
                     html.escape(action_board.DISPLAY[x["earlier_local_action"]]),
                     html.escape(action_board.DISPLAY[x["later_local_action"]]),
                     html.escape(action_board.DISPLAY[x["earlier_local_state"]]),
                     html.escape(action_board.DISPLAY[x["later_local_state"]])))
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN routing changes</title><style>
:root{color-scheme:dark}body{background:#111e32;color:#f1f8ff;
max-width:1100px;margin:auto;padding:clamp(16px,4vw,50px);font:16px/1.5 system-ui}
aside{background:#34343d;padding:20px;border-left:5px solid #efbf76;border-radius:14px}
article{padding:12px 20px;background:#20354c;border-radius:14px;margin:20px 0}
table{border-collapse:collapse;width:100%%;min-width:900px}th,td{padding:12px;
border-bottom:1px solid #54657b;text-align:left}.scroll{overflow:auto}
@media print{body{color:black;background:white}aside,article{background:white;border:1px solid #999}}
</style></head><body><small>LIGHTUP / PRIVATE HUMAN / INCUBATE DRAFT HOLD</small>
<h1>Local HUMAN routing change overview</h1><aside><strong>No original-source proof.</strong>
<p>%s</p></aside><article><h2>%d locally changed ordinal appearances</h2>
<p>%d action changes; %d local state changes. Differences may overlap and
the input order is not an authenticated date, client or original case ID.</p></article>
<div class="scroll"><table><thead><tr><th>Local ordinal, not case</th>
<th>Earlier HUMAN action</th><th>Later HUMAN action</th>
<th>Earlier local state</th><th>Later local state</th>
</tr></thead><tbody>%s</tbody></table></div>
<p>Any real review outcome must be obtained from the current authenticated original
source with independent human authorization, not inferred from these numbers.</p>
</body></html>""" % (
        html.escape(NOTICE),
        summary["ordinal_appearances_with_local_changes"],
        summary["ordinals_with_action_changes"],
        summary["ordinals_with_state_changes"],
        "".join(rows))
    return page.encode("utf-8")


def csv_report(summary: dict) -> bytes:
    file = io.StringIO(newline="")
    out = csv.writer(file, lineterminator="\r\n")
    out.writerow(("local_ordinal_not_case", "earlier_local_action",
                  "later_local_action", "earlier_local_state",
                  "later_local_state", "action_changed", "state_changed"))
    for x in summary["locally_compared_changes"]:
        out.writerow((x["local_ordinal_not_original_case"],
                      x["earlier_local_action"], x["later_local_action"],
                      x["earlier_local_state"], x["later_local_state"],
                      "true" if x["action_changed"] else "false",
                      "true" if x["state_changed"] else "false"))
    return file.getvalue().encode("ascii")


def build(session_path: Path, earlier_board: Path, later_board: Path,
          destination: Path) -> dict:
    portfolio.require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    portfolio.require(not destination.exists() and not destination.is_symlink())
    data = compare(session_path, earlier_board, later_board)
    stage = Path(tempfile.mkdtemp(dir=destination.parent,
                                  prefix=".lightup-local-human-diff-"))
    os.chmod(stage, 0o700)
    try:
        portfolio.exclusive_write(stage / "index.html", report(data))
        portfolio.exclusive_write(stage / "changes.csv", csv_report(data))
        portfolio.exclusive_write(stage / "changes.json", portfolio.serialize(data))
        return_to_studio.sync_dir(stage)
        portfolio.publish(stage, destination)
        return_to_studio.sync_dir(destination.parent)
        return data
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=
        "PRIVATE offline two-board HUMAN state/action comparison; "
        "no verified source, case identity, timeline, fixes or authority.")
    parser.add_argument("--session", type=Path, required=True,
                        help="Original same PRIVATE source-free numeric session")
    parser.add_argument("--earlier-board", type=Path, required=True)
    parser.add_argument("--later-board", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="New owner-private comparison folder, never overwrite")
    args = parser.parse_args()
    try:
        data = build(args.session, args.earlier_board, args.later_board,
                     args.output_dir)
    except (OSError, ValueError, RecursionError):
        print("HOLD: no private local HUMAN routing comparison published.",
              file=sys.stderr)
        return 2
    print("PRIVATE HUMAN local comparison: %d changed ordinal appearances; "
          "not verified cases or remediation." %
          data["ordinal_appearances_with_local_changes"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
