#!/usr/bin/env python3
"""Continue an original PRIVATE Lab HUMAN batch without losing earlier decisions.

An already-saved batch is a source-bound HUMAN draft, never an authority.
Every returned team reply is admitted against the original unchanged handoff.
If any team proposes a different value for an already-edited HUMAN row, the
entire team's reply is withheld rather than silently replacing an older edit.
No scans, networking, grants, messaging, finalization, or QA execution.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import sys

import lab_plans
import lab_plan_review
import lab_review_history
import lab_review_team_batch as batch
import lab_review_team_batch_reopen as reopen
import lab_review_team_handoff as handoff
import lab_review_team_return as team_return
import private_session as privacy
import route_queue

SCHEMA = "lightup.private.original-lab-human-batch-continuation.v1"
AUTH_FALSE = {
    "source_authenticated": False, "client_consent_verified": False,
    "operator_consent_verified": False, "reviewers_authenticated": False,
    "human_go_recorded": False, "scan_or_release_allowed": False,
    "automated_dispatch": False, "original_urls_included": False,
    "private_question_text_included": False,
}
DIFF_FIELDS = ("team", "proposal_slot", "previous_stage", "proposed_stage",
               "private_question_changed", "reason")


def _diff_csv(rows: list[dict]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(DIFF_FIELDS)
    for item in rows:
        writer.writerow([item[field] for field in DIFF_FIELDS])
    return buffer.getvalue().encode("utf-8")


def _page(outcomes: list[dict], adopted: list[dict],
          conflicts: list[dict], missing: list[str]) -> bytes:
    esc = lambda val: html.escape(str(val), quote=True)
    badges = "".join(
        "<li><b>" + esc(x["team"]) + "</b> · " + esc(x["disposition"]) +
        " · original assigned: " + str(x["assigned"]) +
        " · incorporated HUMAN changes: " + str(x["applied_count"]) +
        " · proposal conflicts: " + str(x["conflict_count"]) + "</li>"
        for x in outcomes
    )
    conflict_rows = "".join(
        "<li>Original proposal #" + str(x["proposal_slot"]) + " · " +
        esc(x["team"]) + " · prior HUMAN stage " + esc(x["previous_stage"]) +
        " · newly proposed " + esc(x["proposed_stage"]) +
        " · private question changed: " +
        ("YES" if x["private_question_changed"] else "NO") +
        " · <b>NO AUTOMATIC REPLACEMENT</b></li>"
        for x in conflicts
    )
    absent = "".join("<li>" + esc(x) + " — no new HUMAN reply; previously"
                     " saved decisions retained</li>" for x in missing)
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN Lab continuation</title>
<style>:root{color-scheme:dark;background:#0e1e30;color:#eef8ff;font:16px/1.6 system-ui}
body{max-width:1000px;margin:2rem auto;padding:0 1rem}
header,section,footer{background:#203b51;border:1px solid #5d7e94;
padding:24px;border-radius:16px;margin:16px 0}li{margin:12px 0}
b{color:#ffdfaa}</style></head><body>
<header><p><b>PRIVATE ORIGINAL LAB · HUMAN REVIEW_ONLY · DRAFT/HOLD</b></p>
<h1>Continue earlier HUMAN team decisions</h1>
<p>A previously stored source-rechecked HUMAN draft was the starting point.
New team replies were re-admitted against the SAME original source and handoff.
No old HUMAN decision is changed by an overlapping conflicting team reply.</p></header>
<section><h2>Returned team proposals</h2><ul>""" +
        (badges or "<li>No HUMAN returns incorporated.</li>") +
        """</ul></section>
<section><h2>Earlier HUMAN decisions protected from conflict</h2><ul>""" +
        (conflict_rows or "<li>No overlapping changed original HUMAN decisions.</li>") +
        """</ul><p>Every team containing a conflict was withheld as a whole.
Review privately and choose a NEW original HUMAN draft to resolve it;
the original FINAL review and prior batch remain untouched.</p></section>
<section><h2>Assigned teams without a new return</h2><ul>""" +
        (absent or "<li>No assigned team was omitted from this round.</li>") +
        """</ul></section>
<section><h2>Complete next ORIGINAL HUMAN draft</h2>
<p>The new owner-0600 complete seven-column candidate preserves the exact
original source-ordinal order and earlier team decisions. Open it in the
original HUMAN Studio (option 58) for deliberate fresh HUMAN finalization.
Never infer authority, source authenticity or a verified security fix.</p></section>
<footer><b>INCUBATE M3/M7 PLAN/LAB ONLY · NO GRANT, SCAN, RELEASE OR DISPATCH</b>
<p>Original exact-head hosted/named VPS CI, source-owner review, independent
security/privacy/browser reviews, separate authenticated present client
and operator consent with at-use revocation and explicit HUMAN GO remain
mandatory. No private questions, source paths, URLs, credentials or source
hashes appear on this offline overview. Unsigned file hashes are not identity.</p>
</footer></body></html>""").encode("utf-8")


def build(packets: list[str], final_room: str, handoff_room: str, prior_batch: str,
          replies: list[tuple[str, str]], parent: str, folder: str,
          *, withhold_teams: tuple[str, ...] = (),
          prior_continuations: tuple[str, ...] = ()) -> Path:
    if (type(replies) is not list or not 1 <= len(replies) <= batch.MAX_TEAMS
            or len({team for team, _ in replies}) != len(replies)
            or any(team not in handoff.SLUGS or not path for team, path in replies)):
        raise privacy.Hold("HOLD: 1–4 different original team replies required")
    names = {team for team, _ in replies}
    if (type(withhold_teams) is not tuple
            or len(withhold_teams) != len(set(withhold_teams))
            or any(team not in names for team in withhold_teams)):
        raise privacy.Hold("HOLD: withhold only a distinct returned HUMAN team")
    if (type(prior_continuations) is not tuple or len(prior_continuations) > 6
            or len(set(prior_continuations)) != len(prior_continuations)):
        raise privacy.Hold("HOLD: at most six distinct original HUMAN continuation rooms")
    chosen_withhold = set(withhold_teams)
    dest = lab_plans._new_path(parent, folder)
    prior_room = lab_plans._packet(prior_batch)
    final_source = lab_plans._packet(final_room)
    original_handoff = lab_plans._packet(handoff_room)
    prior_chain = [lab_plans._packet(x) for x in prior_continuations]
    if prior_room in prior_chain or len(set(prior_chain)) != len(prior_chain):
        raise privacy.Hold("HOLD: same original HUMAN batch cannot appear twice")
    sources = [prior_room, final_source, original_handoff, *prior_chain] + [
        lab_plans._packet(x) for x in packets
    ]
    if any(x == dest or x in dest.parents for x in sources):
        raise privacy.Hold("HOLD: new HUMAN continuation may not nest inside source")
    # Strict original and prior room admission FIRST, before creating output.
    reopen.inspect(packets, final_room, handoff_room, prior_batch)
    if prior_chain:
        import lab_review_team_continue_reopen as continued_reopen
        continued_reopen.inspect(
            packets, final_room, handoff_room, prior_batch, str(prior_chain[-1]),
            prior_continuations=tuple(str(x) for x in prior_chain[:-1]))
    previous_source = prior_chain[-1] if prior_chain else prior_room
    previous_filename = ("PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv" if prior_chain
                         else "PRIVATE-HUMAN-CANDIDATE.csv")
    previous_receipt_name = ("PRIVATE-HUMAN-CONTINUATION-RECEIPT.json" if prior_chain
                             else "PRIVATE-HUMAN-MULTITEAM-RECEIPT.json")
    original, fingerprint = lab_plan_review._source_rows(packets)
    final = lab_review_history._admit_final(final_room, original, fingerprint)
    previous = lab_plan_review._rows_admit(
        original, str(previous_source / previous_filename))
    available = batch._selected_manifest(original_handoff, final, fingerprint)
    updated = [dict(row) for row in previous]
    positions = {row["proposal_slot"]: position for position, row in enumerate(previous)}
    conflicts: list[dict] = []
    accepted: list[dict] = []
    team_outcomes: list[dict] = []
    for team, filename in replies:
        if team not in available:
            raise privacy.Hold("HOLD: returned HUMAN team was never assigned")
        selected = [row for row in final if row["human_team"] == team]
        pinned = route_queue.read_owner_csv(str(
            original_handoff / ("TEAM-" + handoff.SLUGS[team] + "-DRAFT.csv")))
        if pinned != handoff._team_csv(selected):
            raise privacy.Hold("HOLD: original HUMAN team handoff source changed")
        incoming = team_return._read_team(filename, selected, team)
        team_changes = []
        team_conflicts = []
        for source_row, proposed in zip(selected, incoming):
            prior = previous[positions[source_row["proposal_slot"]]]
            same_as_previous = all(
                prior[key] == proposed[key] for key in ("human_stage", "human_question")
            )
            earlier_modified = any(
                prior[key] != source_row[key] for key in ("human_stage", "human_question")
            )
            proposed_modifies_earlier = earlier_modified and not same_as_previous
            entry = {
                "team": team, "proposal_slot": int(source_row["proposal_slot"]),
                "previous_stage": prior["human_stage"],
                "proposed_stage": proposed["human_stage"],
                "private_question_changed": (
                    prior["human_question"] != proposed["human_question"]
                ),
                "reason": ("PREVIOUS_HUMAN_DECISION_CONFLICT" if proposed_modifies_earlier
                           else "NEW_HUMAN_PROPOSAL"),
            }
            if proposed_modifies_earlier:
                team_conflicts.append(entry)
            elif not same_as_previous:
                team_changes.append((source_row["proposal_slot"], proposed, entry))
        # All entries were admitted even if the entire team is withheld.
        if team_conflicts:
            disposition = "WITHHELD_CONFLICT"
        elif team in chosen_withhold:
            disposition = "WITHHELD_BY_OPERATOR"
        else:
            disposition = "ADOPTED_AS_UNFINALIZED_HUMAN_DRAFT"
            for ordinal, proposed, entry in team_changes:
                updated[positions[ordinal]] = proposed
                accepted.append(entry)
        conflicts.extend(team_conflicts)
        team_outcomes.append({
            "team": team, "assigned": len(selected), "disposition": disposition,
            "applied_count": len(team_changes) if disposition.startswith("ADOPTED_") else 0,
            "conflict_count": len(team_conflicts),
        })

    missing = [name for name in available if name not in names]
    # The prior and original PRIVATE batch bytes are intentionally unchanged.
    original_receipt_raw = reopen._read(previous_source, previous_receipt_name)
    old_candidate_raw = reopen._read(previous_source, previous_filename)
    if old_candidate_raw != lab_plan_review._csv(previous):
        raise privacy.Hold("HOLD: original prior HUMAN candidate bytes changed")
    receipt = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        **AUTH_FALSE,
        "original_source_fingerprint_sha256_unsigned": fingerprint,
        "prior_receipt_sha256_unsigned": sha256(original_receipt_raw).hexdigest(),
        "prior_candidate_sha256_unsigned": sha256(old_candidate_raw).hexdigest(),
        "team_outcomes": team_outcomes, "not_returned_team_names": missing,
        "incorporated_proposals": len(accepted),
        "protected_conflict_proposals": len(conflicts),
        "manual_finalization_required": True,
    }
    files = (
        ("OPEN-PRIVATE.html", _page(team_outcomes, accepted, conflicts, missing)),
        ("PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv", lab_plan_review._csv(updated)),
        ("PRIVATE-HUMAN-CONTINUED-CHANGES.csv", _diff_csv(accepted)),
        ("PRIVATE-HUMAN-PROTECTED-CONFLICTS.csv", _diff_csv(conflicts)),
    )
    receipt["private_artifact_digests_unsigned"] = {
        name: sha256(data).hexdigest() for name, data in files
    }
    output = (*files, (
        "PRIVATE-HUMAN-CONTINUATION-RECEIPT.json",
        (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    ))
    dest.mkdir(mode=0o700)
    try:
        if not privacy.private(dest, True):
            raise privacy.Hold("HOLD: new HUMAN continuation room is not owner-private")
        for name, data in output:
            privacy.private_write(dest, name, data)
        handle = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)
    except Exception:
        shutil.rmtree(dest)
        raise privacy.Hold("HOLD: PRIVATE HUMAN continuation not published") from None
    return dest / "OPEN-PRIVATE.html"


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="Continue PRIVATE original-source HUMAN batch without losing decisions"
    )
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--prior-batch", required=True)
    cli.add_argument("--prior-continuation", action="append", default=[],
                     help="Prior original HUMAN continuation rooms, oldest first")
    cli.add_argument("--team-return", action="append", required=True,
                     metavar="TEAM=PRIVATE_CSV")
    cli.add_argument("--withhold-team", action="append", default=[],
                     choices=tuple(handoff.SLUGS))
    cli.add_argument("--private-parent", required=True)
    cli.add_argument("--folder", required=True)
    cli.add_argument("--human-confirm", required=True)
    params = cli.parse_args(argv)
    try:
        if params.human_confirm != "CONTINUE PRIVATE LAB HUMAN BATCH":
            raise privacy.Hold("HOLD: explicit HUMAN continuation confirmation missing")
        returns = []
        for argument in params.team_return:
            if "=" not in argument:
                raise privacy.Hold("HOLD: --team-return must be TEAM=PRIVATE_CSV")
            team, filename = argument.split("=", 1)
            returns.append((team, filename))
        page = build(params.packet, params.final_room, params.handoff_room,
                     params.prior_batch, returns, params.private_parent, params.folder,
                     withhold_teams=tuple(params.withhold_team),
                     prior_continuations=tuple(params.prior_continuation))
        print("PRIVATE REVIEW_ONLY: original HUMAN decisions continued, not finalized")
        print("OPEN LOCALLY: " + str(page))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN continuation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
