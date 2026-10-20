#!/usr/bin/env python3
"""Read-only source and unsigned exact-byte reopen of one HUMAN Lab continuation.

Never authenticates a reviewer, client, operator, permission or security result.
All source-owning native packet/FINAL/team decisions remain the authority for
SOURCE SHAPE only. The prior operator batch and subsequent artifact must match.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import io
from pathlib import Path
import re
import sys

import lab_plans
import lab_plan_review
import lab_review_history
import lab_review_team_batch as batch
import lab_review_team_batch_reopen as original_reopen
import lab_review_team_continue as continuation
import private_session as privacy
import route_queue
import workpack_progress

FILES = (
    "OPEN-PRIVATE.html",
    "PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv",
    "PRIVATE-HUMAN-CONTINUED-CHANGES.csv",
    "PRIVATE-HUMAN-PROTECTED-CONFLICTS.csv",
)
VALID_DISPOSITIONS = {
    "ADOPTED_AS_UNFINALIZED_HUMAN_DRAFT",
    "WITHHELD_BY_OPERATOR",
    "WITHHELD_CONFLICT",
}


def _read_diff(raw: bytes) -> list[dict]:
    try:
        records = list(csv.reader(io.StringIO(raw.decode("utf-8", "strict"),
                                              newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise privacy.Hold("HOLD: original HUMAN continuation difference malformed") from None
    if (not records or tuple(records[0]) != continuation.DIFF_FIELDS
            or len(records) > 512):
        raise privacy.Hold("HOLD: HUMAN continuation difference columns/size invalid")
    result = []
    for record in records[1:]:
        if len(record) != len(continuation.DIFF_FIELDS):
            raise privacy.Hold("HOLD: HUMAN continuation difference row malformed")
        item = dict(zip(continuation.DIFF_FIELDS, record))
        if (not item["proposal_slot"].isascii() or
                not item["proposal_slot"].isdigit() or
                item["private_question_changed"] not in ("True", "False")):
            raise privacy.Hold("HOLD: original HUMAN continuation ordinal/Boolean invalid")
        item["proposal_slot"] = int(item["proposal_slot"])
        item["private_question_changed"] = item["private_question_changed"] == "True"
        if (item["proposed_stage"] not in route_queue.STAGES
                or item["previous_stage"] not in route_queue.STAGES
                or item["reason"] not in (
                    "NEW_HUMAN_PROPOSAL", "PREVIOUS_HUMAN_DECISION_CONFLICT")):
            raise privacy.Hold("HOLD: original HUMAN stage/reason invalid")
        result.append(item)
    if len({item["proposal_slot"] for item in result}) != len(result):
        raise privacy.Hold("HOLD: repeated original HUMAN ordinal in one difference")
    return result


def inspect(packets: list[str], final_room: str, handoff_room: str,
            prior_batch: str, continued_room: str,
            *, prior_continuations: tuple[str, ...] = ()) -> dict:
    if (type(prior_continuations) is not tuple or len(prior_continuations) > 6
            or len(set(prior_continuations)) != len(prior_continuations)
            or continued_room in prior_continuations):
        raise privacy.Hold("HOLD: 0–6 distinct earlier original HUMAN continuations required")
    # Compare canonically admitted PRIVATE directory identities, never only
    # literal operator-entered path strings: a past round cannot be replayed.
    lineage = [lab_plans._packet(prior_batch)] + [
        lab_plans._packet(name) for name in prior_continuations
    ] + [lab_plans._packet(continued_room)]
    if len(set(lineage)) != len(lineage):
        raise privacy.Hold("HOLD: duplicated original PRIVATE HUMAN source in chain")
    # Re-admit the entire immutable source lineage, earliest first.
    original_reopen.inspect(packets, final_room, handoff_room, prior_batch)
    if prior_continuations:
        for index, earlier in enumerate(prior_continuations):
            inspect(packets, final_room, handoff_room, prior_batch, earlier,
                    prior_continuations=prior_continuations[:index])
    parent = lab_plans._packet(
        prior_continuations[-1] if prior_continuations else prior_batch)
    current = lab_plans._packet(continued_room)
    if parent == current or parent in current.parents or current in parent.parents:
        raise privacy.Hold("HOLD: saved original HUMAN rooms must remain distinct")
    originals, fingerprint = lab_plan_review._source_rows(packets)
    final = lab_review_history._admit_final(final_room, originals, fingerprint)
    prior_name = ("PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv"
                  if prior_continuations else "PRIVATE-HUMAN-CANDIDATE.csv")
    prior_receipt = ("PRIVATE-HUMAN-CONTINUATION-RECEIPT.json"
                     if prior_continuations else "PRIVATE-HUMAN-MULTITEAM-RECEIPT.json")
    existing = lab_plan_review._rows_admit(
        originals, str(parent / prior_name))
    available = batch._selected_manifest(lab_plans._packet(handoff_room),
                                         final, fingerprint)
    receipt = workpack_progress._private_receipt(
        current / "PRIVATE-HUMAN-CONTINUATION-RECEIPT.json")
    keys = {
        "schema", "status", "authority",
        "original_source_fingerprint_sha256_unsigned",
        "prior_receipt_sha256_unsigned", "prior_candidate_sha256_unsigned",
        "team_outcomes", "not_returned_team_names", "incorporated_proposals",
        "protected_conflict_proposals", "manual_finalization_required",
        "private_artifact_digests_unsigned", *continuation.AUTH_FALSE.keys(),
    }
    if (type(receipt) is not dict or set(receipt) != keys
            or receipt["schema"] != continuation.SCHEMA
            or receipt["status"] != "REVIEW_ONLY"
            or receipt["manual_finalization_required"] is not True
            or receipt["original_source_fingerprint_sha256_unsigned"] != fingerprint
            or any(receipt[k] is not False for k in continuation.AUTH_FALSE)
            or type(receipt["authority"]) is not dict
            or set(receipt["authority"]) != set(privacy.AUTHORITY)
            or any(type(receipt["authority"][k]) is not bool or
                   receipt["authority"][k] is not False for k in privacy.AUTHORITY)):
        raise privacy.Hold("HOLD: original PRIVATE HUMAN continuation receipt rejected")
    old_receipt = original_reopen._read(parent, prior_receipt)
    old_candidate = original_reopen._read(parent, prior_name)
    if (receipt["prior_receipt_sha256_unsigned"] != sha256(old_receipt).hexdigest()
            or receipt["prior_candidate_sha256_unsigned"] !=
            sha256(old_candidate).hexdigest()):
        raise privacy.Hold("HOLD: original prior HUMAN Lab batch byte identity differs")
    inventory = receipt["private_artifact_digests_unsigned"]
    if (type(inventory) is not dict or set(inventory) != set(FILES)
            or any(type(digest) is not str or
                   re.fullmatch(r"[a-f0-9]{64}", digest) is None
                   for digest in inventory.values())):
        raise privacy.Hold("HOLD: PRIVATE HUMAN continuation file inventory differs")
    payloads = {filename: original_reopen._read(current, filename)
                for filename in FILES}
    if any(sha256(payloads[name]).hexdigest() != inventory[name]
           for name in FILES):
        raise privacy.Hold("HOLD: stored original HUMAN continuation bytes changed")
    candidate = lab_plan_review._rows_admit(
        originals, str(current / "PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv"))
    roster = receipt["team_outcomes"]
    if type(roster) is not list or not 1 <= len(roster) <= batch.MAX_TEAMS:
        raise privacy.Hold("HOLD: original HUMAN continued-team roster invalid")
    status = {}
    for item in roster:
        if (type(item) is not dict or set(item) !=
                {"team", "assigned", "disposition", "applied_count", "conflict_count"}):
            raise privacy.Hold("HOLD: malformed original HUMAN continued-team entry")
        team = item["team"]
        if (team not in available or team in status or
                type(item["assigned"]) is not int or
                item["assigned"] != available[team] or
                item["disposition"] not in VALID_DISPOSITIONS or
                type(item["applied_count"]) is not int or
                not 0 <= item["applied_count"] <= item["assigned"] or
                type(item["conflict_count"]) is not int or
                not 0 <= item["conflict_count"] <= item["assigned"] or
                (item["disposition"] != "ADOPTED_AS_UNFINALIZED_HUMAN_DRAFT"
                 and item["applied_count"] != 0) or
                (item["disposition"] == "WITHHELD_CONFLICT"
                 and item["conflict_count"] == 0) or
                (item["disposition"] != "WITHHELD_CONFLICT"
                 and item["conflict_count"] != 0)):
            raise privacy.Hold("HOLD: unknown original HUMAN team continuation state")
        status[team] = item
    absent = [team for team in available if team not in status]
    if type(receipt["not_returned_team_names"]) is not list or receipt[
            "not_returned_team_names"] != absent:
        raise privacy.Hold("HOLD: missing original HUMAN teams changed")
    adopted = _read_diff(payloads["PRIVATE-HUMAN-CONTINUED-CHANGES.csv"])
    protected = _read_diff(payloads["PRIVATE-HUMAN-PROTECTED-CONFLICTS.csv"])
    if (type(receipt["incorporated_proposals"]) is not int or
            type(receipt["protected_conflict_proposals"]) is not int or
            len(adopted) != receipt["incorporated_proposals"] or
            len(protected) != receipt["protected_conflict_proposals"]):
        raise privacy.Hold("HOLD: original HUMAN continuation counts differ")
    actual = []
    by_slot = {int(row["proposal_slot"]): (old, new, final_row)
               for old, new, final_row in zip(existing, candidate, final)}
    for old, new, final_row in by_slot.values():
        if new["human_team"] != old["human_team"]:
            raise privacy.Hold("HOLD: original HUMAN team was reassigned")
        different = any(old[k] != new[k] for k in ("human_stage", "human_question"))
        if not different:
            continue
        team = old["human_team"]
        if (team not in status or status[team]["disposition"] !=
                "ADOPTED_AS_UNFINALIZED_HUMAN_DRAFT"):
            raise privacy.Hold("HOLD: absent or withheld original team modified")
        # A previously changed HUMAN row may NEVER be overwritten.
        if any(old[k] != final_row[k] for k in ("human_stage", "human_question")):
            raise privacy.Hold("HOLD: earlier HUMAN decision was overwritten")
        actual.append({
            "team": team, "proposal_slot": int(old["proposal_slot"]),
            "previous_stage": old["human_stage"],
            "proposed_stage": new["human_stage"],
            "private_question_changed": old["human_question"] != new["human_question"],
            "reason": "NEW_HUMAN_PROPOSAL",
        })
    if (sorted(actual, key=lambda item: item["proposal_slot"]) !=
            sorted(adopted, key=lambda item: item["proposal_slot"])):
        raise privacy.Hold("HOLD: accepted original HUMAN continuation changes differ")
    for team, entry in status.items():
        if entry["applied_count"] != sum(x["team"] == team for x in actual):
            raise privacy.Hold("HOLD: accepted HUMAN team proposal count inconsistent")
    if any(x["reason"] != "NEW_HUMAN_PROPOSAL" for x in adopted):
        raise privacy.Hold("HOLD: invalid accepted HUMAN change reason")
    for item in protected:
        old, _, original = by_slot.get(item["proposal_slot"], (None, None, None))
        if (old is None or item["team"] not in status or
                status[item["team"]]["disposition"] != "WITHHELD_CONFLICT" or
                original["human_team"] != item["team"] or
                old["human_stage"] != item["previous_stage"] or
                not any(old[key] != original[key]
                        for key in ("human_stage", "human_question")) or
                item["reason"] != "PREVIOUS_HUMAN_DECISION_CONFLICT"):
            raise privacy.Hold("HOLD: original HUMAN protected-conflict claim differs")
    if any(status[team]["conflict_count"] !=
           sum(x["team"] == team for x in protected)
           for team in status):
        raise privacy.Hold("HOLD: original HUMAN protected-conflict count changed")
    return {
        "status": "REVIEW_ONLY",
        "earlier_human_decisions_retained": True,
        "new_team_replies": len(roster),
        "adopted_team_replies": sum(
            item["disposition"] == "ADOPTED_AS_UNFINALIZED_HUMAN_DRAFT"
            for item in roster),
        "manually_withheld_team_replies": sum(
            item["disposition"] == "WITHHELD_BY_OPERATOR" for item in roster),
        "conflict_withheld_team_replies": sum(
            item["disposition"] == "WITHHELD_CONFLICT" for item in roster),
        "changed_original_proposals": len(actual),
        "not_returned_teams": len(absent),
        "authorization_granted": False,
        "human_go_recorded": False,
    }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="READ ONLY: reopen a prior-source-bound PRIVATE Lab HUMAN continuation"
    )
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--prior-batch", required=True)
    cli.add_argument("--continued-room", required=True)
    cli.add_argument("--prior-continuation", action="append", default=[])

    cli.add_argument("--human-confirm", required=True)
    args = cli.parse_args(argv)
    try:
        if args.human_confirm != "REOPEN PRIVATE LAB HUMAN CONTINUATION":
            raise privacy.Hold("HOLD: manual original-source read-only reopen required")
        data = inspect(args.packet, args.final_room, args.handoff_room,
                       args.prior_batch, args.continued_room,
                       prior_continuations=tuple(args.prior_continuation))
        print("PRIVATE REVIEW_ONLY: original prior HUMAN source and continuation re-admitted")
        print("NEW REPLIES:", data["new_team_replies"])
        print("CONFLICT-WITHHELD TEAMS:", data["conflict_withheld_team_replies"])
        print("APPLIED UNFINALIZED CHANGES:", data["changed_original_proposals"])
        print("NO AUTHENTICATION, CONSENT, ACTIVE ASSESSMENT OR HUMAN GO")
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original source-bound HUMAN continuation could not reopen",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
