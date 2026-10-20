#!/usr/bin/env python3
"""Reopen an existing PRIVATE HUMAN Lab multi-team proposal against original sources.

READ ONLY. Original packets, the unchanged FINAL source-bound HUMAN review,
the unchanged original TEAM handoff and all generated candidate bytes must
still agree. SHA-256 here is UNSIGNED integrity bookkeeping, never a grant.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import io
import os
from pathlib import Path
import re
import stat
import sys

import lab_plans
import lab_plan_review
import lab_review_history
import lab_review_team_batch as batch
import private_session as privacy
import route_queue
import workpack_progress

FILES = (
    "OPEN-PRIVATE.html",
    "PRIVATE-HUMAN-CANDIDATE.csv",
    "PRIVATE-HUMAN-MULTITEAM-DIFF.csv",
    "PRIVATE-HUMAN-WITHHELD-DIFF.csv",
)
AUTH_FALSE = (
    "source_authenticity_verified", "client_consent_verified",
    "operator_consent_verified", "recipients_authenticated",
    "human_go_recorded", "automated_actions", "scan_or_release_allowed",
    "original_urls_included", "private_question_text_included",
)
FIELDS = ("team", "proposal_slot", "previous_stage", "current_stage",
          "private_question_changed")


def _read(room: Path, filename: str) -> bytes:
    """Bounded descriptor-pinned 0600 original PRIVATE file read."""
    path = lab_plans._entry(room, filename)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        attributes = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid,
                                x.st_nlink, x.st_size, x.st_mtime_ns)
        if (attributes(before) != attributes(first)
                or not stat.S_ISREG(first.st_mode)
                or first.st_nlink != 1 or first.st_uid != os.geteuid()
                or stat.S_IMODE(first.st_mode) != 0o600
                or not 0 < first.st_size <= 2 * 1024 * 1024):
            raise privacy.Hold("HOLD: original PRIVATE HUMAN result file changed")
        payload = os.read(fd, 2 * 1024 * 1024 + 1)
        if (len(payload) != first.st_size
                or attributes(os.fstat(fd)) != attributes(first)):
            raise privacy.Hold("HOLD: original PRIVATE HUMAN result changed during reading")
        return payload
    finally:
        os.close(fd)


def _parse_diff(raw: bytes) -> list[dict]:
    try:
        reader = csv.reader(io.StringIO(raw.decode("utf-8", "strict"), newline=""),
                            strict=True)
        rows = list(reader)
    except (UnicodeError, csv.Error):
        raise privacy.Hold("HOLD: original PRIVATE HUMAN batch diff invalid") from None
    if not rows or tuple(rows[0]) != FIELDS or len(rows) > 512:
        raise privacy.Hold("HOLD: original PRIVATE HUMAN batch diff shape invalid")
    result = []
    for fields in rows[1:]:
        if len(fields) != len(FIELDS):
            raise privacy.Hold("HOLD: original PRIVATE HUMAN batch diff row invalid")
        item = dict(zip(FIELDS, fields))
        if not item["proposal_slot"].isascii() or not item["proposal_slot"].isdigit():
            raise privacy.Hold("HOLD: invalid original proposal ordinal")
        item["proposal_slot"] = int(item["proposal_slot"])
        if item["private_question_changed"] not in ("True", "False"):
            raise privacy.Hold("HOLD: invalid private question-change declaration")
        item["private_question_changed"] = item["private_question_changed"] == "True"
        result.append(item)
    return result


def inspect(packets: list[str], final_room: str, handoff_room: str, batch_room: str) -> dict:
    target = lab_plans._packet(batch_room)
    originals, fingerprint = lab_plan_review._source_rows(packets)
    original_final = lab_review_history._admit_final(final_room, originals, fingerprint)
    handoff = lab_plans._packet(handoff_room)
    available = batch._selected_manifest(handoff, original_final, fingerprint)
    receipt = workpack_progress._private_receipt(
        target / "PRIVATE-HUMAN-MULTITEAM-RECEIPT.json")
    expected = {
        "schema", "status", "authority", "original_source_snapshot_sha256_unsigned",
        "teams", "changed_ordinals", "unreturned_original_team_count",
        "unreturned_original_teams", "received_but_withheld_teams",
        "withheld_proposed_changes", "private_artifact_digests_unsigned", *AUTH_FALSE,
    }
    if (type(receipt) is not dict or set(receipt) != expected
            or receipt["schema"] != batch.SCHEMA
            or receipt["status"] != "REVIEW_ONLY"
            or receipt["original_source_snapshot_sha256_unsigned"] != fingerprint
            or any(receipt[key] is not False for key in AUTH_FALSE)
            or type(receipt["authority"]) is not dict
            or set(receipt["authority"]) != set(privacy.AUTHORITY)
            or any(type(receipt["authority"][key]) is not bool or
                   receipt["authority"][key] is not False for key in privacy.AUTHORITY)):
        raise privacy.Hold("HOLD: original PRIVATE HUMAN batch receipt invalid")

    inventory = receipt["private_artifact_digests_unsigned"]
    if (type(inventory) is not dict or set(inventory) != set(FILES)
            or any(type(value) is not str or
                   re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in inventory.values())):
        raise privacy.Hold("HOLD: original PRIVATE HUMAN batch inventory invalid")
    saved = {filename: _read(target, filename) for filename in FILES}
    if any(sha256(saved[filename]).hexdigest() != inventory[filename]
           for filename in FILES):
        raise privacy.Hold("HOLD: original PRIVATE HUMAN batch bytes changed since handoff")

    candidate = lab_plan_review._rows_admit(
        originals, str(target / "PRIVATE-HUMAN-CANDIDATE.csv"))
    declared = receipt["teams"]
    if (type(declared) is not list or not 1 <= len(declared) <= batch.MAX_TEAMS):
        raise privacy.Hold("HOLD: invalid original HUMAN batch team roster")
    adopted = set()
    withheld = set()
    declared_team_counts = {}
    for item in declared:
        if (type(item) is not dict or set(item) !=
                {"team", "assigned", "changed", "disposition"}):
            raise privacy.Hold("HOLD: malformed original HUMAN team result")
        name = item["team"]
        if name not in available or name in declared_team_counts:
            raise privacy.Hold("HOLD: foreign or duplicate original HUMAN team result")
        if type(item["assigned"]) is not int or item["assigned"] != available[name]:
            raise privacy.Hold("HOLD: original HUMAN team assignment count changed")
        if type(item["changed"]) is not int or not 0 <= item["changed"] <= item["assigned"]:
            raise privacy.Hold("HOLD: original HUMAN team stage count invalid")
        if item["disposition"] == "ADOPTED_AS_UNFINALIZED_HUMAN_DRAFT":
            adopted.add(name)
        elif item["disposition"] == "WITHHELD_FOR_HUMAN_REVIEW":
            if item["changed"] != 0:
                raise privacy.Hold("HOLD: a withheld team cannot mutate candidate")
            withheld.add(name)
        else:
            raise privacy.Hold("HOLD: unsupported original HUMAN team disposition")
        declared_team_counts[name] = item["changed"]

    expected_missing = [{"team": team, "assigned": count}
                        for team, count in available.items()
                        if team not in declared_team_counts]
    if (receipt["unreturned_original_teams"] != expected_missing
            or type(receipt["unreturned_original_team_count"]) is not int
            or receipt["unreturned_original_team_count"] != len(expected_missing)):
        raise privacy.Hold("HOLD: omitted original HUMAN teams no longer agree")
    withheld_receipt = receipt["received_but_withheld_teams"]
    if (type(withheld_receipt) is not list or len(withheld_receipt) != len(withheld)
            or {x["team"] for x in withheld_receipt if type(x) is dict
                and set(x) == {"team", "assigned", "proposed_changed"}} != withheld
            or any(type(x) is not dict or set(x) !=
                   {"team", "assigned", "proposed_changed"} or
                   type(x["assigned"]) is not int or
                   x["assigned"] != available[x["team"]] or
                   type(x["proposed_changed"]) is not int or
                   not 0 <= x["proposed_changed"] <= x["assigned"]
                   for x in withheld_receipt)):
        raise privacy.Hold("HOLD: withheld original HUMAN team roster changed")

    actual = []
    changed_by_team = {team: 0 for team in adopted}
    for prior, current in zip(original_final, candidate):
        # Original Lab FINAL team assignment cannot change as a side effect of a reply.
        if current["human_team"] != prior["human_team"]:
            raise privacy.Hold("HOLD: original source-bound HUMAN team was reassigned")
        differs = (current["human_stage"] != prior["human_stage"]
                   or current["human_question"] != prior["human_question"])
        if not differs:
            continue
        team = prior["human_team"]
        if team not in adopted:
            raise privacy.Hold("HOLD: withheld or unreturned HUMAN team changed")
        changed_by_team[team] += 1
        actual.append({
            "team": team, "proposal_slot": int(prior["proposal_slot"]),
            "previous_stage": prior["human_stage"],
            "current_stage": current["human_stage"],
            "private_question_changed": prior["human_question"] != current["human_question"],
        })
    declared_diff = _parse_diff(saved["PRIVATE-HUMAN-MULTITEAM-DIFF.csv"])
    # The original submission order is operator chosen, while candidate source order
    # is canonical. Compare by original proposal ordinal, never by arbitrary CSV order.
    if (sorted(actual, key=lambda item: item["proposal_slot"]) !=
            sorted(declared_diff, key=lambda item: item["proposal_slot"])):
        raise privacy.Hold("HOLD: PRIVATE HUMAN batch change declarations differ")
    if (receipt["changed_ordinals"] != len(actual)
            or type(receipt["changed_ordinals"]) is not int
            or any(declared_team_counts[x] != changed_by_team[x] for x in adopted)):
        raise privacy.Hold("HOLD: original HUMAN batch counts do not match candidate")
    withheld_diff = _parse_diff(saved["PRIVATE-HUMAN-WITHHELD-DIFF.csv"])
    original_by_slot = {int(x["proposal_slot"]): x for x in original_final}
    withheld_counts = {name: 0 for name in withheld}
    for item in withheld_diff:
        original = original_by_slot.get(item["proposal_slot"])
        if (original is None
                or item["team"] not in withheld
                or original["human_team"] != item["team"]
                or original["human_stage"] != item["previous_stage"]
                or item["current_stage"] not in route_queue.STAGES):
            raise privacy.Hold("HOLD: withheld HUMAN stage or source ordinal mismatch")
        withheld_counts[item["team"]] += 1
    if (type(receipt["withheld_proposed_changes"]) is not int
            or len(withheld_diff) != receipt["withheld_proposed_changes"]
            or len({x["proposal_slot"] for x in withheld_diff}) != len(withheld_diff)
            or any(withheld_counts[x["team"]] != x["proposed_changed"]
                   for x in withheld_receipt)):
        raise privacy.Hold("HOLD: original withheld team declarations differ")

    return {
        "status": "REVIEW_ONLY", "source_rechecked": True,
        "teams_adopted_as_unfinalized_draft": len(adopted),
        "teams_withheld_for_human_review": len(withheld),
        "teams_without_reply": len(expected_missing),
        "human_candidate_changes": len(actual),
        "human_withheld_proposed_changes": len(withheld_diff),
        "client_consent_authenticated": False, "operator_consent_authenticated": False,
        "authorization_granted": False, "human_go_recorded": False,
    }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="Reopen exact ORIGINAL source-bound PRIVATE HUMAN Lab multi-team result")
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--batch-room", required=True)
    cli.add_argument("--human-confirm", required=True)
    args = cli.parse_args(argv)
    try:
        if args.human_confirm != "REOPEN ORIGINAL PRIVATE LAB TEAM BATCH":
            raise privacy.Hold("HOLD: explicit source-bound HUMAN read-only reopen required")
        outcome = inspect(args.packet, args.final_room, args.handoff_room, args.batch_room)
        print("PRIVATE REVIEW_ONLY: original Lab HUMAN team batch source + bytes re-admitted")
        print("ADOPTED AS UNFINALIZED DRAFT:", outcome["teams_adopted_as_unfinalized_draft"])
        print("WITHHELD HUMAN TEAM RETURNS:", outcome["teams_withheld_for_human_review"])
        print("TEAM RESPONSES MISSING:", outcome["teams_without_reply"])
        print("ORIGINAL HUMAN DRAFT CHANGES:", outcome["human_candidate_changes"])
        print("HUMAN WITHHELD PROPOSALS:", outcome["human_withheld_proposed_changes"])
        print("NO approval, source authentication, consent, execution or HUMAN GO")
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN Lab batch could not be re-admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
