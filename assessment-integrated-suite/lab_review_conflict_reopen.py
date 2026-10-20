#!/usr/bin/env python3
"""Read-only exact-original-source reopen for PRIVATE HUMAN conflict resolution.

This does not verify actual reviewer identity or any security finding. It
reconstructs the candidate from pinned original source bytes, previous HUMAN
batch, returned HUMAN team CSVs and the explicit per-ordinal choices.
"""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import io
from pathlib import Path
import sys

import lab_plans
import lab_plan_review
import lab_review_conflict_resolution as conflict
import lab_review_team_batch_reopen as source_reader
import private_session as privacy
import route_queue
import workpack_progress


def inspect(packets: list[str], final_room: str, handoff_room: str,
            root_batch: str, prior_continuations: tuple[str, ...],
            team_returns: list[tuple[str, str]], choices_room: str,
            resolved_room: str) -> dict:
    previous, candidate_changes, original_digest = conflict._source(
        packets, final_room, handoff_room, root_batch, prior_continuations,
        team_returns)
    source_sha = candidate_changes[0]["source_snapshot_sha256"]
    expected = [{key: value for key, value in entry.items()
                 if not key.startswith("_")} for entry in candidate_changes]
    original_choices = lab_plans._packet(choices_room)
    published = lab_plans._packet(resolved_room)
    if original_choices == published or original_choices in published.parents:
        raise privacy.Hold("HOLD: original and published HUMAN rooms cannot overlap")
    original_csv = route_queue.read_owner_csv(str(
        original_choices / "PRIVATE-HUMAN-CHOICES.csv"))
    if original_csv != conflict._csv(expected):
        raise privacy.Hold("HOLD: original exact-source HUMAN choices room changed")
    original_receipt = workpack_progress._private_receipt(
        original_choices / "PRIVATE-HUMAN-DECISIONS-RECEIPT.json")
    original_keys = {
        "schema", "status", "authority", "verified_client_consent",
        "verified_operator_consent", "verified_reviewer_identity",
        "verified_source_identity", "human_go_recorded", "scan_or_release_allowed",
        "automatic_finalization", "external_contact",
        "private_question_text_included_in_overview",
        "original_source_sha256_unsigned", "previous_candidate_sha256_unsigned",
        "human_decisions_to_apply", "private_artifact_sha256_unsigned",
    }
    if (type(original_receipt) is not dict or set(original_receipt) != original_keys
            or original_receipt.get("schema") != conflict.SCHEMA
            or original_receipt.get("status") != "REVIEW_ONLY"
            or original_receipt.get("original_source_sha256_unsigned") != source_sha
            or original_receipt.get("previous_candidate_sha256_unsigned") != original_digest
            or type(original_receipt.get("human_decisions_to_apply")) is not int
            or original_receipt["human_decisions_to_apply"] != 0
            or type(original_receipt.get("authority")) is not dict
            or set(original_receipt["authority"]) != set(privacy.AUTHORITY)
            or any(type(original_receipt["authority"][key]) is not bool or
                   original_receipt["authority"][key] is not False
                   for key in privacy.AUTHORITY)
            or any(original_receipt[key] is not False for key in (
                "verified_client_consent", "verified_operator_consent",
                "verified_reviewer_identity", "verified_source_identity",
                "human_go_recorded", "scan_or_release_allowed",
                "automatic_finalization", "external_contact",
                "private_question_text_included_in_overview"))):
        raise privacy.Hold("HOLD: original HUMAN choices receipt/source differs")
    choice_receipt_files = original_receipt.get("private_artifact_sha256_unsigned")
    if (type(choice_receipt_files) is not dict
            or set(choice_receipt_files) != {
                "OPEN-PRIVATE.html", "EDIT-PRIVATE.html", "PRIVATE-HUMAN-CHOICES.csv"}
            or any(type(digest) is not str or
                   digest != sha256(source_reader._read(
                       original_choices, name)).hexdigest()
                   for name, digest in choice_receipt_files.items())):
        raise privacy.Hold("HOLD: original PRIVATE HUMAN choice bytes differ")

    receipt = workpack_progress._private_receipt(
        published / "PRIVATE-HUMAN-RESOLUTION-RECEIPT.json")
    all_keys = {
        "schema", "status", "authority", "verified_client_consent",
        "verified_operator_consent", "verified_reviewer_identity",
        "verified_source_identity", "human_go_recorded", "scan_or_release_allowed",
        "automatic_finalization", "external_contact",
        "private_question_text_included_in_overview", "original_source_sha256_unsigned",
        "previous_candidate_sha256_unsigned", "human_decisions_to_apply",
        "private_artifact_sha256_unsigned",
    }
    if (type(receipt) is not dict or set(receipt) != all_keys
            or receipt["schema"] != conflict.SCHEMA
            or receipt["status"] != "REVIEW_ONLY"
            or receipt["original_source_sha256_unsigned"] != source_sha
            or receipt["previous_candidate_sha256_unsigned"] != original_digest
            or type(receipt["human_decisions_to_apply"]) is not int
            or type(receipt["authority"]) is not dict
            or set(receipt["authority"]) != set(privacy.AUTHORITY)
            or any(type(receipt["authority"][key]) is not bool or
                   receipt["authority"][key] is not False for key in privacy.AUTHORITY)
            or any(receipt[key] is not False for key in (
                "verified_client_consent", "verified_operator_consent",
                "verified_reviewer_identity", "verified_source_identity",
                "human_go_recorded", "scan_or_release_allowed",
                "automatic_finalization", "external_contact",
                "private_question_text_included_in_overview"))):
        raise privacy.Hold("HOLD: resolved original HUMAN receipt/authority invalid")
    files = ("OPEN-PRIVATE.html", "PRIVATE-HUMAN-RESOLVED-CANDIDATE.csv",
             "PRIVATE-HUMAN-FINAL-CHOICES.csv")
    inventory = receipt["private_artifact_sha256_unsigned"]
    if (type(inventory) is not dict or set(inventory) != set(files)
            or any(type(inventory[name]) is not str or
                   inventory[name] != sha256(
                       source_reader._read(published, name)).hexdigest()
                   for name in files)):
        raise privacy.Hold("HOLD: resolved PRIVATE HUMAN file bytes changed")

    completed = route_queue.read_owner_csv(str(
        published / "PRIVATE-HUMAN-FINAL-CHOICES.csv"))
    try:
        table = list(csv.reader(io.StringIO(completed.decode("utf-8", "strict"),
                                             newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise privacy.Hold("HOLD: completed original HUMAN decisions malformed") from None
    if (len(table) != len(expected) + 1
            or tuple(table[0]) != conflict.COLUMNS):
        raise privacy.Hold("HOLD: completed original HUMAN choice rows differ")
    saved_choices = []
    for expected_row, actual_fields in zip(expected, table[1:]):
        if len(actual_fields) != len(conflict.COLUMNS):
            raise privacy.Hold("HOLD: completed original HUMAN choice row malformed")
        chosen = dict(zip(conflict.COLUMNS, actual_fields))
        if (any(chosen[key] != expected_row[key] for key in conflict.COLUMNS
                if key != "human_choice") or
                chosen["human_choice"] not in conflict.CHOICES):
            raise privacy.Hold("HOLD: original HUMAN source or explicit choice changed")
        saved_choices.append(chosen)
    original = [dict(row) for row in previous]
    positions = {row["proposal_slot"]: i for i, row in enumerate(original)}
    applied = 0
    for before, selected in zip(candidate_changes, saved_choices):
        if selected["human_choice"] == "APPLY_RETURN":
            row = before["_candidate"]
            original[positions[row["proposal_slot"]]] = row
            applied += 1
    expected_csv = lab_plan_review._csv(original)
    if (applied < 1 or applied != receipt["human_decisions_to_apply"]
            or expected_csv != route_queue.read_owner_csv(str(
                published / "PRIVATE-HUMAN-RESOLVED-CANDIDATE.csv"))):
        raise privacy.Hold("HOLD: published HUMAN conflict result differs from choices")
    return {
        "status": "REVIEW_ONLY", "exact_original_source_readmitted": True,
        "complete_prior_human_decisions_preserved_except_explicit_choices": True,
        "proposals_offered_to_human": len(expected),
        "explicitly_applied_unfinalized_proposals": applied,
        "original_human_finalization_performed": False,
        "authenticated_authority": False, "client_consent_authenticated": False,
        "operator_consent_authenticated": False, "human_go_recorded": False,
    }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(
        description="Read-only original PRIVATE HUMAN conflict resolution byte/source reopen")
    cli.add_argument("--packet", action="append", required=True)
    cli.add_argument("--final-room", required=True)
    cli.add_argument("--handoff-room", required=True)
    cli.add_argument("--root-batch", required=True)
    cli.add_argument("--prior-continuation", action="append", default=[])
    cli.add_argument("--team-return", action="append", required=True)
    cli.add_argument("--choices-room", required=True)
    cli.add_argument("--resolved-room", required=True)
    cli.add_argument("--human-confirm", required=True)
    opts = cli.parse_args(argv)
    try:
        if opts.human_confirm != "REOPEN ORIGINAL HUMAN CONFLICT RESOLUTION":
            raise privacy.Hold("HOLD: original HUMAN read-only reopen confirmation missing")
        inputs = []
        for item in opts.team_return:
            if "=" not in item:
                raise privacy.Hold("HOLD: team return must be TEAM=PRIVATE_CSV")
            inputs.append(tuple(item.split("=", 1)))
        result = inspect(opts.packet, opts.final_room, opts.handoff_room,
                         opts.root_batch, tuple(opts.prior_continuation),
                         inputs, opts.choices_room, opts.resolved_room)
        print("PRIVATE REVIEW_ONLY: original HUMAN conflict candidate re-admitted")
        print("EXPLICIT ORIGINAL HUMAN CHOICES:", result[
            "explicitly_applied_unfinalized_proposals"])
        print("NO scanner, authentication, consent, finalization or HUMAN GO")
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc, privacy.Hold) else
              "HOLD: original PRIVATE HUMAN resolution could not be re-admitted",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
