#!/usr/bin/env python3
"""Explicit human reconfirmation of old neutral-role capacity for a NEW agenda.

Source-bound planning only, no actual assignment, scan, grant, approval or GO.
"""
from __future__ import annotations

from portfolio import FLAGS, Hold, encode, summarize
from capacity_plan import SCHEMA, admitted_plan
from capacity import plan, html_report, csv_report
from followup import ROLES


def rebind(previous_plan_path, previous_agendas, previous_day,
           new_agendas, new_day, *, human_reconfirmed=False):
    if human_reconfirmed is not True:
        raise Hold("explicit human reconfirmation required for changed human source")
    if (not 1 <= len(previous_agendas) <= 12
            or len(previous_agendas) != len(new_agendas)):
        raise Hold("original agenda membership changed")
    budgets, weeks = admitted_plan(previous_plan_path, previous_agendas, previous_day)
    if (type(budgets) is not dict or set(budgets) != set(ROLES)
            or type(weeks) is not int or not 1 <= weeks <= 12):
        raise Hold("invalid original private hypothetical capacity")
    for old, new in zip(previous_agendas, new_agendas):
        if old["status"] != new["status"]:
            raise Hold("original held source status changed")
        old_slots = {row["slot"]: row["source_kind"] for row in old["rows"]}
        new_slots = {row["slot"]: row["source_kind"] for row in new["rows"]}
        if old_slots != new_slots:
            raise Hold("source kind or membership changed")
    # The capacity Studio already knows exactly this ORIGINAL capacity schema.
    # A new human acknowledgement is needed precisely because the source changed.
    document = {
        "schema": SCHEMA, "reference_date": new_day,
        "source_count": len(new_agendas),
        "sources": [{"slot":index,
                     "source_sha256": source["sha256"],
                     "claimed_status": source["status"]}
                    for index, source in enumerate(new_agendas, 1)],
        "hypothetical_weeks": weeks,
        "role_capacities": dict(budgets),
        **{flag: False for flag in FLAGS},
    }
    summary = summarize(new_agendas, new_day)
    schedule, counts = plan(new_agendas, new_day, budgets, weeks)
    private_report = html_report(summary, schedule, counts, weeks, False)
    aggregate_report = html_report(summary, schedule, counts, weeks, True)
    aggregate_csv = csv_report(summary, counts)
    return {
        "new-private-human-capacity-plan.json": encode(document),
        "new-private-human-capacity-outlook.html": private_report,
        "new-aggregate-human-capacity.html": aggregate_report,
        "new-aggregate-human-capacity.csv": aggregate_csv,
        "HUMAN-CAPACITY-RECONFIRMATION.txt": (
            "LIGHTUP / PRIVATE HUMAN HYPOTHETICAL CAPACITY CONTINUATION / NO GO\n"
            "Old original source-bound capacity assumptions were admitted, then\n"
            "explicitly reconfirmed for the NEW human-only source date and state.\n"
            "No real reviewer or project assignment, completion, due date or SLA exists.\n"
            "The old original plan was NOT edited and is NOT valid for the new source.\n"
            "The NEW private JSON is valid ONLY alongside the NEXT source-bound\n"
            "standalone Capacity Studio in next-human-workspace.zip.\n"
            "Review all changed neutral role assignments and original HOLD again.\n"
            "Hashes do not authenticate source, user, client consent or authorization.\n"
            "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.\n"
        ).encode("utf-8"),
    }
