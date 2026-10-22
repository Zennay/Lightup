#!/usr/bin/env python3
"""Scriptless PRIVATE offline landing page for one exact all-priority HUMAN pack.

Contains only pre-admitted aggregate HUMAN counts and fixed local filenames.
Relative navigation is not permission to disclose or send files to recipients.
"""
from __future__ import annotations

from briefing import h
from curate import Hold
from revision import private_frame

FILES = (
    ("PRIVATE-HUMAN-priority-round-explorer.html",
     "Interactive round comparison, status history and attention desk"),
    ("PRIVATE-HUMAN-priority-round-portfolio.html",
     "Static printable HUMAN portfolio and transition overview"),
    ("PRIVATE-HUMAN-priority-round-portfolio.json",
     "Canonical source-minimal numeric portfolio for private analysis"),
    ("PRIVATE-HUMAN-priority-round-portfolio.csv",
     "Complete round / priority / stage count spreadsheet"),
    ("PRIVATE-HUMAN-priority-round-stage-transitions.csv",
     "Directional adjacent HUMAN status changes"),
    ("PRIVATE-HUMAN-priority-round-intervals.csv",
     "Every earlier/later HUMAN interval comparison"),
    ("PRIVATE-HUMAN-priority-round-interval-stage-movements.csv",
     "Every earlier/later HUMAN status movement with original priority"),
    ("PRIVATE-HUMAN-priority-round-portfolio-receipt.json",
     "UNSIGNED local source and output byte-digest receipt"),
)
PRIORITIES = ("urgent", "soon", "routine")
STAGES = ("blocked_human", "needs_more_information", "no_human_response")


def build(rounds: int, selection_count: int, attention: list[dict]) -> bytes:
    if (type(rounds) is not int or not 2 <= rounds <= 8 or
        type(selection_count) is not int or not 1 <= selection_count <= 64 or
        type(attention) is not list or len(attention) != 9):
        raise Hold("HOLD: PRIVATE HUMAN landing metadata invalid")
    by_key = {}
    for row in attention:
        if (type(row) is not dict or
            set(row) != {"human_priority", "human_stage", "human_rows"} or
            row["human_priority"] not in PRIORITIES or
            row["human_stage"] not in STAGES or
            type(row["human_rows"]) is not int or
            not 0 <= row["human_rows"] <= selection_count or
            (row["human_priority"], row["human_stage"]) in by_key):
            raise Hold("HOLD: duplicated or unsupported HUMAN attention summary")
        by_key[(row["human_priority"], row["human_stage"])] = row["human_rows"]
    if set(by_key) != {(p, stage) for p in PRIORITIES for stage in STAGES}:
        raise Hold("HOLD: incomplete PRIVATE HUMAN attention summary")
    rows = "".join(
        "<tr><td>" + h(priority) + "</td><td>" +
        str(by_key[(priority, "blocked_human")]) + "</td><td>" +
        str(by_key[(priority, "needs_more_information")]) + "</td><td>" +
        str(by_key[(priority, "no_human_response")]) + "</td></tr>"
        for priority in PRIORITIES)
    links = "".join(
        "<li><a href='" + h(filename) + "'>" + h(label) +
        "</a> <small>(" + h(filename) + ")</small></li>"
        for filename, label in FILES)
    body = (
        "<header><h1>LightUp · PRIVATE HUMAN all-priority workroom</h1>"
        "<p class='notice'>REVIEW ONLY · isolated offline, no active assessment, "
        "verified finding, remediation, human identity, real customer consent, "
        "grant, task or release. Nothing is sent or activated by this page.</p>"
        "<p>This owner-private source-bound package was generated from " +
        str(selection_count) + " original HUMAN-selected rows across " +
        str(rounds) + " manually ordered HUMAN response rounds. The chosen "
        "ordering is not independently authenticated chronology.</p>"
        "<p>All original source, selection, priority handoffs and complete "
        "HUMAN responses were readmitted before packet creation. The unsigned "
        "receipt only records local byte consistency, never producer identity. "
        "Even numeric aggregates may identify small client cohorts: do not "
        "disclose without current, separate HUMAN approval.</p></header>"
        "<section><h2>Latest HUMAN attention at a glance</h2>"
        "<p>These are human-reported unresolved discussion states, not verified "
        "risk priorities or operational assignments.</p><table>"
        "<thead><tr><th>Original HUMAN priority</th><th>Blocked</th>"
        "<th>Needs information</th><th>No HUMAN response</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table></section>"
        "<section><h2>Open the offline workroom</h2><ol>" +
        links + "</ol><p>Choose the interactive interval explorer first. "
        "The printable portfolio and private spreadsheets remain separate "
        "to prevent unsolicited exports. Local links only; nothing is uploaded "
        "or emailed. Exports and browser downloads require secure HUMAN "
        "handling outside this workroom.</p></section>"
    )
    return private_frame("PRIVATE HUMAN all-priority offline workroom", body)
