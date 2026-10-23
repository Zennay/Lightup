#!/usr/bin/env python3
"""Scriptless, source-minimized PRIVATE HUMAN priority inbox with per-row answers.

Only original selected ordinals, reported severity/count and unverified HUMAN
questions/replies are rendered. No original targets, finding IDs, evidence
bodies or identity/consent authority is included.
"""
from __future__ import annotations

from briefing import h
from revision import private_frame

def render(source: dict, selected: list[dict], answers: dict[int, dict]) -> bytes:
    priorities = sorted({r["priority"] for r in selected})
    navigation = "".join(
        "<a href='#priority-" + h(priority) + "'>HUMAN " + h(priority) + "</a> · "
        for priority in priorities
    )
    sections = []
    for priority in priorities:
        cards = []
        for item in selected:
            if item["priority"] != priority:
                continue
            ordinal = item["ordinal"]
            finding = source["findings"][ordinal-1]
            human = answers[ordinal]
            labels = (
                ("Source reported severity (UNVERIFIED)", finding["severity"]),
                ("Original evidence reference count", str(len(finding["evidence_ids"]))),
                ("HUMAN priority", item["priority"]),
                ("Original HUMAN question (UNVERIFIED)", item["question"]),
                ("Recipient self-reported HUMAN stage (UNVERIFIED)", human["recipient_stage"]),
                ("Recipient HUMAN answer (UNVERIFIED)", human["recipient_reply"]),
                ("Recipient next HUMAN follow-up", human["recipient_next_question"]),
            )
            details = "".join("<dt>" + h(k) + "</dt><dd><pre>" + h(v) +
                              "</pre></dd>" for k, v in labels)
            cards.append(
                "<article id='ordinal-" + str(ordinal) + "'><h3>Original ordinal #" +
                str(ordinal) + "</h3><dl>" + details + "</dl>"
                "<p>Independent HUMAN review: __________; original source "
                "checked: __________; no automatic security verdict.</p></article>"
            )
        sections.append(
            "<section id='priority-" + h(priority) + "'><h2>Original HUMAN "
            "priority: " + h(priority) + " · " + str(len(cards)) +
            " selected</h2>" + "".join(cards) + "</section>"
        )
    content = (
        "<header><h1>LightUp · PRIVATE HUMAN priority answer inbox</h1>"
        "<p class='notice'>REVIEW ONLY · original producer, lab finding, "
        "HUMAN recipient, actual evidence, claimed remedy, client/operator "
        "consent and disclosure authorization remain UNVERIFIED. No scan, "
        "message, grant or human assignment was executed.</p>"
        "<p>This readable report is deliberately ORIGINAL source-minimized: "
        "it excludes target names, original IDs, evidence summaries, "
        "run/tenant information and source hashes. However HUMAN questions "
        "and replies can reveal confidential clients, so this entire output "
        "is PRIVATE and may not be shared without independently verified "
        "current recipient and disclosure authority.</p>"
        "<p>All original selected HUMAN ordinals are included, including "
        "unanswered items. Missing HUMAN response is NEVER a verified fix, "
        "lack of risk or completed follow-up. Responses are self-reported "
        "and untrusted until independently reviewed.</p>"
        "<nav aria-label='PRIVATE HUMAN priority sections'>" + navigation +
        "</nav></header>" + "".join(sections)
    )
    return private_frame("PRIVATE HUMAN priority answer inbox — unverified", content)
