#!/usr/bin/env python3
"""Scriptless PRIVATE packet directory for already-admitted curated HUMAN lab material.

No client source or HUMAN questions are copied into the directory. Its links
are fixed relative filenames within one owner-private publication directory.
An unsigned digest is only a byte-consistency aid, never trust/consent.
"""
from __future__ import annotations

import base64
import hashlib

from briefing import CSS, h


def render(source: dict, selected: list[dict], priorities: tuple[str, ...]) -> bytes:
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    policy = (
        "default-src 'none'; style-src 'sha256-" + css_pin +
        "'; script-src 'none'; connect-src 'none'; img-src 'none'; "
        "object-src 'none'; base-uri 'none'; form-action 'none'"
    )
    names = {
        "full": "PRIVATE-curated-dossier.html",
        "limited": "PRIVATE-source-minimized-HUMAN-handoff.html",
    }
    groups = {priority: [r for r in selected if r["priority"] == priority]
              for priority in priorities}
    sections = []
    for priority in priorities:
        group = groups[priority]
        if not group:
            continue
        group_file = "PRIVATE-HUMAN-" + priority + "-priority.html"
        rows = []
        for item in group:
            ordinal = item["ordinal"]
            finding = source["findings"][ordinal - 1]
            links = (
                '<a href="' + names["limited"] + '#ordinal-' + str(ordinal) +
                '">Source-minimized HUMAN question</a> · '
                '<a href="' + names["full"] + '#ordinal-' + str(ordinal) +
                '">FULL original PRIVATE evidence</a> · '
                '<a href="' + group_file + '#ordinal-' + str(ordinal) +
                '">Priority-only PRIVATE packet</a>'
            )
            rows.append(
                "<tr><th scope='row'>#" + str(ordinal) + "</th><td>" +
                h(finding["severity"]) + " (source-reported, UNVERIFIED)</td><td>" +
                str(len(finding["evidence_ids"])) + "</td><td>" +
                links + "</td></tr>"
            )
        sections.append(
            "<section><h2>HUMAN priority: " + h(priority) + " · " +
            str(len(group)) + " selected</h2><table><thead><tr>" +
            "<th scope='col'>Original ordinal</th><th scope='col'>Reported severity</th>" +
            "<th scope='col'>Evidence references</th><th scope='col'>PRIVATE local views</th>" +
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></section>"
        )
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
        '<meta http-equiv="Content-Security-Policy" content="' + h(policy) + '">' +
        "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
        "<title>PRIVATE curated packet directory</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · PRIVATE curated packet directory</h1>" +
        "<p class='notice'>REVIEW ONLY · INCUBATE M3/M7 PLAN/LAB ONLY · HOLD. "
        "This is a local human navigation aid, NOT a disclosure approval, "
        "permission, evidence verification, finding verdict or real reviewer identity.</p>" +
        "<p>Directory includes source-reported severity, original ordinal, reference "
        "counts and HUMAN priority only. It excludes targets, original finding IDs, "
        "evidence text, source hashes, original owner labels and HUMAN questions. "
        "These metadata and small groups can STILL identify a client: PRIVATE, not anonymous.</p>" +
        "<p>The FULL report includes original confidential evidence. The limited "
        "handoff and per-priority packets contain HUMAN questions that may contain "
        "identifying information. Choose a minimum-necessary packet and obtain "
        "separate current HUMAN disclosure authorization before sharing. "
        "Opening a link never sends or approves a packet.</p>" +
        "<p>Selected HUMAN ordinals: " + str(len(selected)) + " of " +
        str(len(source["findings"])) + " source-declared entries.</p>" +
        "<p>Local files: <a href='" + names["limited"] +
        "'>Source-minimized HUMAN handoff</a> · <a href='" + names["full"] +
        "'>FULL PRIVATE evidence dossier</a>.</p></header>" +
        "".join(sections) + "</body></html>\n"
    )
    return document.encode("utf-8")
