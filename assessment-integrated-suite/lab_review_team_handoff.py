#!/usr/bin/env python3
"""PRIVATE source-bound original HUMAN lab team worklist handoff, offline only.

Never scans, releases, sends, authorizes, schedules, contacts or authenticates
a recipient. These are *manually proposed* HUMAN team drafts only.
"""
from __future__ import annotations

import argparse
import csv
import io
from base64 import b64encode
from hashlib import sha256
import html
import json
import os
from pathlib import Path
import shutil
import sys

import lab_plans
import lab_plan_review
import lab_review_history
import lab_team_reply_browser
import private_session as privacy
import route_queue

SCHEMA = "lightup.private.original-lab-human-team-handoff.v1"
SLUGS = {
    "Security": "security",
    "Privacy": "privacy",
    "Client operations": "client-operations",
    "Platform": "platform",
}
STYLE = """:root{color-scheme:dark;background:#0e1f31;color:#ebf8ff;font:16px/1.6 system-ui}
body{max-width:980px;margin:2rem auto;padding:0 1.2rem}
header,section,footer{border:1px solid #51718a;background:#20384c;
padding:24px;margin:16px 0;border-radius:17px}
h1{font-size:clamp(1.7rem,4vw,2.7rem)}h2{font-size:1.3rem}
.warn{font-weight:750;color:#ffe0a7}b{color:#b9efd9}
li{padding:13px 0;border-bottom:1px solid #456278}
a{color:#c6eafe}a:focus-visible{outline:3px solid #ffe0a7}
pre{white-space:pre-wrap}small{color:#bad5e6}""".replace("b{", "b{", 1)


def _page(title: str, intro: str, rows: list[dict],
          links: list[tuple[str,str]] | None = None) -> bytes:
    esc = lambda val: html.escape(str(val), quote=True)
    digest = b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    items = []
    for row in rows:
        items.append(
            "<li><b>Original proposal #" + esc(row["proposal_slot"]) +
            "</b> · HUMAN stage: " + esc(row["human_stage"]) +
            " · HUMAN team: " + esc(row["human_team"] or "Unassigned") +
            "<br>PRIVATE HUMAN question: " +
            esc(row["human_question"] or "Not provided") + "</li>"
        )
    navigation = "".join(
        '<li><a rel="noopener noreferrer" href="' + esc(file) + '">' +
        esc(label) + "</a></li>" for label,file in (links or []))
    page = ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-""" +
        digest + """'; script-src 'none'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN Team Handoff</title><style>""" + STYLE +
        """</style></head><body><header><p class="warn">PRIVATE / ORIGINAL LAB /
HUMAN REVIEW_ONLY · DRAFT/HOLD</p><h1>""" + esc(title) +
        """</h1><p>""" + esc(intro) +
        """</p></header><section><h2>Manually assigned HUMAN tasks</h2><ol>""" +
        ("".join(items) or "<li>No HUMAN tasks assigned to this team.</li>") +
        """</ol></section>""" +
        ("<section><h2>Private operator directory</h2><ul>" +
         navigation + "</ul></section>" if links else "") +
        """<footer><p class="warn">NO ACTIVITY · NO SCAN · NO AUTHORITY</p>
<p>Original Lab Launchpad source admission and an original 0600 HUMAN FINAL
review were revalidated. This privately curated sheet contains only
manually assigned original packet positions and PRIVATE HUMAN questions;
it has no original lab URLs, paths, source SHA, credentials, real client
identities or proven security findings. Each file is for HUMAN review,
not a verified intended recipient or automatically delivered handoff.
Separate client/operator consent, at-use revocation, source-owner
and independent privacy/security/browser approval, exact-head CI and
explicit HUMAN GO remain required. Do not share outside a separately
approved PRIVATE channel.</p></footer></body></html>""")
    return page.encode("utf-8")


def _team_csv(rows: list[dict]) -> bytes:
    """Original source-bound HUMAN rows, only the selected team subset."""
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(lab_plan_review.COLUMNS)
    for row in rows:
        writer.writerow([row[key] for key in lab_plan_review.COLUMNS])
    return stream.getvalue().encode("utf-8")


def build(packets: list[str], final_room: str, parent: str,
          folder: str) -> Path:
    dest = lab_plans._new_path(parent, folder)
    original, fingerprint = lab_plan_review._source_rows(packets)
    final = lab_plans._packet(final_room)
    if final == dest or final in dest.parents:
        raise privacy.Hold("HOLD: do not write within an original HUMAN Lab room")
    # Re-open the unchanged original finalized HUMAN receipt, read native CSV,
    # re-admit against the *current* exact original Launchpad packet identities.
    rows = lab_review_history._admit_final(str(final), original, fingerprint)
    teams = {team: [row for row in rows if row["human_team"] == team]
             for team in SLUGS}
    unassigned = [row for row in rows if row["human_team"] == ""
                  and row["human_stage"] != "UNASSESSED"]
    manifests = [
        {"label": team, "filename": "TEAM-" + SLUGS[team] + ".html",
         "human_tasks": len(entries)}
        for team,entries in teams.items() if entries
    ]
    if unassigned:
        manifests.append({"label":"Unassigned HUMAN follow-up",
                          "filename":"TEAM-unassigned-operator-only.html",
                          "human_tasks":len(unassigned)})
    nav = []
    for item in manifests:
        nav.append((item["label"] + " (" + str(item["human_tasks"]) + ") · read-only",
                    item["filename"]))
        if item["label"] in SLUGS:
            nav.append((item["label"] + " · edit HUMAN response locally",
                        "TEAM-" + SLUGS[item["label"]] + "-EDITOR.html"))
    overview = {
        "schema":SCHEMA,"status":"REVIEW_ONLY","authority":privacy.AUTHORITY,
        "verified_source":False,"verified_consent":False,
        "recipients_authenticated":False,"automated_dispatch":False,
        "assessment_authorized":False,"original_lab_urls_included":False,
        "private_question_text_included":False,
        "original_source_fingerprint_sha256_unsigned":fingerprint,
        "original_final_human_csv_sha256_unsigned":sha256(
            lab_plan_review._csv(rows)).hexdigest(),
        "team_workrooms":manifests,
        "unassessed":sum(x["human_stage"]=="UNASSESSED" for x in rows),
        "unassigned_human":len(unassigned),
    }
    docs = [("OPEN-PRIVATE.html",
             _page("Lab HUMAN Team Handoff · local directory",
                   "Only authorized local owner may select and manually "
                   "inspect an individual team worklist. No recipient authenticated.",
                   [],nav)),
            ("PRIVATE-HUMAN-TEAM-MANIFEST.json",
             (json.dumps(overview,sort_keys=True,separators=(",",":"))+"\n").encode("ascii"))]
    for team,entries in teams.items():
        if entries:
            docs.append(("TEAM-"+SLUGS[team]+".html",
                _page("HUMAN Lab · "+team,"Only HUMAN tasks assigned to "+team+
                      " from original source-bound finalized review.",entries)))
            docs.append(("TEAM-"+SLUGS[team]+"-DRAFT.csv",_team_csv(entries)))
            docs.append(("TEAM-"+SLUGS[team]+"-EDITOR.html",
                         lab_team_reply_browser.render(team,entries)))
    if unassigned:
        docs.append(("TEAM-unassigned-operator-only-DRAFT.csv",_team_csv(unassigned)))
        docs.append(("TEAM-unassigned-operator-only.html",
                     _page("HUMAN Lab · unassigned operator-only",
                           "Assign a HUMAN team deliberately in a new original review round.",
                           unassigned)))
    dest.mkdir(mode=0o700)
    try:
        if not privacy.private(dest,True):
            raise privacy.Hold("HOLD: PRIVATE team workroom custody invalid")
        for filename,content in docs:
            privacy.private_write(dest,filename,content)
        fd=os.open(dest,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    except (OSError,ValueError):
        shutil.rmtree(dest)
        raise privacy.Hold("HOLD: original PRIVATE HUMAN team handoff incomplete") from None
    return dest/"OPEN-PRIVATE.html"


def main(argv: list[str]|None=None) -> int:
    cli=argparse.ArgumentParser(description="Offline original source-bound HUMAN team worklists; no send")
    cli.add_argument("--packet",action="append",required=True)
    cli.add_argument("--final-room",required=True)
    cli.add_argument("--private-parent",required=True)
    cli.add_argument("--folder",required=True)
    cli.add_argument("--human-confirm",required=True)
    options=cli.parse_args(argv)
    try:
        if options.human_confirm!="BUILD PRIVATE LAB TEAM HANDOFF":
            raise privacy.Hold("HOLD: explicit original HUMAN confirmation required")
        page=build(options.packet,options.final_room,
                   options.private_parent,options.folder)
        print("PRIVATE REVIEW_ONLY: original HUMAN team worklists prepared, NOT sent")
        print("OPEN LOCALLY: "+str(page))
        return 2
    except Exception as exc:
        print(str(exc) if isinstance(exc,privacy.Hold) else
              "HOLD: original Lab HUMAN team source invalid",file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
