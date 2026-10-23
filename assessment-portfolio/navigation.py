#!/usr/bin/env python3
"""Offline assessment human workspace: one navigable private start page.

No external assets, scripts, credentials, remote operations or permissions.
"""
from __future__ import annotations
from base64 import b64encode
from hashlib import sha256
from html import escape

from portfolio import Hold

STYLE = """
:root{font:16px/1.5 system-ui,sans-serif;color-scheme:dark;background:#091828;color:#eaf8ff}
*{box-sizing:border-box}body{max-width:1230px;margin:auto;padding:28px}
header{padding:36px;border:1px solid #386b80;border-radius:24px;background:linear-gradient(128deg,#144962,#14283e)}
header p{max-width:78ch}small{letter-spacing:.17em;color:#a6eed5;font-weight:800}
h1{font-size:clamp(2rem,6vw,3.8rem);line-height:1.1}h2{margin:0 0 9px}p{color:#bcd4e1}
.state{color:#ffe0a3;font-weight:900}nav{display:grid;grid-template-columns:1fr 1fr;gap:17px;margin:23px 0}
.card{border-radius:16px;border:1px solid #3a647a;background:#132e44;padding:22px}
.card a{display:inline-block;color:#0c2430;background:#a4ead2;border-radius:10px;padding:10px 16px;font-weight:800;text-decoration:none}
.card a:focus-visible{outline:3px solid #f8d79a}.card p{min-height:48px}
mark{background:#d6e6be;color:#13273c;padding:2px 8px;border-radius:5px}ol li{margin:10px 0}
.note{background:#302d39;border-left:4px solid #f0cf8e;padding:20px;border-radius:8px}
footer{margin:20px 0;color:#a4c3d5}
@media(max-width:800px){body{padding:14px}nav{display:block}.card{margin:15px 0}}
@media print{body,header,.card,.note{background:white;color:black}p{color:black}}
"""

def build(summary):
    if (type(summary) is not dict
            or summary.get("claimed_status") not in ("HOLD", "REVIEW_ONLY")
            or type(summary.get("agenda_count")) is not int
            or not 1 <= summary["agenda_count"] <= 12
            or type(summary.get("human_item_count")) is not int
            or not 1 <= summary["human_item_count"] <= 768):
        raise Hold("unrecognized private human portfolio summary")
    digest=b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    items=[
        ("1 · Portfolio overview", "Open the original-source human attention queue; original HOLD remains visible.",
         "index.html","Open queue"),
        ("2 · Cross-agenda human review", "Edit human notes and proposed dates across all original agendas, then download one private proposal bundle.",
         "original-human-review-studio.html","Review all agendas"),
        ("3 · Hypothetical role capacity", "Model optional neutral human-role work capacity without actual assignments or outcome claims.",
         "interactive-capacity-studio.html","Open capacity studio"),
        ("4 · Aggregate-only summary", "Inspect source-neutral totals before a separately reviewed anonymous handoff.",
         "aggregate.html","View totals"),
        ("5 · Independent human collaboration", "Combine independently reviewed human proposal bundles without overlapping source changes, or resolve conflicts in an offline human Studio.",
         "collaboration-guide.html","Open collaboration guide"),
    ]
    cards="".join(
        "<section class='card'><h2>"+escape(title)+"</h2><p>"+escape(description)+
        "</p><a href='"+link+"'>"+escape(label)+"</a></section>"
        for title,description,link,label in items)
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'sha256-"+digest+"'; img-src 'none'; script-src 'none'; "
            "connect-src 'none'; form-action 'none'; object-src 'none'; base-uri 'none'\">"
            "<title>LightUp · Offline human workspace</title><style>"+STYLE+"</style></head><body>"
            "<header><small>LIGHTUP / ASSESSMENT RUNTIME / PRIVATE OFFLINE</small>"
            "<h1>Your next human review, in one place.</h1>"
            "<p>Original source-neutral planning for <strong>"+str(summary["agenda_count"])+
            " agendas</strong> and <strong>"+str(summary["human_item_count"])+
            " human items</strong>. This is a private handoff, not an assessment execution.</p>"
            "<p class='state'>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "+
            escape(summary["claimed_status"])+" · NO GO</p></header>"
            "<nav aria-label='Offline human workflow'>"+cards+"</nav>"
            "<section class='card'><h2>Return your changes to the original human records</h2>"
            "<ol><li>Open <strong>Cross-agenda human review</strong> and edit only human planning fields.</li>"
            "<li>Explicitly acknowledge and export the single PRIVATE all-agenda proposal JSON.</li>"
            "<li>Keep this ZIP and the ORIGINAL separately held original manifest/choices files.</li>"
            "<li>An operator runs <code>assessment-portfolio/review_cycle.py</code> with the original ZIP, "
            "original manifests, original choices, exported <code>--proposal-bundle</code>, "
            "and explicit <code>--next-as-of</code> to create a NEW private workspace ZIP.</li>"
            "<li>Open the next ZIP's <code>workspace-home.html</code>. Nothing replaces a previous source.</li></ol>"
            "<p><mark>Private data:</mark> Never share original-private-agenda JSON, "
            "private-source-bindings.json or private-original-source-map.json as aggregates. "
            "The aggregate.html/json/csv files carry only counts, but small cohort counts still need review.</p></section>"
            "<aside class='note'><strong>Original data and permissions never change here.</strong>"
            "<p>Original unsigned hashes correlate bytes; they do not authenticate source, "
            "client/operator identity, evidence, a remediation or consent. Proposed human review dates "
            "are not deadlines. Missing rows never mean fixed findings. Actual scans, grants, "
            "actions and release still require original authenticated client/operator consent, "
            "revocation at use, original exact-head hosted/named VPS CI, source-owner and independent "
            "privacy/security review, and explicit HUMAN GO.</p></aside>"
            "<footer>Standalone scriptless local navigation · no remote links, cookies, browser storage, "
            "script execution, permissions, scanners or target requests.</footer></body></html>").encode("utf-8")
