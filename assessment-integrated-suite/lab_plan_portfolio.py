#!/usr/bin/env python3
"""PRIVATE 3-8 original owner-only Lab Launchpad proposals, source-bound.

No network, target execution, model, grant, fake time ordering or customer
identity. Reuses the ORIGINAL reopen/compare source owners for every packet.
"""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import html
import json
import os
from pathlib import Path
import shutil
import sys

import lab_plans
import private_session as privacy

SCHEMA = "lightup.private.original-lab-proposal-portfolio.v1"
MAX_PACKETS = 8


def _original_reader():
    for source in (str(lab_plans.SOURCE), str(lab_plans.REPO / "src")):
        if source not in sys.path:
            sys.path.insert(0, source)
    import compare as original_comparison
    return original_comparison


def _load(packets: list[str]) -> list[dict]:
    original = _original_reader()
    results = []
    seen = set()
    for name in packets:
        path = lab_plans._packet(name)
        # Exact immutable original source-owned reopen and read policies:
        # full private file hashes, scope rules, Studio membership, no-symlink,
        # canonical lab URLs, owner-only modes, no target/network contact.
        item = original._load(str(path))
        digest = item["manifest_sha256"]
        identity = (digest, item["studio_catalog_sha256"], item["studio_scenario_id"])
        if identity in seen:
            raise privacy.Hold("HOLD: same original lab packet declared twice")
        seen.add(identity)
        results.append(item)
    return results


def _render(snapshots: list[dict], transitions: list[dict]) -> bytes:
    def esc(x: object) -> str:
        return html.escape(str(x), quote=True)
    cards = []
    for index, record in enumerate(snapshots, 1):
        points = "".join(
            "<li><code>" + esc(url) + "</code></li>" for url in record["endpoints"]
        )
        cards.append(
            "<section><h2>Human-declared packet #" + str(index) + "</h2>" +
            "<p>" + str(len(record["endpoints"])) + " original-policy-admitted "
            "literal offline lab proposals · Studio source: " +
            ("PRESENT" if record["studio"] else "ABSENT") +
            "</p><details><summary>Show PRIVATE declared URLs</summary><ol>" +
            points + "</ol></details></section>"
        )
    movements = []
    for change in transitions:
        def list_urls(title: str, values: list[str]) -> str:
            return ("<h3>" + esc(title) + " · " + str(len(values)) +
                    "</h3><ul>" + "".join("<li><code>" + esc(url) +
                    "</code></li>" for url in values) + "</ul>")
        movements.append(
            "<section><h2>Proposals #" + str(change["from_position"]) +
            " → #" + str(change["to_position"]) + "</h2>" +
            "<p>Added: " + str(len(change["added"])) + " · Absent: " +
            str(len(change["absent"])) + " · Retained: " +
            str(len(change["retained"])) + " · Declared Studio revision differs: " +
            str(change["studio_revision_differs"]) + "</p><details><summary>"
            "Show literal PRIVATE source differences</summary>" +
            list_urls("Newly proposed", change["added"]) +
            list_urls("No longer proposed (NOT VERIFIED FIXED)", change["absent"]) +
            list_urls("Exactly retained", change["retained"]) +
            "</details></section>"
        )
    stylesheet = """
:root{color-scheme:dark;background:#101e31;color:#ecf5fd;font:16px/1.55 system-ui}
body{max-width:1120px;padding:20px;margin:auto}
header,section,footer{border:1px solid #456885;background:#1d334b;border-radius:17px;
padding:24px;margin:16px 0}h1{font-size:clamp(1.8rem,4vw,3rem);margin:0}
.warn{color:#ffe0a8;font-weight:bold}
section h2{color:#beeede;font-size:1.25rem}code{overflow-wrap:anywhere;color:#d6edff}
details{margin:10px 0}summary{cursor:pointer;color:#bce6ff}
li{padding:8px 0;border-bottom:1px solid #405b73}
:focus-visible{outline:3px solid #ffe0a8}
"""
    csp_hash = b64encode(sha256(stylesheet.encode("utf-8")).digest()).decode("ascii")
    page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'sha256-' + csp_hash + '\'; script-src \'none\'; connect-src '
        '\'none\'; img-src \'none\'; base-uri \'none\'; form-action \'none\'">'
        '<title>LightUp / PRIVATE original lab proposal portfolio</title><style>' +
        stylesheet + '</style></head><body><header><p class="warn">LIGHTUP · '
        'INCUBATE M3/M7 · PRIVATE LAB PLAN · DRAFT/HOLD</p>'
        '<h1>Original Lab Proposal Portfolio</h1><p>' + str(len(snapshots)) +
        ' separately selected owner-private packets · ' + str(len(transitions)) +
        ' consecutive HUMAN comparisons. No real chronology is verified.</p>'
        '<p>These are original SOURCE-ADMITTED *planning inputs*, not successful '
        'assessments, authenticated clients, grants or approved scope.</p></header>'
        '<section><h2>Original PRIVATE source proposals</h2>'
        '<p>Each packet was re-opened under its ORIGINAL source owner rules, '
        'including literal isolated IP policy. Details contain PRIVATE URLs.</p>'
        '</section>' + "".join(cards) +
        '<section><h2>Declared proposal differences</h2><p>An endpoint absent '
        'from a later selected plan does NOT prove a security fix, asset removal '
        'or revocation. An added URL is not permission to assess.</p></section>' +
        "".join(movements) +
        '<footer><p class="warn">REVIEW_ONLY · NO AUTHORITY · NO SCAN</p>'
        '<p>Original owner-private numeric lab URLs and unsigned digests must '
        'remain within this 0700/0600 room. No automatic scans, DNS, models, '
        'network, grants, release, notifications or findings. CI, source-owner '
        'security/privacy review, at-use revocation, authentic separate client '
        'and operator consent and explicit HUMAN GO remain mandatory.</p>'
        '</footer></body></html>'
    )
    return page.encode("utf-8")


def build(packets: list[str], parent: str, folder: str) -> Path:
    if type(packets) is not list or not 3 <= len(packets) <= MAX_PACKETS:
        raise privacy.Hold("HOLD: select 3–8 original private Lab Launchpad packets")
    if any(type(item) is not str for item in packets):
        raise privacy.Hold("HOLD: original private packet paths must be strings")
    dest = lab_plans._new_path(parent, folder)
    originals = [lab_plans._packet(name) for name in packets]
    if len(set(originals)) != len(originals):
        raise privacy.Hold("HOLD: original private packet appears more than once")
    if any(item == dest or item in dest.parents for item in originals):
        raise privacy.Hold("HOLD: cannot publish inside original private packet")
    snapshots = _load(packets)
    differences = []
    for index in range(1, len(snapshots)):
        old, new = snapshots[index-1], snapshots[index]
        old_set, new_set = set(old["endpoints"]), set(new["endpoints"])
        differences.append({
            "from_position": index,
            "to_position": index + 1,
            "added": [u for u in new["endpoints"] if u not in old_set],
            "absent": [u for u in old["endpoints"] if u not in new_set],
            "retained": [u for u in new["endpoints"] if u in old_set],
            "studio_revision_differs": (old["studio_catalog_sha256"],
                                        old["studio_scenario_id"]) != (
                                            new["studio_catalog_sha256"],
                                            new["studio_scenario_id"]),
        })
    aggregate = {
        "schema": SCHEMA, "status": "DRAFT_HOLD",
        "source_authenticity_verified": False, "consent_verified": False,
        "grant_issued": False, "may_assess": False, "revisions_authenticated": False,
        "operator_declared_order": True,
        "source_names_or_addresses_included": False,
        "snapshots": [
            {"position": i, "endpoint_count": len(record["endpoints"]),
             "studio_draft_present": bool(record["studio"])}
            for i, record in enumerate(snapshots, 1)],
        "changes": [
            {"from_position": c["from_position"], "to_position": c["to_position"],
             "added_count": len(c["added"]), "absent_count": len(c["absent"]),
             "retained_count": len(c["retained"]),
             "studio_revision_differs": c["studio_revision_differs"]}
            for c in differences
        ],
    }
    private = {
        "schema": SCHEMA, "status": "DRAFT_HOLD",
        "authority": privacy.AUTHORITY,
        "source_authenticity_verified": False, "operator_declared_order": True,
        "snapshots": [
            {"position": i, "private_unsigned_source_sha256": data["manifest_sha256"],
             "private_endpoints": data["endpoints"],
             "private_studio_scenario": data["studio_scenario_id"]}
            for i, data in enumerate(snapshots, 1)
        ],
        "changes": differences,
    }
    documents = (
        ("OPEN-PRIVATE.html", _render(snapshots, differences)),
        ("PRIVATE-LAB-PROPOSALS.json", (json.dumps(private, sort_keys=True,
             ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")),
        ("PRIVATE-ANONYMOUS-COUNTS.json", (json.dumps(aggregate, sort_keys=True,
             ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")),
    )
    dest.mkdir(mode=0o700)
    try:
        if not privacy.private(dest, True):
            raise privacy.Hold("HOLD: new Lab Portfolio is not owner-private")
        for name, payload in documents:
            privacy.private_write(dest, name, payload)
        fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(dest)
        raise privacy.Hold("HOLD: original PRIVATE Lab Portfolio was not published") from None
    return dest / "OPEN-PRIVATE.html"
