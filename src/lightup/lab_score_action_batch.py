"""Bounded multi-pair original-source HUMAN follow-up, never verification or grant.

The supplied source/action envelope must already come from both independently
rechecked synthetic original ZIPs. The selector cannot discover other pairs.
"""
from __future__ import annotations

import csv
import io
import json
import re

from .lab_score_action_admission import admit_human_actions
from .lab_score_portable_html_safety import admit_inert_html

_TOKEN = re.compile(r"(baseline|candidate):([1-8])-([1-8])", re.ASCII)
_ACTION = {
    "evidence_reused": "Recapture independent first-party synthetic originals",
    "score_drift": "Review isolated synthetic scorer drift",
}
_HUMAN = ("Independent HUMAN source/security/privacy review, identity and "
          "separate authenticated consent remain mandatory.")


def select_all_original_holds(data: dict) -> str:
    """Select EVERY distinct original synthetic HOLD pair or refuse in full.

    Never silently truncate or infer a cross-ZIP identity. The resulting
    canonical explicit selector is stored in private rooms, not the ALL alias.
    """
    rows = admit_human_actions(data)
    if data["review_status"] != "HOLD":
        raise ValueError("no original HUMAN HOLD pairs to select")
    found: set[tuple[str, int, int]] = set()
    selection: list[str] = []
    for row in rows[:-1]:
        key = (row["transport"], row["anonymous_previous"], row["anonymous_current"])
        if key not in found:
            found.add(key)
            selection.append(f"{key[0]}:{key[1]}-{key[2]}")
            if len(selection) > 16:
                raise ValueError("original HUMAN HOLD batch exceeds 16 pairs; no partial selection")
    result = ",".join(selection)
    if not result or len(result) > 256:
        raise ValueError("original HUMAN HOLD selection unavailable or oversized")
    return result


def render_human_batch(data: dict, selection: str, fmt: str) -> str:
    """Select 1..16 distinct original HOLD pairs, reordered to source queue."""
    rows = admit_human_actions(data)
    if selection == "ALL":
        selection = select_all_original_holds(data)
    if (type(selection) is not str or not 1 <= len(selection) <= 256
            or not selection.isascii() or data["review_status"] != "HOLD"):
        raise ValueError("untrusted original HUMAN batch selection")
    tokens = selection.split(",")
    if not 1 <= len(tokens) <= 16:
        raise ValueError("unbounded HUMAN selection")
    requested = set()
    for token in tokens:
        match = _TOKEN.fullmatch(token)
        if match is None:
            raise ValueError("invalid source-local HOLD selector")
        source, previous, current = match.groups()
        p, c = int(previous), int(current)
        key = (source, p, c)
        if p >= c or key in requested:
            raise ValueError("duplicate or backwards original HOLD pair")
        requested.add(key)
    selected: dict[tuple[str, int, int], list[str]] = {}
    for row in rows[:-1]:
        key = (row["transport"], row["anonymous_previous"], row["anonymous_current"])
        if key in requested:
            selected.setdefault(key, []).append(row["reason"])
    if set(selected) != requested:
        raise ValueError("requested original pair has no admitted HOLD")
    packet = {
        "schema": "lightup.lab-score-human-multi-pair-selection.v1",
        "global_review_status": "HOLD",
        "selected_original_pairs": [{
            "source": source, "anonymous_previous": previous,
            "anonymous_current": current,
            "hold_reasons": reasons,
            "human_actions": [_ACTION[reason] for reason in reasons],
            "completion": "NOT_VERIFIED",
        } for (source, previous, current), reasons in selected.items()],
        "original_unsigned_transport_sha256": {
            key: data["unsigned_transport_sha256"][key]
            for key in ("baseline", "candidate")
        },
        "selected_pair_count": len(selected),
        "other_original_pairs_hidden": True,
        "original_source_authenticated": False,
        "same_originals_proven": False,
        "authorization_granted": False,
        "remediation_verified": False,
        "deployment": False,
        "human_review_only": True,
    }
    if fmt == "actions-batch-json":
        output = json.dumps(packet, sort_keys=True, allow_nan=False) + "\n"
    elif fmt == "actions-batch-csv":
        # All CSV cells originate from admitted enums or bounded integer ordinals.
        # No source paths, external identities or spreadsheet formulas.
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(("source", "anonymous_previous", "anonymous_current",
                         "hold_reason", "human_followup", "completion",
                         "global_review_status", "authorization_granted",
                         "original_source_authenticated", "other_original_pairs_hidden"))
        for item in packet["selected_original_pairs"]:
            for reason in item["hold_reasons"]:
                writer.writerow((item["source"], item["anonymous_previous"],
                                 item["anonymous_current"], reason, _ACTION[reason],
                                 "NOT_VERIFIED", "HOLD", "false", "false", "true"))
        output = buffer.getvalue()
    elif fmt == "actions-batch-markdown":
        output = ("# LightUp offline synthetic HUMAN selected HOLD pairs\n\n"
                  "**GLOBAL STATUS HOLD — NOT VERIFIED / NOT AUTHORIZED**\n\n"
                  "Selected pair ordinals only; no cross-ZIP identity matching.\n\n")
        for item in packet["selected_original_pairs"]:
            output += (f"## {item['source']} anonymous "
                       f"{item['anonymous_previous']}-{item['anonymous_current']}\n\n")
            output += "".join(f"- [ ] {_ACTION[reason]} — NOT_VERIFIED\n"
                              for reason in item["hold_reasons"])
            output += "\n"
        output += ("All other original pairs are intentionally hidden; their "
                   "HOLD status cannot be cleared here.\n\n" + _HUMAN
                   + "\nNo scans, grants, research or release.\n")
    elif fmt == "actions-batch-html":
        items = "".join(
            f"<section><h2>{item['source']} original anonymous "
            f"{item['anonymous_previous']}-{item['anonymous_current']}</h2>"
            "<ul>" + "".join(
                f"<li>{_ACTION[reason]} — <strong>NOT_VERIFIED</strong></li>"
                for reason in item["hold_reasons"]) + "</ul></section>"
            for item in packet["selected_original_pairs"]
        )
        output = (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' "
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>LightUp selected original HUMAN HOLD pairs</title>"
            "<style>body{font:1rem/1.5 system-ui;max-width:60rem;margin:2rem auto;"
            "padding:0 1rem}section{border:1px solid;padding:1rem;margin:1rem 0}"
            "@media print{section{break-inside:avoid}}</style></head><body><main>"
            "<h1>Offline synthetic source-local HUMAN selected HOLD pairs</h1>"
            "<p><strong>GLOBAL STATUS HOLD — NOT VERIFIED / NOT AUTHORIZED.</strong></p>"
            "<p>Only selected original source-local HOLD pairs are displayed. "
            "Anonymous pairs do not identify matching original ZIP sources.</p>"
            + items +
            "<p>Other original pairs intentionally hidden; their HOLD is not "
            "cleared by this view.</p><p>" + _HUMAN +
            " No scans, grants, research or release.</p></main></body></html>"
        )
        admit_inert_html(output.encode("utf-8"))
    else:
        raise ValueError("invalid HUMAN batch output format")
    if not 0 < len(output.encode("utf-8")) <= 65536:
        raise ValueError("oversized selected HUMAN packet")
    return output
