#!/usr/bin/env python3
"""PRIVATE original-bound HUMAN follow-up register from one encrypted reply.

Never imports original finding/case identity or verified security severity.
Displays HUMAN questions/next steps in explicit local categories; does not
call any API, scanner, grant service or send an external message.
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import sys

import reply
import install
import reconcile

KIND = "lightup.private_selected_human_followup_register.v1"
WARNING = (
    "PRIVATE HUMAN-only self-declared follow-up register. Original selected "
    "source-free counts/reason labels and tentative HUMAN notes are NOT verified "
    "findings, distinct cases, verified remediation, actual source/sender "
    "identity, authenticated client/operator consent, release or HUMAN GO. "
    "INCUBATE M3/M7 DRAFT/HOLD."
)
STEPS = {
    "need_clarification_human": (
        "01_ASK_HUMAN_CLARIFICATION",
        "HUMAN clarification requested, NOT validated finding",
    ),
    "received_human": (
        "02_AWAIT_HUMAN_RESPONSE",
        "Received HUMAN only, not resolved",
    ),
    "working_human": (
        "03_HUMAN_DISCUSSION_OPEN",
        "HUMAN-only discussion ongoing, not a verified repair",
    ),
    "declined_human": (
        "04_HUMAN_REQUEST_DECLINED",
        "Declined HUMAN request; separate human routing decision needed",
    ),
    "answered_human_only": (
        "05_HUMAN_ANSWERED_NOT_VERIFIED",
        "HUMAN answered; NOT a verified fix, retest, finding or approval",
    ),
}
STYLE = """
body{font:16px/1.55 system-ui,sans-serif;background:#f1f5fa;color:#1a3149;margin:0}
main{max-width:1060px;margin:0 auto;padding:1.5rem}
section,article,aside{background:white;border:1px solid #c5d3e3;padding:1rem 1.25rem;border-radius:10px;margin:1rem 0}
aside{border-left:6px solid #ab7e2c}article{break-inside:avoid}
h1{font-size:1.8rem}h2{font-size:1.2rem}
dt{font-weight:bold}dd{margin:0 0 .8rem;white-space:pre-wrap;overflow-wrap:anywhere}
small{color:#47617d}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.6rem;border-bottom:1px solid #c9d5e5}
@media print{body{background:white}article{page-break-inside:avoid}}
"""

def require(ok: bool, reason: str) -> None:
    reply.require(ok, reason)

def esc(text: object) -> str:
    return html.escape(str(text), quote=True)

def source_bound_differences(matrix_file: Path, original: dict, key: str) -> tuple[list[bool], bytes]:
    """Native read of an existing PRIVATE multi-reply comparison, never an authority source."""
    raw = reply.schedule_vault.private_vault(matrix_file)
    require(100 <= len(raw) <= 3_000_000,
            "PRIVATE earlier HUMAN comparison outside bounded size")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=install.pairs,
                         parse_constant=lambda x: (_ for _ in ()).throw(
                             ValueError("Nonfinite PRIVATE HUMAN matrix field")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise reply.single_review.review.Hold(
            "Noncanonical PRIVATE original-bound HUMAN comparison") from exc
    require(type(doc) is dict and raw == reply.schedule.canonical(doc)
            and set(doc) == {
                "kind", "version", "disposition", "authority_granted",
                "consent_verified", "source_authenticated", "remediation_verified",
                "independent_reviewer_count_verified",
                "original_selected_redacted_sha256", "selected_human_rows",
                "warning"
            } and doc["kind"] == "lightup.private_human_selected_reply_matrix.v1"
            and type(doc["version"]) is int and doc["version"] == 1
            and doc["disposition"] == "PRIVATE_HUMAN_ONLY_DRAFT_HOLD"
            and all(doc[k] is False for k in (
                "authority_granted", "consent_verified", "source_authenticated",
                "remediation_verified", "independent_reviewer_count_verified"))
            and doc["original_selected_redacted_sha256"] == key
            and doc["warning"] == reconcile.WARNING,
            "Wrong prior HUMAN comparison/original selection or raised authority")
    entries = doc["selected_human_rows"]
    require(type(entries) is list and len(entries) == len(original["items"]),
            "Incomplete or reordered source-redacted HUMAN original task matrix")
    differences: list[bool] = []
    expected_file_count = None
    for ordinal, (record, expected) in enumerate(zip(entries, original["items"]), 1):
        require(type(record) is dict and set(record) == {
            "ordinal", "redacted_human_reason", "unverified_reply_file_slots"
        } and type(record["ordinal"]) is int and record["ordinal"] == ordinal
                and record["redacted_human_reason"] == expected["reason"],
                "Private HUMAN comparison ordinal/reason changed")
        slots = record["unverified_reply_file_slots"]
        require(type(slots) is list and 2 <= len(slots) <= 8,
                "Incomplete previous HUMAN response file slots")
        if expected_file_count is None:
            expected_file_count = len(slots)
        require(len(slots) == expected_file_count,
                "Earlier HUMAN comparison cannot vary original file slots")
        for index, slot in enumerate(slots, 1):
            require(type(slot) is dict and set(slot) == {
                "slot", "human_status", "human_answer", "human_question"
            } and type(slot["slot"]) is int and slot["slot"] == index
                    and type(slot["human_status"]) is str
                    and slot["human_status"] in reply.STAGES
                    and reply.schedule_vault.local_text(slot["human_answer"], 240, 960, True)
                    and reply.schedule_vault.local_text(slot["human_question"], 240, 960, True)
                    and (slot["human_status"] != "answered_human_only" or
                         slot["human_answer"].strip())
                    and (slot["human_status"] != "need_clarification_human" or
                         slot["human_question"].strip()),
                    "Unsafe/misordered PRIVATE earlier HUMAN response data")
        differences.append(any(len({slot[field] for slot in slots}) > 1 for field in (
            "human_status", "human_answer", "human_question")))
    return differences, raw

def grouped(original: dict, rows: list[dict], key: str,
            previous_differences: list[bool] | None = None) -> tuple[list[dict], dict]:
    require(type(rows) is list and len(rows) == len(original["items"]),
            "Cannot create incomplete PRIVATE HUMAN follow-up from original source")
    selected: list[dict] = []
    counts = {label: 0 for label, _ in STEPS.values()}
    require(previous_differences is None or len(previous_differences) == len(rows),
            "Incomplete original-bound prior HUMAN response difference membership")
    for ordinal, (base, human) in enumerate(zip(original["items"], rows), 1):
        kind, heading = STEPS[human["status"]]
        counts[kind] += 1
        selected.append({
            "ordinal": ordinal,
            "source_redacted_reason": base["reason"],
            "human_followup_category": kind,
            "human_category_warning": heading,
            "original_human_requested_action": base["next_action"],
            "new_human_question": human["question"],
            "human_self_declared_answer": human["answer"],
            "human_self_declared_stage": human["status"],
            "earlier_human_reply_files_differed":
                previous_differences[ordinal - 1] if previous_differences is not None else None,
        })
    # Within each HUMAN-only follow-up group, surface original-selected
    # reason groups with literal differences in prior encrypted reply files
    # first. The original human stage never becomes a verified severity.
    selected.sort(key=lambda row: (
        row["human_followup_category"],
        0 if row["earlier_human_reply_files_differed"] is True else 1,
        row["ordinal"]
    ))
    return selected, counts

def html_page(rows: list[dict], counts: dict) -> bytes:
    fragments = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; ',
        'script-src \'none\'; connect-src \'none\'; img-src \'none\'; ',
        'style-src ', reply.hash_csp(STYLE.encode("utf-8")), '; ',
        'object-src \'none\'; base-uri \'none\'; form-action \'none\'">',
        '<title>LightUp PRIVATE HUMAN-only follow-up register</title><style>',
        STYLE, '</style></head><body><main>',
        '<h1>PRIVATE source-redacted HUMAN follow-up register</h1>',
        '<aside><strong>INCUBATE · DRAFT/HOLD · HUMAN ONLY</strong><p>',
        esc(WARNING),
        '</p><p>Source-free labels are NOT original client cases. ',
        'A HUMAN answer does not establish remediation, a retest, a grant ',
        'or any authenticated permission. No automatic owner assignment, ',
        'closure, release, notification or scanning.</p></aside>',
        '<section><h2>HUMAN action overview</h2><table>',
        '<thead><tr><th>Human category</th><th>Original reason groups</th></tr></thead><tbody>',
    ]
    for kind, warning in STEPS.values():
        fragments.extend(['<tr><td>', esc(warning), '</td><td>',
                          str(counts[kind]), '</td></tr>'])
    differed = sum(row["earlier_human_reply_files_differed"] is True
                   for row in rows)
    supplied = any(row["earlier_human_reply_files_differed"] is not None
                   for row in rows)
    fragments.extend(['</tbody></table>',
                      '<p>These totals are ORIGINAL SELECTED HUMAN reason groups, ',
                      'not distinct client cases or findings. All answered entries ',
                      'remain HUMAN-only and unverified.</p>',
                      '<p>Prior locally observed literal HUMAN reply differences: ',
                      str(differed) if supplied else 'UNKNOWN (no earlier comparison supplied)',
                      '. This does not establish number of humans or security severity. ',
                      'When provided, groups with earlier differences appear first ',
                      'within each HUMAN follow-up category.</p></section>'])
    previous_category = None
    for row in rows:
        kind = row["human_followup_category"]
        if kind != previous_category:
            if previous_category is not None:
                fragments.append('</section>')
            fragments.extend(['<section><h2>',
                              esc(row["human_category_warning"]),
                              '</h2>'])
            previous_category = kind
        fragments.extend([
            '<article><h3>Original selected HUMAN reason group ',
            str(row["ordinal"]), '</h3><dl>',
            '<dt>Source-redacted original category</dt><dd>',
            esc(row["source_redacted_reason"]), '</dd>',
            '<dt>Originally self-declared HUMAN next action</dt><dd>',
            esc(row["original_human_requested_action"] or "Not declared"), '</dd>',
            '<dt>New self-declared HUMAN clarification question</dt><dd>',
            esc(row["new_human_question"] or "Not recorded"), '</dd>',
            '<dt>Self-declared HUMAN answer (never a verified fix)</dt><dd>',
            esc(row["human_self_declared_answer"] or "Not recorded"), '</dd>',
            '<dt>Earlier local HUMAN encrypted reply comparison</dt><dd>',
            ('LITERAL DIFFERENCES IN EARLIER HUMAN FILES — follow up manually'
             if row["earlier_human_reply_files_differed"] is True else
             'Prior HUMAN file text literally matches (NOT consensus)'
             if row["earlier_human_reply_files_differed"] is False else
             'No earlier private HUMAN comparison supplied'),
            '</dd>',
            '</dl><small>Local original order only; no authenticated person, ',
            'chronology, case, consent or technical remediation.</small></article>'
        ])
    if previous_category is not None:
        fragments.append('</section>')
    fragments.append('<p>Private static offline reading copy. It cannot approve or execute actions.</p></main></body></html>')
    raw = "".join(fragments).encode("utf-8")
    require(len(raw) <= 2_000_000, "PRIVATE HUMAN follow-up HTML exceeds bounded size")
    return raw

def publish(handoff: Path, saved_reply: Path, output: Path,
            comparison: Path | None = None) -> None:
    require(handoff.is_absolute() and saved_reply.is_absolute()
            and handoff != saved_reply and
            output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose original separate encrypted HUMAN inputs and fresh PRIVATE destination")
    if comparison is not None:
        require(comparison.is_absolute() and
                comparison not in (handoff, saved_reply, output),
                "Previous PRIVATE HUMAN comparison must be a distinct absolute file")
    for path in (handoff, saved_reply, *([comparison] if comparison else [])):
        require(path != output and path.parent != output
                and output not in path.parents and path not in output.parents,
                "Source-free HUMAN input/output folders cannot overlap")
    source, key, exact_source = reply.source(handoff)
    rows, exact_reply = reply.admitted_reply(saved_reply, source, key)
    differences, prior_exact = (
        source_bound_differences(comparison, source, key) if comparison else (None, None)
    )
    items, counters = grouped(source, rows, key, differences)
    report = html_page(items, counters)
    private_json = reply.schedule.canonical({
        "kind": KIND, "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "source_redacted_original_sha256": key,
        "source_redacted_selected_human_groups": len(items),
        "human_followup_items": items,
        "earlier_private_comparison_supplied": differences is not None,
        "warning": WARNING,
    })
    require(len(private_json) <= 2_000_000,
            "PRIVATE HUMAN follow-up machine-readable document exceeds bounded size")
    public_misnomer_avoided = reply.schedule.canonical({
        "kind": "lightup.private_human_followup_aggregate.v1",
        "disposition": "HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "groups_not_unique_cases": len(items),
        "private_human_stage_groups": counters,
        "earlier_human_file_difference_groups":
            sum(differences) if differences is not None else None,
        "warning": WARNING,
    })
    require(reply.encrypted_cockpit.private_envelope(handoff) == exact_source
            and reply.schedule_vault.private_vault(saved_reply) == exact_reply
            and (comparison is None or
                 reply.schedule_vault.private_vault(comparison) == prior_exact),
            "Original source-free HUMAN handoff, reply or matrix changed before private report")
    reply.exclusive_output(output, [handoff, saved_reply,
                                    *([comparison] if comparison else [])], {
        "index.html": report,
        "private-human-followup.json": private_json,
        "private-aggregate.json": public_misnomer_avoided,
        "README.txt": (
            WARNING + "\nindex.html and private-human-followup.json contain "
            "PRIVATE human questions, answers and original requested action "
            "text in PLAINTEXT. The aggregate is also PRIVATE: small counts "
            "may identify people or groups. No upload, automatic closure, "
            "email, verified source, grant, consent or remediation.\n"
        ).encode("utf-8"),
    })
    print("REVIEW_ONLY: PRIVATE HUMAN follow-up register:", output / "index.html")
    print("Source-redacted HUMAN groups:", len(items), "; no original case identity.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True,
                        help="Exact original PRIVATE selected encrypted .luhq")
    parser.add_argument("--reply", type=Path, required=True,
                        help="Existing source-bound encrypted .luhr HUMAN reply")
    parser.add_argument("--comparison", type=Path,
                        help="Optional EXACT original-bound PRIVATE comparison JSON from "
                             "reconcile.py (never authenticates independent humans)")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh absolute owner-private HUMAN follow-up output")
    args = parser.parse_args()
    try:
        publish(args.handoff, args.reply, args.output_dir, args.comparison)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError,
            KeyError, TypeError, ImportError, UnicodeError,
            RuntimeError, OverflowError) as exc:
        print("HOLD: PRIVATE HUMAN follow-up register: " + str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
