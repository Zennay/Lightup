#!/usr/bin/env python3
"""PRIVATE original-bound HUMAN follow-up register from one encrypted reply.

Never imports original finding/case identity or verified security severity.
Displays HUMAN questions/next steps in explicit local categories; does not
call any API, scanner, grant service or send an external message.
"""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import sys

import reply

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

def grouped(original: dict, rows: list[dict], key: str) -> tuple[list[dict], dict]:
    require(type(rows) is list and len(rows) == len(original["items"]),
            "Cannot create incomplete PRIVATE HUMAN follow-up from original source")
    selected: list[dict] = []
    counts = {label: 0 for label, _ in STEPS.values()}
    for ordinal, (base, human) in enumerate(zip(original["items"], rows), 1):
        kind, heading = STEPS[human["status"]]
        counts[kind] += 1
        selected.append({
            "ordinal": ordinal,
            "source_redacted_reason": base["reason"],
            "source_redacted_original_sha256": key,
            "human_followup_category": kind,
            "human_category_warning": heading,
            "original_human_requested_action": base["next_action"],
            "new_human_question": human["question"],
            "human_self_declared_answer": human["answer"],
            "human_self_declared_stage": human["status"],
        })
    selected.sort(key=lambda row: (row["human_followup_category"], row["ordinal"]))
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
    fragments.extend(['</tbody></table>',
                      '<p>These totals are ORIGINAL SELECTED HUMAN reason groups, ',
                      'not distinct client cases or findings. All answered entries ',
                      'remain HUMAN-only and unverified.</p></section>'])
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
            '</dl><small>Local original order only; no authenticated person, ',
            'chronology, case, consent or technical remediation.</small></article>'
        ])
    if previous_category is not None:
        fragments.append('</section>')
    fragments.append('<p>Private static offline reading copy. It cannot approve or execute actions.</p></main></body></html>')
    raw = "".join(fragments).encode("utf-8")
    require(len(raw) <= 2_000_000, "PRIVATE HUMAN follow-up HTML exceeds bounded size")
    return raw

def publish(handoff: Path, saved_reply: Path, output: Path) -> None:
    require(handoff.is_absolute() and saved_reply.is_absolute()
            and handoff != saved_reply and
            output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose original separate encrypted HUMAN inputs and fresh PRIVATE destination")
    for path in (handoff, saved_reply):
        require(path != output and path.parent != output
                and output not in path.parents and path not in output.parents,
                "Source-free HUMAN input/output folders cannot overlap")
    source, key, exact_source = reply.source(handoff)
    rows, exact_reply = reply.admitted_reply(saved_reply, source, key)
    items, counters = grouped(source, rows, key)
    report = html_page(items, counters)
    private_json = reply.schedule.canonical({
        "kind": KIND, "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "source_redacted_original_sha256": key,
        "source_redacted_selected_human_groups": len(items),
        "human_followup_items": items,
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
        "warning": WARNING,
    })
    require(reply.encrypted_cockpit.private_envelope(handoff) == exact_source
            and reply.schedule_vault.private_vault(saved_reply) == exact_reply,
            "Original source-free HUMAN handoff or reply changed before private report")
    reply.exclusive_output(output, [handoff, saved_reply], {
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
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh absolute owner-private HUMAN follow-up output")
    args = parser.parse_args()
    try:
        publish(args.handoff, args.reply, args.output_dir)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError,
            KeyError, TypeError, ImportError, UnicodeError,
            RuntimeError, OverflowError) as exc:
        print("HOLD: PRIVATE HUMAN follow-up register: " + str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
