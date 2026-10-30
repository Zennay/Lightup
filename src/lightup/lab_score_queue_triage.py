"""Source-free synthetic HUMAN queue worksheet. Never grants authority."""
from __future__ import annotations
import re
from typing import Any
from .lab_score_portable_queue import validate_portable_queue

_SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def render_human_triage_plan(queue: dict[str, Any], *, global_status: str,
                             source_zip_sha256: str) -> str:
    """Derive bounded HUMAN follow-up steps from an admitted original queue."""
    validate_portable_queue(queue, global_status)
    if not isinstance(source_zip_sha256, str) or not _SHA256.fullmatch(source_zip_sha256):
        raise ValueError('invalid synthetic transport identity')
    lines = [
        '# LightUp synthetic offline HUMAN triage worksheet', '',
        f'**GLOBAL STATUS: {global_status}** — {queue["pairs_checked"]} original pairs; '
        f'{queue["hold_pairs"]} HOLD; {queue["pass_pairs"]} PASS.', '',
        f'**Source-free ZIP SHA-256:** `{source_zip_sha256}`', '',
        '**NOT AUTHORIZATION:** An unsigned transport SHA is only a local '
        'consistency check. It is not source/reviewer identity, consent, scope '
        'approval, external target contact, a scan or a deployment. A local '
        'PASS never clears a global HOLD. HUMAN offline review only.', '',
        '## Original affected archives — HOLD first', '',
    ]
    if not queue['archive_priorities']:
        lines.append('No archived HOLD comparisons. Separate human gates '
                     'still apply; no automatic clearance.')
    for item in queue['archive_priorities']:
        lines.append(f'- [ ] Archive {item["index"]}: '
                     f'{item["hold_pairs"]} HOLD pairs; '
                     f'{item["reused_evidence_pairs"]} evidence reuse; '
                     f'{item["score_drift_pairs"]} score drift. Inspect '
                     'original owner-private records offline; do not attach '
                     'private evidence or source identities to this worksheet.')
    lines += ['', '## Original pairs — HOLD first', '']
    for pair in queue['pairs']:
        a, b = pair['previous_index'], pair['current_index']
        lines.append(f'### Anonymous pair {a}-{b}: {pair["review_status"]}')
        if pair['review_status'] == 'HOLD':
            if 'evidence_reused' in pair['hold_reasons']:
                lines.append('- [ ] **Evidence reuse:** Generate genuinely '
                             'independent synthetic localhost baseline/candidate '
                             'captures in new private storage. Preserve this '
                             'original comparison as HOLD.')
            if 'score_drift' in pair['hold_reasons']:
                lines.append('- [ ] **Score drift:** Review synthetic scorer '
                             'calibration against isolated localhost fixtures; '
                             'record any new result separately, never change '
                             'this original HOLD.')
            lines.append('- [ ] HUMAN reviewer: privately compare original '
                         'evidence and record unresolved concerns outside '
                         'this source-free worksheet.')
        else:
            lines.append('- [ ] **Local PASS only:** Privately verify the '
                         'original comparison. This cannot clear another HOLD '
                         'or authorize external work.')
        lines.append('')
    lines += [
        '## HUMAN closure — separate approval gate', '',
        '- [ ] Qualified independent source/security/privacy reviewer has '
        'reviewed actual owner-private originals and any unresolved HOLDs.',
        '- [ ] Consent, scope and release restrictions remain independently '
        'enforced. This report can never mark them complete.', '',
        '**No automatic state transition, target action or grant is issued.**', '',
    ]
    result = '\n'.join(lines)
    if len(result.encode('utf-8')) > 65536:
        raise ValueError('triage worksheet too large')
    return result


def render_human_triage_html(queue: dict[str, Any], *, global_status: str,
                             source_zip_sha256: str) -> str:
    """Inert printable HUMAN follow-up page derived only from admitted values."""
    from .lab_score_portable_html_safety import admit_inert_html
    # Shared validation binds this output to the exact same anonymous source
    # and global HOLD/PASS as the private Markdown worksheet.
    render_human_triage_plan(queue, global_status=global_status,
                             source_zip_sha256=source_zip_sha256)
    archive_rows = ""
    for archive in queue['archive_priorities']:
        index = archive['index']
        related = [pair for pair in queue['pairs']
                   if pair['review_status'] == 'HOLD'
                   and index in (pair['previous_index'], pair['current_index'])]
        links = ", ".join(
            f"<a href='#pair-{p['previous_index']}-{p['current_index']}'>"
            f"{p['previous_index']}-{p['current_index']}</a>"
            for p in related)
        archive_rows += (
            f"<li id='archive-{index}'>Archive {index}: "
            f"{archive['hold_pairs']} HOLD pairs; "
            f"{archive['reused_evidence_pairs']} replay; "
            f"{archive['score_drift_pairs']} drift. "
            f"Follow-ups: {links}. Privately inspect originals; "
            "never embed private evidence here.</li>")
    if not archive_rows:
        archive_rows = '<li>No local HOLD pairs. Human review still required.</li>'
    pairs = []
    for p in queue['pairs']:
        a, b = p['previous_index'], p['current_index']
        actions = []
        if 'evidence_reused' in p['hold_reasons']:
            actions.append('☐ Evidence reuse: produce independent synthetic localhost '
                           'baseline/candidate captures in new private storage; '
                           'preserve this original HOLD.')
        if 'score_drift' in p['hold_reasons']:
            actions.append('☐ Score drift: inspect synthetic scorer calibration '
                           'against isolated localhost fixtures; retain original HOLD.')
        if p['review_status'] == 'HOLD':
            actions.append('☐ HUMAN: compare owner-private original records offline '
                           'and record unresolved concerns separately.')
        else:
            actions.append('☐ Local PASS only: verify privately; does not clear '
                           'other HOLD pairs or authorize external activity.')
        checklist = ''.join(f'<li>{item}</li>' for item in actions)
        pairs.append(f"<section id='pair-{a}-{b}'><h3>Pair {a}-{b}: "
                     f"{p['review_status']}</h3><ul>{checklist}</ul></section>")
    if queue['hold_pairs']:
        first = queue['pairs'][0]
        nav = ("<nav aria-label='HOLD-first checklist navigation'>"
               f"<a href='#pair-{first['previous_index']}-{first['current_index']}'>"
               "Jump to highest-priority original HOLD checklist</a></nav>")
    else:
        nav = ("<nav aria-label='Review navigation'><a href='#content'>"
               "All local pairs PASS; HUMAN review still required</a></nav>")
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>LightUp offline HUMAN triage worksheet</title>"
        "<style>body{font:1rem/1.5 system-ui;max-width:65rem;"
        "margin:2rem auto;padding:0 1rem}section{margin:1.3rem 0}"
        "li{margin:.5rem 0}h3{border-top:1px solid;padding-top:.5rem}"
        "a:focus-visible{outline:3px solid currentColor}"
        "@media print{body{margin:0}section{break-inside:avoid}}"
        "</style></head><body><main id='content'>"
        "<h1>LightUp synthetic offline HUMAN triage worksheet</h1>"
        f"{nav}"
        f"<p><strong>GLOBAL STATUS {global_status}</strong>; "
        f"{queue['pairs_checked']} original pairs; "
        f"{queue['hold_pairs']} HOLD; {queue['pass_pairs']} PASS.</p>"
        f"<p>Source-free unsigned local ZIP SHA-256: {source_zip_sha256}. "
        "This digest is NOT provenance or source identity proof.</p>"
        "<p><strong>NOT AUTHORIZATION</strong>: HUMAN-only offline comparison; "
        "no consent, scope grant, real targets, external scans or deployment. "
        "Local PASS never clears global HOLD.</p>"
        f"<section><h2>Affected archive priorities</h2><ul>{archive_rows}</ul></section>"
        f"<section><h2>All original pair follow-ups (HOLD first)</h2>"
        f"{''.join(pairs)}</section>"
        "<section><h2>Independent HUMAN closure gate</h2><ul>"
        "<li>☐ Qualified independent source/security/privacy reviewer must "
        "check original owner-private records and unresolved HOLDs.</li>"
        "<li>☐ Separate scope, owner consent and release gates remain enforced "
        "outside this worksheet.</li></ul></section>"
        "<p><strong>No approval, action, or state transition is issued by "
        "this document.</strong></p></main></body></html>"
    )
    admit_inert_html(html.encode('utf-8'))
    return html


def render_human_triage_csv(queue: dict[str, Any], *, global_status: str,
                            source_zip_sha256: str) -> str:
    """Bounded formula-safe HUMAN action rows, never a machine clearance."""
    import csv
    from io import StringIO
    # This performs complete canonical pair/priority/authority validation as
    # well as binding the unsigned ZIP transport digest to this projection.
    render_human_triage_plan(queue, global_status=global_status,
                             source_zip_sha256=source_zip_sha256)
    output = StringIO(newline='')
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow(('global_status', 'anonymous_pair', 'pair_status',
                     'action_code', 'human_action', 'completion',
                     'unsigned_zip_sha256', 'source_authenticated',
                     'authorization_granted', 'deployment_approved'))
    def row(pair: str, status: str, code: str, action: str) -> None:
        writer.writerow((global_status, pair, status, code, action,
                         'NOT_VERIFIED', source_zip_sha256, 'false',
                         'false', 'false'))
    for p in queue['pairs']:
        pair = f"{p['previous_index']}-{p['current_index']}"
        if 'evidence_reused' in p['hold_reasons']:
            row(pair, 'HOLD', 'RECAPTURE_INDEPENDENT',
                'New independent synthetic localhost captures; preserve original HOLD')
        if 'score_drift' in p['hold_reasons']:
            row(pair, 'HOLD', 'REVIEW_SCORER_DRIFT',
                'Review isolated synthetic scorer; preserve original HOLD')
        row(pair, p['review_status'], 'HUMAN_COMPARE_ORIGINALS',
            'Review original owner-private evidence offline; do not export it')
    row('GLOBAL', global_status, 'INDEPENDENT_SOURCE_SECURITY_PRIVACY',
        'Qualified independent review and separate authorization required')
    result = output.getvalue()
    if len(result.encode('utf-8')) > 65536:
        raise ValueError('triage CSV too large')
    return result
