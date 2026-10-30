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
