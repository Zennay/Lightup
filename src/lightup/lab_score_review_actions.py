"""HOLD-first HUMAN actions for two independent, anonymous synthetic ZIPs.

The original anonymous ordinals are meaningful within each transport only.
Never match an ordinal across ZIPs or infer a remediation, approval or grant.
"""
from __future__ import annotations
import csv
import io
import json
from typing import Any

from .lab_score_action_admission import admit_human_actions
from .lab_score_handoff_verify import verify_portable_review
from .lab_score_portable_html_safety import admit_inert_html


def build_review_actions(comparison: dict[str, Any], baseline: str,
                         candidate: str) -> dict[str, Any]:
    if comparison.get('schema') != 'lightup.lab-score-human-two-transport-comparison.v1':
        raise ValueError('not a verified HUMAN two-ZIP comparison')
    items = []
    for label, path in (('baseline', baseline), ('candidate', candidate)):
        checked = verify_portable_review(path, review_queue=True)
        summary = comparison[label]
        queue = checked['review_queue']
        if (checked['history_content_validated'] is not True
                or checked['portable_transport_sha256'] != summary['unsigned_transport_sha256']
                or checked['review_status'] != summary['global_status']
                or queue['hold_pairs'] != summary['hold_pairs']
                or queue['pairs_checked'] != summary['original_pairs']):
            raise ValueError('original anonymous ZIP changed during action build')
        for pair in queue['pairs']:
            if pair['review_status'] != 'HOLD':
                continue
            reasons = pair['hold_reasons']
            if not reasons or not set(reasons).issubset({'evidence_reused', 'score_drift'}):
                raise ValueError('invalid original HOLD reason')
            for reason in reasons:
                action = ('RECAPTURE_INDEPENDENT_SYNTHETIC_ORIGINALS'
                          if reason == 'evidence_reused' else
                          'REVIEW_ISOLATED_SYNTHETIC_SCORER_DRIFT')
                items.append({
                    'transport': label,
                    'anonymous_previous': pair['previous_index'],
                    'anonymous_current': pair['current_index'],
                    'reason': reason,
                    'human_action': action,
                    'completion': 'NOT_VERIFIED',
                    'authorization_granted': False,
                    'remediation_verified': False,
                })
    # The minimum action remains even if both original synthetic ZIPs PASS.
    items.append({
        'transport': 'both_independent_origins',
        'anonymous_previous': None,
        'anonymous_current': None,
        'reason': 'original_source_and_identity_unverified',
        'human_action': 'HUMAN_COMPARE_ORIGINAL_PRIVATE_SOURCES_AND_APPROVALS',
        'completion': 'NOT_VERIFIED',
        'authorization_granted': False,
        'remediation_verified': False,
    })
    return {
        'schema': 'lightup.lab-score-human-two-transport-actions.v1',
        'review_status': comparison['review_status'],
        'unsigned_transport_sha256': {
            label: comparison[label]['unsigned_transport_sha256']
            for label in ('baseline','candidate')
        },
        'hold_action_rows': len(items)-1,
        'human_review_only': True,
        'original_source_authenticated': False,
        'same_originals_proven': False,
        'authorization_granted': False,
        'remediation_verified': False,
        'deployment': False,
        'actions': items,
    }


def render_review_actions(data: dict[str, Any], fmt: str) -> str:
    """Render a bounded inert synthetic HUMAN action manifest."""
    actions=admit_human_actions(data)
    if (data['schema']!='lightup.lab-score-human-two-transport-actions.v1'
            or data['review_status'] not in ('PASS','HOLD')
            or not 1 <= len(actions) <= 113
            or data['hold_action_rows']!=len(actions)-1
            or any(data[k] is not False for k in (
                'original_source_authenticated','same_originals_proven',
                'authorization_granted','remediation_verified','deployment'))
            or data['human_review_only'] is not True
            or actions[-1]['human_action'] !=
               'HUMAN_COMPARE_ORIGINAL_PRIVATE_SOURCES_AND_APPROVALS'):
        raise ValueError('untrusted HUMAN action projection')
    if fmt=='actions-json':
        return json.dumps(data,sort_keys=True,allow_nan=False)+'\n'
    headers=('transport','anonymous_previous','anonymous_current','reason',
             'human_action','completion','authorization_granted','remediation_verified')
    if fmt=='actions-csv':
        output=io.StringIO(newline='')
        writer=csv.writer(output,lineterminator='\n')
        writer.writerow(headers)
        for a in actions:
            writer.writerow([str(a[k]).lower() if isinstance(a[k],bool)
                             else a[k] for k in headers])
        return output.getvalue()
    if fmt!='actions-html':
        raise ValueError('invalid HUMAN action format')
    rows=[]
    for a in actions:
        origin=a['transport']
        previous=a['anonymous_previous']
        current=a['anonymous_current']
        if origin not in ('baseline','candidate','both_independent_origins'):
            raise ValueError('untrusted original source label')
        if previous is not None and (type(previous) is not int
                                      or type(current) is not int
                                      or not 1 <= previous < current <= 8):
            raise ValueError('invalid anonymous ordinals')
        if (a['completion']!='NOT_VERIFIED'
                or a['authorization_granted'] is not False
                or a['remediation_verified'] is not False
                or a['human_action'] not in (
                    'RECAPTURE_INDEPENDENT_SYNTHETIC_ORIGINALS',
                    'REVIEW_ISOLATED_SYNTHETIC_SCORER_DRIFT',
                    'HUMAN_COMPARE_ORIGINAL_PRIVATE_SOURCES_AND_APPROVALS')):
            raise ValueError('untrusted review action')
        pair=('--' if previous is None else f'{previous}-{current}')
        rows.append(f"<tr><th scope='row'>{origin}</th><td>{pair}</td>"
                    f"<td>{a['human_action']}</td><td>NOT_VERIFIED</td></tr>")
    html=(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>LightUp offline HUMAN two-source action queue</title>"
        "<style>body{font:1rem/1.5 system-ui;max-width:64rem;margin:2rem auto;"
        "padding:0 1rem}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid;padding:.6rem;text-align:left;overflow-wrap:anywhere}"
        "@media print{body{margin:0}tr{break-inside:avoid}}</style>"
        "</head><body><main><h1>Offline synthetic HUMAN follow-up actions</h1>"
        f"<p><strong>GLOBAL STATUS {data['review_status']}</strong>."
        " Original HOLD evidence remains HOLD across transports.</p>"
        "<p><strong>NOT VERIFIED OR AUTHORIZED.</strong> Anonymous original"
        " ordinals are local to each ZIP and cannot be matched across ZIPs."
        " No source identity, consent, independent proof, scans or deployment.</p>"
        "<table><caption>Private original evidence review actions</caption>"
        "<thead><tr><th scope='col'>Transport</th><th scope='col'>Original pair</th>"
        "<th scope='col'>HUMAN next action</th><th scope='col'>Completion</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        "<p>Qualified independent HUMAN source/security/privacy review and"
        " separate legal scope approval remain external requirements.</p>"
        "</main></body></html>")
    if len(html.encode())>65536:
        raise ValueError('HUMAN action HTML exceeds bounded output')
    admit_inert_html(html.encode())
    return html
