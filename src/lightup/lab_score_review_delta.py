"""Compare two synthetic HUMAN ZIP transports without claiming remediation."""
from __future__ import annotations
import csv
import io
import json
from math import isqrt
from typing import Any
from .lab_score_handoff_verify import verify_portable_review
from .lab_score_portable_html_safety import admit_inert_html

_SCHEMA = 'lightup.lab-score-human-two-transport-comparison.v1'
_FIELDS = ('original_pairs', 'hold_pairs', 'pass_pairs',
           'reused_evidence_pairs', 'score_drift_pairs')


def _read(path: str) -> dict[str, Any]:
    checked = verify_portable_review(path, review_queue=True)
    if checked['history_content_validated'] is not True:
        raise ValueError('unverified transport')
    q = checked['review_queue']
    n = (1 + isqrt(1 + 8 * q['pairs_checked'])) // 2
    if n * (n-1) // 2 != q['pairs_checked']:
        raise ValueError('incomplete original matrix')
    return {
        'global_status': checked['review_status'],
        'unsigned_transport_sha256': checked['portable_transport_sha256'],
        'original_archives': n,
        'original_pairs': q['pairs_checked'],
        'hold_pairs': q['hold_pairs'],
        'pass_pairs': q['pass_pairs'],
        'reused_evidence_pairs': sum('evidence_reused' in p['hold_reasons']
                                    for p in q['pairs']),
        'score_drift_pairs': sum('score_drift' in p['hold_reasons']
                                 for p in q['pairs']),
    }


def compare_portable_review_transports(first: str, second: str) -> dict[str, Any]:
    """Twice admit each original ZIP; preserve all old HOLDs and reviewer gates."""
    left, right = _read(first), _read(second)
    if left['unsigned_transport_sha256'] == right['unsigned_transport_sha256']:
        raise ValueError('same unsigned synthetic transport')
    if _read(first) != left or _read(second) != right:
        raise ValueError('ZIP changed during original comparison')
    return {
        'schema': _SCHEMA,
        'baseline': left,
        'candidate': right,
        'count_change_candidate_minus_baseline': {
            k: right[k] - left[k] for k in _FIELDS
        },
        'baseline_hold_preserved': left['global_status'] == 'HOLD',
        'review_status': 'HOLD' if ('HOLD' in (left['global_status'],
                                              right['global_status'])) else 'PASS',
        'original_source_authenticated': False,
        'same_originals_proven': False,
        'remediation_verified': False,
        'authorization_granted': False,
        'external_targets_contacted': False,
        'deployment': False,
        'human_review_only': True,
    }


def render_comparison(result: dict[str, Any], fmt: str) -> str:
    """Project a canonical two-transport comparison for an offline HUMAN."""
    if result.get('schema') != _SCHEMA:
        raise ValueError('untrusted HUMAN comparison')
    a, b = result['baseline'], result['candidate']
    delta = result['count_change_candidate_minus_baseline']
    if fmt == 'json':
        return json.dumps(result, sort_keys=True, allow_nan=False) + '\n'
    if fmt == 'text':
        lines = [
            'LightUp two-transport HUMAN synthetic comparison',
            'GLOBAL STATUS '+result['review_status'],
            'Original HOLD preserved; anonymous counts cannot prove remediation.',
            'Unsigned baseline ZIP SHA-256: '+a['unsigned_transport_sha256'],
            'Unsigned candidate ZIP SHA-256: '+b['unsigned_transport_sha256'],
        ]
        lines += [f'{k}: baseline={a[k]}, candidate={b[k]}, change={delta[k]:+d}'
                  for k in _FIELDS]
        lines.append('No source authentication, independent identity mapping, '
                     'consent, target action, security grant or deployment.')
        return '\n'.join(lines) + '\n'
    if fmt == 'csv':
        dest = io.StringIO(newline='')
        writer = csv.writer(dest, lineterminator='\n')
        writer.writerow(('metric', 'baseline', 'candidate', 'candidate_minus_baseline',
                         'global_status', 'remediation_verified',
                         'authorization_granted'))
        for k in _FIELDS:
            writer.writerow((k, a[k], b[k], delta[k],
                             result['review_status'], 'false', 'false'))
        return dest.getvalue()
    if fmt != 'html':
        raise ValueError('invalid comparison format')
    rows = ''.join(
        f'<tr><th scope="row">{k.replace("_"," ")}</th><td>{a[k]}</td>'
        f'<td>{b[k]}</td><td>{delta[k]:+d}</td></tr>' for k in _FIELDS)
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>LightUp synthetic HUMAN comparison</title>"
        "<style>body{font:1rem/1.5 system-ui;max-width:58rem;margin:2rem auto;"
        "padding:0 1rem}table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid;padding:.6rem;text-align:left}"
        "@media print{body{margin:0}}</style></head><body><main>"
        "<h1>Source-free synthetic HUMAN two-transport comparison</h1>"
        f"<p><strong>GLOBAL STATUS {result['review_status']}</strong>. "
        "Original HOLDs cannot be cleared by a later ZIP.</p>"
        "<p><strong>NOT AUTHORIZATION</strong>: different unsigned ZIP hashes "
        "do not prove the same originals, independence, remediation, identity "
        "or approval. No real targets, scans, grants or deployment.</p>"
        "<table><caption>Anonymous counts; no original identity mapping</caption>"
        "<thead><tr><th scope='col'>Metric</th><th scope='col'>Baseline</th>"
        "<th scope='col'>Candidate</th><th scope='col'>Change</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
        "<p>Human source/security/privacy review of original private evidence "
        "and separate permissions always remain mandatory.</p>"
        "</main></body></html>")
    admit_inert_html(html.encode('utf-8'))
    return html
