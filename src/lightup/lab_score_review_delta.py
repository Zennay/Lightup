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


def publish_private_comparison(first: str, second: str, destination: str, *,
                               include_actions: bool = False,
                               include_briefs: bool = False) -> dict[str, Any]:
    """Atomically publish complete HUMAN views from two admitted ZIPs."""
    import os
    import hashlib
    from pathlib import Path
    from .lab_score_suite import _private_output_directory
    from .lab_score_inspect import _private_dir_fd
    from .lab_score_queue_workroom import _check_file

    if include_briefs and not include_actions:
        raise ValueError("persistent HUMAN briefs require action workroom")
    sources = [Path(p).expanduser().absolute() for p in (first, second)]
    target = Path(destination).expanduser().absolute()
    if ('..' in Path(destination).parts or any(
            target == source.parent or target in source.parents
            or source in target.parents for source in sources)):
        raise ValueError('offline comparison output overlaps source ZIPs')
    result = compare_portable_review_transports(first, second)
    names = ('comparison.json','comparison.txt','comparison.csv','comparison.html')
    formats = ('json','text','csv','html')
    payloads = {name: render_comparison(result, fmt).encode('utf-8')
                for name, fmt in zip(names, formats)}
    if include_actions:
        from .lab_score_review_actions import build_review_actions, render_review_actions
        actions = build_review_actions(result, first, second)
        for fmt, name in (('actions-json', 'actions.json'),
                          ('actions-csv', 'actions.csv'),
                          ('actions-html', 'actions.html')):
            payloads[name] = render_review_actions(actions, fmt).encode('utf-8')
        if include_briefs:
            from .lab_score_action_brief import render_action_brief
            for fmt, name in (('actions-brief-markdown', 'human-brief.md'),
                              ('actions-brief-html', 'human-brief.html')):
                payloads[name] = render_action_brief(actions, fmt).encode('utf-8')
    receipt = {
        'schema': ('lightup.lab-score-human-two-transport-workroom.v3'
                   if include_briefs else
                   'lightup.lab-score-human-two-transport-workroom.v2'
                   if include_actions else 'lightup.lab-score-human-two-transport-workroom.v1'),
        'unsigned_local_consistency_only': True,
        'source_zip_sha256': [result['baseline']['unsigned_transport_sha256'],
                              result['candidate']['unsigned_transport_sha256']],
        'file_sha256': {name: hashlib.sha256(data).hexdigest()
                        for name, data in payloads.items()},
        'authorization_granted': False,
        'remediation_verified': False,
        'deployment': False,
    }
    payloads['manifest.json']=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()
    if any(not 0 < len(data) <= 65536 for data in payloads.values()):
        raise ValueError('oversized HUMAN comparison package')
    root = _private_output_directory(target)
    directory = _private_dir_fd(root)
    created = []
    try:
        try:
            for name, data in payloads.items():
                temporary='.'+name+'.tmp'
                writer=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                               0o600,dir_fd=directory)
                try:
                    with os.fdopen(writer,'wb') as output:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                    stamp=os.stat(temporary,dir_fd=directory,follow_symlinks=False)
                    identity=(stamp.st_dev,stamp.st_ino)
                    os.link(temporary,name,src_dir_fd=directory,dst_dir_fd=directory,
                            follow_symlinks=False)
                    created.append((name,identity))
                    os.unlink(temporary,dir_fd=directory)
                    if _check_file(directory,name,data)[:2]!=identity:
                        raise ValueError('saved HUMAN comparison replaced')
                finally:
                    try:os.unlink(temporary,dir_fd=directory)
                    except FileNotFoundError:pass
            os.fsync(directory)
            if compare_portable_review_transports(first, second)!=result:
                raise ValueError('source ZIP changed during publication')
        except Exception:
            for name,identity in reversed(created):
                try:
                    current=os.stat(name,dir_fd=directory,follow_symlinks=False)
                    if (current.st_dev,current.st_ino)==identity:
                        os.unlink(name,dir_fd=directory)
                except FileNotFoundError:pass
            try:
                pinned=os.fstat(directory)
                actual=os.stat(root,follow_symlinks=False)
                if ((pinned.st_dev,pinned.st_ino)==(actual.st_dev,actual.st_ino)
                        and not os.listdir(directory)):
                    os.rmdir(root)
            except OSError:pass
            raise
    finally:
        os.close(directory)
    return result


def verify_private_comparison(first: str, second: str, directory: str, *,
                              with_count: bool = False) -> dict[str, Any]:
    """Reopen all five saved private files and both original ZIPs, read only."""
    import os
    import hashlib
    from .lab_score_inspect import _private_dir_fd
    from .lab_score_queue_workroom import _check_file

    result=compare_portable_review_transports(first,second)
    views={('comparison.txt' if fmt=='text' else 'comparison.'+fmt):
           render_comparison(result,fmt).encode('utf-8')
           for fmt in ('json','text','csv','html')}
    fd=_private_dir_fd(directory)
    try:
        inventory = set(os.listdir(fd))
        base = {'comparison.json', 'comparison.txt', 'comparison.csv',
                'comparison.html', 'manifest.json'}
        with_actions = base | {'actions.json', 'actions.csv', 'actions.html'}
        with_briefs = with_actions | {'human-brief.md', 'human-brief.html'}
        if inventory not in (base, with_actions, with_briefs):
            raise ValueError('invalid saved HUMAN comparison inventory')
        include_briefs = inventory == with_briefs
        include_actions = inventory in (with_actions, with_briefs)
    finally:
        os.close(fd)
    if include_actions:
        from .lab_score_review_actions import build_review_actions, render_review_actions
        actions = build_review_actions(result, first, second)
        for fmt, name in (('actions-json', 'actions.json'),
                          ('actions-csv', 'actions.csv'),
                          ('actions-html', 'actions.html')):
            views[name] = render_review_actions(actions, fmt).encode('utf-8')
        if include_briefs:
            from .lab_score_action_brief import render_action_brief
            for fmt, name in (('actions-brief-markdown', 'human-brief.md'),
                              ('actions-brief-html', 'human-brief.html')):
                views[name] = render_action_brief(actions, fmt).encode('utf-8')
    manifest={
        'schema':('lightup.lab-score-human-two-transport-workroom.v3'
                  if include_briefs else
                  'lightup.lab-score-human-two-transport-workroom.v2'
                  if include_actions else 'lightup.lab-score-human-two-transport-workroom.v1'),
        'unsigned_local_consistency_only':True,
        'source_zip_sha256':[result['baseline']['unsigned_transport_sha256'],
                             result['candidate']['unsigned_transport_sha256']],
        'file_sha256':{k:hashlib.sha256(v).hexdigest() for k,v in views.items()},
        'authorization_granted':False,
        'remediation_verified':False,
        'deployment':False,
    }
    views['manifest.json']=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    fd=_private_dir_fd(directory)
    try:
        original={}
        for _ in range(2):
            if set(os.listdir(fd))!=set(views):
                raise ValueError('saved HUMAN comparison inventory changed')
            for name,expected in views.items():
                identity=_check_file(fd,name,expected)
                if name in original and original[name]!=identity:
                    raise ValueError('saved comparison changed between reads')
                original[name]=identity
        if set(os.listdir(fd))!=set(views):
            raise ValueError('saved comparison inventory replaced')
    finally:
        os.close(fd)
    if compare_portable_review_transports(first,second)!=result:
        raise ValueError('original review transports changed during receipt inspection')
    return (result, len(views)) if with_count else result
