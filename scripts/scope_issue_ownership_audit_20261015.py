"""Read-only offline LightUp scope-authorization issue/PR ownership audit.

This is not an authorization, security proof, CI verdict or release gate. Input is an
untrusted, explicitly supplied JSON snapshot; this module never talks to GitHub.
"""
from __future__ import annotations

import json
import sys
import unicodedata
from collections import defaultdict
from pathlib import PurePosixPath

MAX_INPUT = 512 * 1024
MAX_ROWS = 2000
MAX_PATHS = 4000


class InvalidSnapshot(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise InvalidSnapshot('duplicate JSON key')
        out[key] = value
    return out


def _fields(value, keys):
    if type(value) is not dict or set(value) != keys:
        raise InvalidSnapshot('invalid record shape')


def _positive_int(value):
    if type(value) is not int or not (1 <= value <= 1_000_000_000):
        raise InvalidSnapshot('invalid issue/PR number')
    return value


def _path(value):
    if type(value) is not str or not (1 <= len(value) <= 260):
        raise InvalidSnapshot('invalid changed path')
    # Preserve exact Git path identity but refuse visual control/invisible text.
    # In particular U+202E can make a path look like a different owned file.
    if unicodedata.normalize('NFC', value) != value:
        raise InvalidSnapshot('ambiguous path normalization')
    if any(unicodedata.category(ch) in ('Cc', 'Cf', 'Cs')
           or unicodedata.bidirectional(ch) in (
               'LRE', 'RLE', 'LRO', 'RLO', 'PDF', 'LRI', 'RLI', 'FSI', 'PDI')
           for ch in value):
        raise InvalidSnapshot('invisible or bidirectional path')
    if '\\' in value or '\x00' in value or '\r' in value or '\n' in value:
        raise InvalidSnapshot('invalid changed path')
    parts = value.split('/')
    if any(part in ('', '.', '..') for part in parts) or value.startswith('/'):
        raise InvalidSnapshot('noncanonical changed path')
    if parts[0] == '.git' or str(PurePosixPath(value)) != value:
        raise InvalidSnapshot('noncanonical changed path')
    return value


def _snapshot(blob):
    if type(blob) is not bytes or len(blob) > MAX_INPUT:
        raise InvalidSnapshot('oversized or invalid input')
    try:
        doc = json.loads(blob.decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(InvalidSnapshot('nonfinite number')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidSnapshot('invalid JSON snapshot') from exc
    _fields(doc, {'issues', 'prs'})
    issues, prs = doc['issues'], doc['prs']
    if type(issues) is not list or type(prs) is not list or len(issues) > MAX_ROWS or len(prs) > MAX_ROWS:
        raise InvalidSnapshot('invalid collection size')
    issue_ids = set()
    normalized_issues = []
    for item in issues:
        _fields(item, {'number', 'open', 'lane'})
        number = _positive_int(item['number'])
        if number in issue_ids or type(item['open']) is not bool or item['lane'] != 'scope-authorization':
            raise InvalidSnapshot('invalid or duplicate scope issue')
        issue_ids.add(number)
        normalized_issues.append((number, item['open']))
    pr_ids = set()
    normalized_prs = []
    path_count = 0
    for item in prs:
        _fields(item, {'number', 'open', 'draft', 'issues', 'paths'})
        number = _positive_int(item['number'])
        if number in pr_ids or type(item['open']) is not bool or type(item['draft']) is not bool:
            raise InvalidSnapshot('invalid or duplicate pull request')
        pr_ids.add(number)
        owned, paths = item['issues'], item['paths']
        if type(owned) is not list or type(paths) is not list or len(owned) > MAX_ROWS or len(paths) > MAX_PATHS:
            raise InvalidSnapshot('invalid PR contents')
        owned_ids = [_positive_int(n) for n in owned]
        paths_checked = [_path(path) for path in paths]
        if len(set(owned_ids)) != len(owned_ids) or len(set(paths_checked)) != len(paths_checked):
            raise InvalidSnapshot('duplicate PR issue or path')
        path_count += len(paths_checked)
        if path_count > MAX_PATHS:
            raise InvalidSnapshot('too many changed paths')
        normalized_prs.append((number, item['open'], item['draft'], owned_ids, paths_checked))
    return normalized_issues, normalized_prs


def audit(blob: bytes) -> dict:
    issues, prs = _snapshot(blob)
    claims = defaultdict(set)
    path_claims = defaultdict(set)
    unknown_claims = defaultdict(set)
    open_issues = {number for number, is_open in issues if is_open}
    for number, is_open, _draft, owned, paths in prs:
        if not is_open:
            continue
        for issue in owned:
            (claims if issue in open_issues else unknown_claims)[issue].add(number)
        for path in paths:
            path_claims[path].add(number)
    # Only exact path collisions are decisive. Directory overlap is intentionally
    # not inferred and must be reviewed by a human on real GitHub diff data.
    collisions = [{'path': path, 'prs': sorted(ids)} for path, ids in sorted(path_claims.items()) if len(ids) > 1]
    duplicate_owners = [{'issue': issue, 'prs': sorted(ids)} for issue, ids in sorted(claims.items()) if len(ids) > 1]
    missing = [{'issue': issue, 'prs': sorted(ids)} for issue, ids in sorted(unknown_claims.items())]
    return {
        'status': 'HOLD',
        'can_authorize': False, 'can_scan': False, 'can_merge': False,
        'can_deploy': False, 'can_release': False,
        'reason': 'Offline untrusted snapshot; independent runtime/security/CI/human review required',
        'unclaimed_open_issues': sorted(open_issues - claims.keys()),
        'claimed_open_issues': sorted(open_issues & claims.keys()),
        'duplicate_issue_claims': duplicate_owners,
        'exact_path_collisions': collisions,
        'unknown_or_closed_issue_claims': missing,
        'open_draft_prs': sorted(number for number, opened, draft, *_ in prs if opened and draft),
    }


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        result = audit(raw)
    except (InvalidSnapshot, OSError):
        result = {'status': 'HOLD', 'can_authorize': False, 'can_scan': False,
                  'can_merge': False, 'can_deploy': False, 'can_release': False,
                  'reason': 'Rejected invalid/untrusted offline snapshot'}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
