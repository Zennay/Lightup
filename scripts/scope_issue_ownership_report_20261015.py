"""Human-readable HOLD-only report for offline synthetic scope ownership snapshots."""
from __future__ import annotations

import html
import json
import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot, audit


def _safe_path(value: str) -> str:
    # Render text only; caller controlled file paths cannot inject Markdown/HTML.
    safe = json.dumps(value, ensure_ascii=True)[1:-1]
    safe = html.escape(safe, quote=True)
    for mark in ('\\', '`', '*', '_', '[', ']', '(', ')', '#', '|', '!', '<', '>'):
        safe = safe.replace(mark, '\\' + mark)
    return safe


def render(result: dict) -> str:
    if type(result) is not dict or result.get('status') != 'HOLD' or any(
        result.get(flag) is not False
        for flag in ('can_authorize', 'can_scan', 'can_merge', 'can_deploy', 'can_release')
    ):
        raise ValueError('untrusted result')
    lines = [
        '# LightUp · scope-authorization werkverdeling',
        '',
        '**Status: HOLD — offline momentopname, geen autorisatie of release.**',
        '',
        'De lijst is alleen een werkverdelingshint. Controleer de actuele GitHub-PR’s,',
        'Notion-toewijzing en broncode voordat iemand een issue of branch overneemt.',
        '',
    ]
    sections = (
        ('Open issues zonder bekende PR-claim', 'unclaimed_open_issues', lambda n: f'- Issue #{n}'),
        ('Open issues met een PR-claim', 'claimed_open_issues', lambda n: f'- Issue #{n}'),
        ('Open draft-PR’s', 'open_draft_prs', lambda n: f'- PR #{n}'),
        ('Dubbele issueclaims', 'duplicate_issue_claims',
         lambda row: f"- Issue #{row['issue']} claimt PR " + ', '.join(f"#{n}" for n in row['prs'])),
        ('Bestandsconflicten op exact pad', 'exact_path_collisions',
         lambda row: f"- Bestand **{_safe_path(row['path'])}** in PR " + ', '.join(f"#{n}" for n in row['prs'])),
        ('Claims op ontbrekende of gesloten issues', 'unknown_or_closed_issue_claims',
         lambda row: f"- Issue #{row['issue']} in PR " + ', '.join(f"#{n}" for n in row['prs'])),
    )
    for heading, key, fmt in sections:
        lines.extend(['## ' + heading, ''])
        values = result[key]
        lines.extend(fmt(item) for item in values) if values else lines.append('- Geen binnen de aangeleverde selectie.')
        lines.append('')
    lines.extend([
        '**Geen uitvoerings-, scan-, merge- of deploymentrechten.**',
        'Geselecteerde issues kunnen al door een andere worker bezet zijn; controleer dit handmatig.',
        '',
    ])
    return '\n'.join(lines)


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        report = render(audit(raw))
    except (InvalidSnapshot, ValueError, KeyError, OSError, TypeError):
        report = '# LightUp · scope-authorization\n\n**HOLD — ongeldige of niet te vertrouwen offline momentopname.**\n'
    sys.stdout.write(report)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
