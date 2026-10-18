"""Private, self-contained before/after review page for rejected-request revisions.

Only an authenticated local CLI may render this page from persisted records.
The saved copy is unsigned, stale on later updates, and never operator consent.
"""
from __future__ import annotations

from datetime import datetime, timezone
import html

from .domain import AssessmentRequestRecord


def render_revision_review(original: AssessmentRequestRecord, draft: dict) -> str:
    """Render a limited, read-only before/after review with escaped user data."""
    if draft.get("previous_request_id") != original.request_id:
        raise ValueError("revision and source request identity differ")
    escape = lambda value: html.escape(str(value), quote=True)
    old = tuple(draft["previous_assets"])
    new = tuple(draft["requested_assets"])
    added = tuple(draft["newly_introduced_assets"])
    removed = tuple(draft["removed_or_narrowed_assets"])
    if any(type(s) is not str for s in (*old, *new, *added, *removed)):
        raise ValueError("malformed revision text")
    if len(old) > 80 or len(new) > 80 or len(added) > 80 or len(removed) > 80:
        raise ValueError("too many assets for the bounded revision overview")

    def rows(items: tuple[str, ...]) -> str:
        return "".join("<li><code>" + escape(value) + "</code></li>" for value in items) or "<li>None</li>"

    expanded = bool(draft["scope_expansion_requires_confirmation"])
    scope_note = (
        "Broader scope or risk: a separate explicit expansion confirmation is required "
        "for a new review request. The existing rejection remains unchanged."
        if expanded else
        "The proposed scope is unchanged or narrowed; a NEW operator review is still required."
    )
    # The request provenance digest is only an unsigned exact-row consistency hint.
    stamp = escape(datetime.now(timezone.utc).isoformat())
    source_digest = escape(draft["previous_record_sha256"])
    proposed_digest = escape(draft["revision_sha256"])
    current_risk = escape(draft["requested_risk"])
    previous_risk = escape(draft["previous_risk"])
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; script-src \'none\'; connect-src \'none\'; '
        'img-src \'none\'; style-src \'unsafe-inline\'; form-action \'none\'; base-uri \'none\'">'
        '<title>LightUp · Request revision review (not authorization)</title>'
        '<style>:root{font:15px/1.55 system-ui,sans-serif;color:#e3ecfb;background:#0d1423}'
        '*{box-sizing:border-box}body{margin:0}header,main,footer{max-width:1150px;margin:auto;padding:1.8rem}'
        'header{border-bottom:1px solid #33445d}.eyebrow{color:#85dfc4;letter-spacing:.1em;font-weight:750}'
        'h1{margin:.2rem 0}h2{margin:0 0 .6rem}.muted{color:#b0bfd3}.grid{display:grid;'
        'grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:1rem}'
        '.panel{background:#152239;border:1px solid #344863;border-radius:14px;padding:1.4rem;margin:1rem 0}'
        '.notice{border-left:5px solid #dabc72;background:#2c291e;padding:1rem;border-radius:6px}'
        'ul{padding-left:1.1rem}li{overflow-wrap:anywhere;margin:.4rem 0}code{overflow-wrap:anywhere}'
        '.metrics{display:flex;gap:.9rem;flex-wrap:wrap}.metric{padding:1rem;border-radius:10px;'
        'background:#1b3050;flex:1 0 190px}.metric strong{display:block;font-size:1.8rem}'
        'footer{font-size:.87rem;color:#b0bfd3;border-top:1px solid #344863}'
        '@media print{:root{color:#000;background:white}.panel,.metric{background:white;color:black;border:1px solid #666}'
        '.notice{color:#000;background:#eee}}</style></head><body>'
        '<header><p class="eyebrow">LIGHTUP / PRIVATE LOCAL REVIEW</p>'
        '<h1>Review a rejected request revision</h1>'
        '<p class="muted">Prepared ' + stamp + ' · Previous request '
        + escape(original.request_id) + '</p>'
        '<p class="notice"><strong>NOT AUTHORIZED.</strong> This is a client proposal, '
        'not a grant, independent operator decision, scan permit, verified consent '
        'or current-revocation proof. The original request remains REJECTED. '
        'This file is private, unsigned and may become stale.</p></header>'
        '<main><section class="metrics">'
        '<div class="metric"><strong>' + str(len(added)) + '</strong>New or wider asset declarations</div>'
        '<div class="metric"><strong>' + str(len(removed)) + '</strong>Removed or narrowed declarations</div>'
        '<div class="metric"><strong>' + previous_risk + ' → ' + current_risk + '</strong>Requested risk level</div>'
        '</section>'
        '<p class="notice">' + escape(scope_note) + '</p>'
        '<div class="grid"><section class="panel"><h2>Previously rejected</h2>'
        '<p>Status: <strong>REJECTED</strong> · Risk ' + previous_risk + '</p>'
        '<h3>Original assets</h3><ul>' + rows(old) + '</ul></section>'
        '<section class="panel"><h2>New proposal only</h2>'
        '<p>Status: <strong>NOT SUBMITTED</strong> · Proposed risk ' + current_risk + '</p>'
        '<h3>Proposed assets</h3><ul>' + rows(new) + '</ul></section></div>'
        '<div class="grid"><section class="panel"><h2>New or wider</h2><ul>'
        + rows(added) + '</ul></section><section class="panel"><h2>Removed or narrower</h2><ul>'
        + rows(removed) + '</ul></section></div>'
        '<section class="panel"><h2>Next action</h2><p>Review this private comparison. '
        'In the authenticated CLI, run <code>revise-submit</code> using the exact '
        'source SHA-256 and complete proposed revision SHA-256 shown below, <code>--confirm-new-request</code> and, when '
        'scope has expanded, <code>--confirm-scope-expansion</code>. '
        'Do not interpret confirmations as security authorization.</p>'
        '<p>Source review SHA-256 (unsigned): <code>' + source_digest + '</code></p>'
        '<p>Complete proposed revision SHA-256 (unsigned): <code>' + proposed_digest + '</code></p>'
        '<p class="muted">Fresh login and a new independent operator review are mandatory. '
        'An approved request alone is not a durable authorization grant.</p></section></main>'
        '<footer>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · '
        'Sensitive client request material; keep locally private.</footer></body></html>'
    )
