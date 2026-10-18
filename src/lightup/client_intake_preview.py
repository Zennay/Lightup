"""Readable private scope-request preview, with no submission or grant path.

Consumes only a normalized intake payload. It does not authenticate, infer
ownership, contact assets, persist an assessment request or accept consent.
"""
from __future__ import annotations

from datetime import datetime, timezone
import html


def render_client_intake_preview(payload: dict) -> str:
    """Render a scriptless, offline human-checkable request proposal."""
    if type(payload) is not dict:
        raise ValueError("intake preview requires a bounded normalized request")
    if payload.get("requested_mode") != "authorized_assessment":
        raise ValueError("only reviewable assessment request payloads are supported")
    assets = payload.get("requested_assets")
    risk = payload.get("requested_risk")
    notes = payload.get("notes")
    if (type(assets) is not list or not 1 <= len(assets) <= 80
            or any(type(x) is not str or len(x) > 253 for x in assets)
            or type(risk) is not int or not 1 <= risk <= 4
            or type(notes) is not str or len(notes) > 4000):
        raise ValueError("unbounded preview fields")
    if any(payload.get(key) is not False for key in (
        "authorized", "consent_verified", "grant_issued", "scan_allowed",
        "dispatch_allowed", "release_allowed",
    )):
        raise ValueError("a proposal cannot assert authority")
    esc = lambda item: html.escape(str(item), quote=True)
    listed = "".join('<li><code>' + esc(asset) + '</code></li>' for asset in assets)
    imported = payload.get("source_format") == "lightup.scope_proposal_draft/v1"
    digest = payload.get("proposal_file_sha256") if imported else None
    if imported and (type(digest) is not str or len(digest) != 64
                     or any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError("invalid Studio proposal continuity value")
    intake_digest = payload.get("intake_sha256")
    if (type(intake_digest) is not str or len(intake_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in intake_digest)):
        raise ValueError("missing exact normalized intake revision")
    time = esc(datetime.now(timezone.utc).isoformat())
    provenance = (
        '<section class="card"><h2>Studio import (unsigned)</h2>'
        '<p>The following SHA-256 describes the exact reviewed input file. '
        'Copy it to authenticated submission; this is NOT a signature or consent.</p>'
        '<p><code>' + esc(digest) + '</code></p>'
        '<p>Any studio exclusions, scheduled windows or private-lab activities '
        'were rejected before this preview: the current stored request schema '
        'cannot enforce those constraints.</p></section>'
        if imported else
        '<section class="card"><h2>Manual client draft</h2>'
        '<p>The assets and risk shown here are local client input, not proof of '
        'ownership, authorization, a scheduled window or consent.</p></section>'
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; script-src \'none\'; connect-src \'none\'; '
        'img-src \'none\'; form-action \'none\'; base-uri \'none\'">'
        '<title>LightUp · Client request draft</title>'
        '<style>:root{font:16px/1.55 system-ui,sans-serif;background:#0b1524;color:#ecf3ff}'
        '*{box-sizing:border-box}body{margin:0 auto;max-width:930px;padding:2rem}'
        'h1{font-size:clamp(1.6rem,4vw,2.6rem);margin:.1rem 0}h2{font-size:1.1rem}'
        '.lead{color:#a9bdcf}.card{background:#17253b;padding:1.4rem;border-radius:13px;'
        'border:1px solid #39506a;margin:1rem 0;overflow-wrap:anywhere}'
        '.alert{border:2px solid #e5bb75;background:#2c271f;padding:1rem;border-radius:12px}'
        '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}'
        '.grid .card{margin:0}.big{font-size:1.65rem;font-weight:800}'
        'code{overflow-wrap:anywhere}li{padding:.25rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
        'footer{color:#a9bdcf;margin:2rem 0 0;border-top:1px solid #39506a;padding-top:1rem}'
        '@media print{:root{background:white;color:black}.card{background:white;color:black}'
        '.alert{background:#eee;color:black}}</style></head><body>'
        '<p class="lead">LIGHTUP / PRIVATE LOCAL CLIENT INTAKE</p>'
        '<h1>Proposed assessment request</h1>'
        '<p class="lead">Generated ' + time + '</p>'
        '<div class="alert"><strong>DRAFT — NO CONSENT OR AUTHORIZATION.</strong> '
        'This file has NOT been submitted or approved. It is a private unsigned '
        'copy that can become stale. It never issues grants, contacts assets or '
        'starts a scan. Review in a separate authenticated client channel.</div>'
        '<main><div class="grid"><section class="card"><h2>Requested risk</h2>'
        '<div class="big">' + esc(risk) + ' / 4</div>'
        '<p>Independent operator review and appropriate approvals are required.</p>'
        '</section><section class="card"><h2>Declared assets</h2>'
        '<div class="big">' + str(len(assets)) + '</div>'
        '<p>Proposed literal host/IP/CIDR scope — not a runtime allowlist.</p>'
        '</section></div>'
        '<section class="card"><h2>Proposed assets</h2><ul>' + listed + '</ul></section>'
        '<section class="card"><h2>Client explanation and safety notes</h2>'
        '<pre>' + esc(notes) + '</pre></section>'
        '<section class="card"><h2>Exact proposal revision</h2>'
        '<p>To submit this proposal, provide <code>--expect-intake-sha256</code> '
        'with the following digest. A mismatch requires another preview. '
        'This SHA-256 is unsigned and NOT a consent signature.</p>'
        '<p><code>' + esc(intake_digest) + '</code></p></section>' + provenance
        + '<section class="card"><h2>Next step</h2>'
        '<p>Only an existing, individually authenticated LightUp client account '
        'can explicitly submit this proposal using <code>client_request_cli submit</code>. '
        'The operator must review it independently; even an approved request '
        'does not provide a current executable grant.</p></section></main>'
        '<footer>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · '
        'Sensitive request data · Never publish this exported file.</footer></body></html>'
    )
