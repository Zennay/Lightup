"""Offline display bridge: untrusted JSON -> inert HTML, never authority.

Only fictional notices already decoded by the strict non-authorizing
consumer can be shown. No permissions, consent, grant IDs or tool execution.
"""
from __future__ import annotations

from html import escape

from .synthetic_scope_notice_consumer_1495 import decode_fictional_notice_for_display
from .synthetic_scope_notice_html_1495 import _shell

_HOLD_TITLE = "NOT AUTHORIZED — HOLD"
_HOLD_DETAIL = "No valid fictional review envelope. Nothing approved or executed."
# Embedded CSS style remains static, so it does not inherit untrusted content.
_READONLY_STYLE = (
    '<style>pre.review-text{white-space:pre-wrap;overflow-wrap:anywhere;'
    'font:inherit;line-height:1.65;background:#121724;color:#f2f6ff;'
    'border:1px solid #334158;border-radius:10px;padding:16px;'
    'max-width:100%;overflow:auto}@media print{pre.review-text{'
    'background:white;color:#111;border-color:#bbb}}</style>'
)


def render_fictional_envelope_html(raw: bytes) -> str:
    """Return a stand-alone, inert read-only review page or generic HOLD.

    A correct JSON schema/decoder result is *not* source authentication.
    The original JSON is never re-parsed or interpreted as a grant.
    """
    view = decode_fictional_notice_for_display(raw)
    if view is None:
        body = (
            '<header class="warning" role="alert"><span class="tag stop">HOLD</span>'
            '<h1>' + _HOLD_TITLE + '</h1><p>' + _HOLD_DETAIL + '</p></header>'
            '<footer>NOT AUTHORIZED · authorized=false · consent_verified=false · '
            'dispatch_allowed=false · release_allowed=false</footer>'
        )
        return _shell(language="en", body=body)

    is_dutch = view.notice.startswith(
        "NOT AUTHORIZED — NIET GEAUTORISEERD"
    )
    language = "nl" if is_dutch else "en"
    heading = (
        "NOT AUTHORIZED — NIET GEAUTORISEERD"
        if is_dutch else "NOT AUTHORIZED — REVIEW ONLY"
    )
    summary = (
        "Dit is uitsluitend een fictieve, niet-geauthenticeerde beoordeling."
        if is_dutch else
        "Fictional, unauthenticated human review preview only."
    )
    if view.status == "HOLD":
        label = "HOLD"
    else:
        label = "REVIEW_ONLY"
    # Escape both untrusted display text AND the generated metadata. A
    # producer could emit fake HTML or authority-looking content in notice.
    body = (
        '<header class="warning" role="alert"><span class="tag stop">'
        + escape(label) + '</span><h1>' + escape(heading) + '</h1><p>'
        + escape(summary) + '</p></header>'
        '<section aria-label="Fictional review text">'
        '<h2>' + ("Fictieve beoordeling" if is_dutch else "Fictional review")
        + '</h2><p class="meta">'
        + (f"Voorgestelde regels: {view.reviewed}" if is_dutch else
           f"Proposed entries: {view.reviewed}")
        + '</p><pre class="review-text">' + escape(view.notice)
        + '</pre></section>'
        '<footer>NOT AUTHORIZED · authorized=false · consent_verified=false · '
        'dispatch_allowed=false · release_allowed=false'
        '<p>' + (
            "Geen echte toestemming, grants, scanners of productiewijzigingen."
            if is_dutch else
            "No real consent, grants, scanning or production changes."
        ) + '</p></footer>'
    )
    # Reuse only self-contained static CSS and strict HTML CSP from the
    # existing review card. Add a static style for readable wrapped text.
    # Keep style inside <head>; no scripts, remote assets or links.
    page = _shell(language=language, body=body)
    return page.replace("</head>", _READONLY_STYLE + "</head>", 1)
