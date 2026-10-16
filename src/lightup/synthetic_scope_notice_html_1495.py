"""Standalone, self-contained human-visible fictional scope review. No authority.

The HTML is deliberately inert: no links, forms, network, JS, images or
external assets. This module never contacts a real target or consent store.
"""
from __future__ import annotations

from datetime import datetime
from html import escape

from .synthetic_scope_notice_1495 import ScopeProposal, render_scope_notice

_MAX_HTML = 65536

_CSS = """
:root{color-scheme:dark;--bg:#10131b;--panel:#1b2130;--line:#334158;
--muted:#b9c7d8;--ink:#f2f6ff;--danger:#ffb2b8;--warn:#ffdba4}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.55 system-ui,-apple-system,Segoe UI,Arial,sans-serif}
main{max-width:1040px;margin:auto;padding:clamp(20px,5vw,60px)}
header,section,footer{background:var(--panel);border:1px solid var(--line);
border-radius:14px;padding:clamp(18px,3vw,30px);margin-bottom:18px}
h1{font-size:clamp(1.6rem,4vw,2.5rem);line-height:1.2;margin:0 0 14px}
h2{font-size:1.22rem;margin:0 0 12px}p{margin:8px 0}
strong,th{font-weight:750}.warning{border:2px solid #ed7180}
.warning h1,.stop{color:var(--danger)}.risk{color:var(--warn)}
.meta{color:var(--muted)}.tag{display:inline-block;border:1px solid currentColor;
border-radius:20px;padding:3px 12px;font-weight:700;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{border-bottom:1px solid var(--line);padding:13px 10px;text-align:left}
th{color:var(--muted)}td{overflow-wrap:anywhere}
.wrap{overflow-x:auto}code{font:inherit;color:#d9e8ff}
.metrics{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}.metric{flex:1 1 155px;
background:var(--bg);padding:12px;border:1px solid var(--line);border-radius:9px}
.metric strong{display:block;font-size:1.1rem}.gates{padding-left:25px}
.gates li{margin:7px 0}.pending{color:var(--warn);font-weight:750}
footer{color:var(--muted)}.sr-only{position:absolute;width:1px;height:1px;
padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:640px){table{min-width:650px}main{padding:16px}}
@media print{:root{color-scheme:light}body{background:white;color:#111}
header,section,footer{break-inside:avoid;background:white;color:#111}
.warning h1,.stop{color:#ad001b}.meta,th{color:#333}th,td{border-color:#bbb}}
"""


def _shell(*, language: str, body: str) -> str:
    title = "Fictieve scopebeoordeling" if language == "nl" else "Fictional scope review"
    # No remote resources, no JS, no forms, even if this is saved as a local
    # HTML file and opened in a browser.
    return (
        "<!doctype html>\n<html lang=\"" + language + "\"><head>"
        "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; script-src 'none'; connect-src 'none'; "
        "img-src 'none'; font-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'none'; base-uri 'none'\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        "<title>" + escape(title) + " — NOT AUTHORIZED</title>"
        "<style>" + _CSS + "</style></head><body><main>" + body +
        "</main></body></html>\n"
    )


def render_synthetic_scope_html(
    proposals: tuple[ScopeProposal, ...],
    *,
    review_at: datetime,
    language: str = "en",
) -> str:
    """Inert HTML preview, always NOT AUTHORIZED; caller data is untrusted.

    The already existing pure notice policy remains the sole admission shape
    checker. HOLD renders a generic HTML page without any input echo.
    """
    # Freeze one private copy BEFORE review: a caller can use object.__setattr__
    # even on a frozen dataclass and mutate a record between the policy check
    # and HTML rendering. Never re-read the caller-owned objects afterwards.
    try:
        if type(proposals) is tuple and 1 <= len(proposals) <= 32 and all(
            type(p) is ScopeProposal for p in proposals
        ):
            snapshot = tuple(
                ScopeProposal(p.asset, p.capability, p.risk, p.valid_from, p.valid_until)
                for p in proposals
            )
        else:
            snapshot = ()
    except (AttributeError, TypeError, ValueError):
        snapshot = ()
    notice = render_scope_notice(snapshot, review_at=review_at, language=language)
    locale = language if type(language) is str and language in ("en", "nl") else "en"
    dutch = locale == "nl"
    banner = (
        "NOT AUTHORIZED — NIET GEAUTORISEERD"
        if dutch else "NOT AUTHORIZED — NO EXECUTION PERMISSION"
    )
    if notice.status != "REVIEW_ONLY":
        reason = (
            "De opgegeven fictieve scope is afgewezen. Er is niets goedgekeurd, "
            "geverifieerd of uitgevoerd."
            if dutch else
            "The proposed fictional scope was rejected. Nothing has been "
            "approved, verified or executed."
        )
        body = (
            "<header class=\"warning\" role=\"alert\">"
            "<span class=\"tag stop\">HOLD</span><h1>" + escape(banner) + "</h1>"
            "<p>" + escape(reason) + "</p></header>"
            "<footer>HOLD · authorized=false · consent_verified=false · "
            "dispatch_allowed=false · release_allowed=false</footer>"
        )
        return _shell(language=locale, body=body)

    # Every entry has been type and shape validated by the pure reviewer;
    # still escape absolutely every displayed value.
    rows = []
    for proposal in sorted(snapshot, key=lambda x: (x.asset, x.capability)):
        start = proposal.valid_from.isoformat().replace("+00:00", "Z")
        end = proposal.valid_until.isoformat().replace("+00:00", "Z")
        rows.append(
            "<tr><td><code>" + escape(proposal.asset) + "</code></td>"
            "<td><code>" + escape(proposal.capability) + "</code></td>"
            "<td>" + str(proposal.risk) + "/5</td>"
            "<td><time datetime=\"" + escape(start) + "\">" + escape(start) + "</time></td>"
            "<td><time datetime=\"" + escape(end) + "\">" + escape(end) + "</time></td></tr>"
        )
    labels = (
        ("Voorgesteld bereik", "Fictieve voorstellen", "Beoordeling (UTC)",
         "Systeem", "Handeling", "Risico", "Vanaf", "Tot")
        if dutch else
        ("Proposed scope", "Fictional proposals", "Review instant (UTC)",
         "Asset", "Capability", "Risk", "From", "Until")
    )
    intro = (
        "Geen klanttoestemming, operatoridentiteit of uitvoeringsrecht "
        "geverifieerd. Deze kaart is alleen geschikt voor menselijke beoordeling."
        if dutch else
        "No client consent, operator identity or execution authority has been "
        "verified. This is a human review preview only."
    )
    risk_text = (
        "Hoog risico: aparte bevestiging en onafhankelijke menselijke toets nodig."
        if dutch else
        "High risk: independent step-up and human security review required."
    ) if notice.elevated_risk else (
        "Iedere scope vereist een onafhankelijke menselijke toets."
        if dutch else
        "Every proposed scope requires independent human review."
    )
    unique_assets = len({p.asset for p in snapshot})
    elevated_count = sum(1 for p in snapshot if p.risk >= 4)
    earliest_expiry = min(p.valid_until for p in snapshot).isoformat().replace("+00:00", "Z")
    metric_labels = (
        ("Fictieve systemen", "Hoog risico", "Eerste verloopmoment (UTC)")
        if dutch else ("Fictional assets", "Elevated risks", "Earliest expiry (UTC)")
    )
    metrics_html = (
        "<div class=\"metrics\" aria-label=\""
        + ("Overzicht fictieve scope" if dutch else "Fictional scope summary") + "\">"
        + "".join(
            "<div class=\"metric\"><span class=\"meta\">" + escape(label)
            + "</span><strong>" + escape(str(value)) + "</strong></div>"
            for label, value in zip(
                metric_labels, (unique_assets, elevated_count, earliest_expiry)
            )
        ) + "</div>"
    )
    gates = (
        ("Verifieer klant- en operatoridentiteit onafhankelijk",
         "Laat scope, tijdvenster en referentie door bronhouder valideren",
         "Toets duurzame intrekking bij daadwerkelijk gebruik",
         "Verkrijg onafhankelijke security-/privacyreview en expliciete menselijke GO")
        if dutch else
        ("Independently authenticate client and operator identities",
         "Verify exact scope, time window and reference with source owner",
         "Verify durable revocation at actual time of use",
         "Obtain independent security/privacy review and explicit human GO")
    )
    gate_heading = "Open vrijgavevoorwaarden" if dutch else "Outstanding release requirements"
    gates_html = (
        "<section aria-labelledby=\"gates-title\"><h2 id=\"gates-title\">"
        + escape(gate_heading) + "</h2>"
        + "<ol class=\"gates\">"
        + "".join(
            "<li><span class=\"pending\">PENDING — </span>"
            + escape(gate) + "</li>" for gate in gates
        ) + "</ol></section>"
    )
    body = (
        "<header class=\"warning\" role=\"alert\">"
        "<span class=\"tag stop\">REVIEW_ONLY</span><h1>" + escape(banner) + "</h1>"
        "<p>" + escape(intro) + "</p></header>"
        "<section aria-labelledby=\"scope-title\"><h2 id=\"scope-title\">"
        + escape(labels[0]) + "</h2><p class=\"meta\">"
        + escape(labels[1]) + ": " + str(notice.reviewed)
        + " · " + escape(labels[2]) + ": "
        + escape(review_at.isoformat().replace("+00:00", "Z")) + "</p>"
        + metrics_html +
        "<div class=\"wrap\"><table><thead><tr>"
        + "".join("<th scope=\"col\">" + escape(label) + "</th>"
                  for label in labels[3:])
        + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>"
        "<section aria-labelledby=\"risk-title\"><h2 id=\"risk-title\">"
        + ("Risicocontrole" if dutch else "Risk review") + "</h2>"
        "<p class=\"risk\">" + escape(risk_text) + "</p></section>"
        + gates_html +
        "<footer>NOT AUTHORIZED · authorized=false · consent_verified=false · "
        "dispatch_allowed=false · release_allowed=false"
        "<p>" + (
            "Geen echte systemen, scans, toestemming, grants, handlers of "
            "productiewijzigingen toegestaan."
            if dutch else
            "No real assets, scans, consent, grants, handlers or production changes."
        ) + "</p></footer>"
    )
    page = _shell(language=locale, body=body)
    if len(page) > _MAX_HTML:
        return _shell(
            language=locale,
            body="<header class=\"warning\" role=\"alert\"><h1>NOT AUTHORIZED — HOLD</h1>"
                 "<p>Fictional review size rejected.</p></header>",
        )
    return page
