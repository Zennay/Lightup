"""Private offline HTML snapshot of requests belonging to one authenticated client.

A saved export is stale, unsigned sensitive client material; it proves neither
ongoing login nor consent, approval, grant, execution or asset ownership.
"""
from __future__ import annotations

from datetime import datetime, timezone
import html
import os
from pathlib import Path

from .domain import AssessmentRequestRecord


MAX_EXPORT_RECORDS = 200
MAX_EXPORT_BYTES = 2 * 1024 * 1024


def render_request_snapshot(records: list[AssessmentRequestRecord]) -> str:
    """HTML-escape every stored field; no JS, network, web forms or credentials."""
    if type(records) is not list or len(records) > MAX_EXPORT_RECORDS:
        raise ValueError("bounded export accepts at most 200 stored requests")
    esc = lambda value: html.escape(str(value), quote=True)
    cards = []
    for rec in records:
        assets = "".join("<li>" + esc(asset) + "</li>" for asset in rec.requested_assets[:80])
        notes = "<p>" + esc(rec.notes) + "</p>" if rec.notes else ""
        decided = esc(rec.decided_at) if rec.decided_at else "Not decided"
        cards.append(
            '<article class="request">'
            f'<div class="eyebrow">Request {esc(rec.request_id)}</div>'
            f'<h2>{esc(rec.status.value).replace("_", " ").title()}</h2>'
            f'<p>Requested {esc(rec.created_at)} · Decision: {decided}</p>'
            f'<p>Mode: {esc(rec.requested_mode.value)} · Requested risk: {int(rec.requested_risk)}</p>'
            f'<details><summary>Original proposed assets ({len(rec.requested_assets)})</summary>'
            f'<ul>{assets}</ul></details>{notes}'
            '<p class="warning">A request decision is not an authorization grant.</p>'
            '</article>'
        )
    total = len(records)
    time = esc(datetime.now(timezone.utc).isoformat())
    items = "".join(cards) if cards else "<p>No stored requests for this client.</p>"
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; "
        "connect-src 'none'; img-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<title>LightUp client request snapshot — offline</title>"
        "<style>:root{font:16px system-ui,sans-serif;color:#19283a;background:#f5f7fa}"
        "body{max-width:850px;margin:3rem auto;padding:0 1rem;line-height:1.55}"
        "h1{font-size:2rem}h2{margin:.25rem 0}.request{background:white;border:1px solid #ccd6df;"
        "border-radius:12px;padding:1rem 1.25rem;margin:1rem 0;overflow-wrap:anywhere}"
        ".eyebrow{font-size:.8rem;color:#48586b}.warning{font-weight:600}"
        "header{border-bottom:2px solid #243a53;padding-bottom:1rem}"
        "details{padding:.35rem 0}footer{padding:2rem 0;color:#48586b}"
        "</style></head><body><header><h1>Client assessment requests</h1>"
        "<p>Private offline snapshot, created " + time + "; " + str(total) + " requests.</p>"
        "<p class=\"warning\">REVIEW ONLY · NO AUTHORIZATION, CONSENT, GRANT, "
        "SCAN, DISPATCH OR RELEASE. This saved copy is unsigned and may be stale. "
        "An APPROVED request is not a scan permit. Reauthenticate in LightUp "
        "for current status; do not share this file publicly.</p></header>"
        "<main>" + items + "</main>"
        "<footer>LightUp · INCUBATE / PLAN-LAB ONLY · DRAFT-HOLD</footer>"
        "</body></html>"
    )


def save_private_snapshot(destination: Path, content: str) -> None:
    data = content.encode("utf-8")
    if not data or len(data) > MAX_EXPORT_BYTES:
        raise ValueError("private snapshot exceeds 2 MiB")
    if destination.suffix.lower() != ".html":
        raise ValueError("destination must use .html")
    # An existing file, including a symlink, must never be overwritten.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
