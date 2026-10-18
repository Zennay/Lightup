"""Lossless, private, non-authorizing Studio scope handoff.

Unlike native client submission, this path retains excluded assets, planning
windows and proposed lab activities. It never calls DomainStore or authorizes
execution. Every supported proposal is for independent, authenticated review.
"""
from __future__ import annotations

from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path

from .client_proposal_intake import read_studio_draft

MAX_HANDOFF_BYTES = 2 * 1024 * 1024


def prepare_studio_handoff(filename: str) -> dict:
    source, sha = read_studio_draft(filename)
    blocked: list[dict[str, str]] = []
    def hold(code: str, message: str) -> None:
        blocked.append({"code": code, "reason": message})

    if source["excluded_assets"]:
        hold("EXCLUSIONS_NOT_PERSISTED",
             "The native request schema cannot retain or enforce excluded assets.")
    local = source["proposed_window_local"]
    utc = source.get("proposed_window_utc")
    if (local["start"] is not None or local["end"] is not None
            or utc is not None and utc["status"] != "unscheduled"):
        hold("PLANNING_WINDOW_NOT_PERSISTED",
             "Local/UTC planning data cannot be bound to the native request.")
    if source["proposed_activities"]["private_lab_network_checks"]:
        hold("PRIVATE_LAB_ACTIVITY",
             "Private-lab checks require a separate independently authorized workflow.")
    if source["requested_mode"] != "authorized_assessment":
        hold("ANALYSIS_ONLY_MODE",
             "An analysis_only proposal must not be converted to an active assessment.")

    return {
        "kind": "lightup.studio_scope_handoff",
        "schema_version": 1,
        "state": "LOCAL_REVIEW_ONLY",
        "source_file_sha256": sha,
        "browser_revision_sha256_unverified": source.get("scope_fingerprint_sha256"),
        "reviewed_at_utc": datetime.now(timezone.utc).isoformat(),
        "held_for_native_submission": bool(blocked),
        "held_constraints": blocked,
        "proposal": source,  # Preserve exact scope/exclusions/planning/notes; no field is dropped.
        "source_verified": False,
        "client_authenticated": False,
        "operator_approved": False,
        "client_consent": False,
        "operator_consent": False,
        "authorization": False,
        "grant_issued": False,
        "revocation_checked": False,
        "scan_allowed": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }


def render_studio_handoff(packet: dict) -> str:
    if packet.get("kind") != "lightup.studio_scope_handoff":
        raise ValueError("invalid Studio handoff type")
    source = packet["proposal"]
    esc = lambda value: html.escape(str(value), quote=True)
    items = lambda seq: "".join("<li><code>" + esc(value) + "</code></li>" for value in seq) or "<li>None declared</li>"
    rows = "".join(
        '<li><strong>' + esc(item["code"]) + '</strong>: '
        + esc(item["reason"]) + '</li>'
        for item in packet["held_constraints"]
    ) or "<li>Native intake constraints not triggered. This is still NOT authorized.</li>"
    local = source["proposed_window_local"]
    utc = source.get("proposed_window_utc") or {}
    activities = source["proposed_activities"]
    activity_items = "".join(
        "<li>" + esc(name.replace("_", " ")) + ": "
        + ("proposed" if value else "not proposed") + "</li>"
        for name, value in activities.items()
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; style-src \'unsafe-inline\'; '
        'script-src \'none\'; connect-src \'none\'; img-src \'none\'; '
        'form-action \'none\'; base-uri \'none\'; object-src \'none\'">'
        '<title>LightUp · Complete Studio proposal handoff</title>'
        '<style>:root{font:15px/1.6 system-ui,sans-serif;color:#eaf1fb;background:#0d1628}'
        '*{box-sizing:border-box}body{max-width:1100px;margin:auto;padding:2rem}'
        'h1{margin:.15rem 0}h2{font-size:1.15rem}.muted{color:#b3c4d6}'
        '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1rem}'
        '.card{background:#19283e;border:1px solid #435570;border-radius:13px;'
        'padding:1.3rem;margin:.8rem 0;overflow-wrap:anywhere}'
        '.warning{border:2px solid #e2b976;background:#34291e;padding:1.1rem;border-radius:10px}'
        'ul{padding-left:1.3rem}li{padding:.25rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
        'code{overflow-wrap:anywhere}footer{color:#b3c4d6;padding:1rem 0;border-top:1px solid #435570}'
        '@media print{:root{color:black;background:white}.card,.warning{color:black;background:white}}'
        '</style></head><body>'
        '<header><p class="muted">LIGHTUP · LOCAL STUDIO HANDOFF / PRIVATE</p>'
        '<h1>' + esc(source["proposal_name"]) + '</h1>'
        '<p>Client label (unverified): ' + esc(source["client_label"] or "Not given") + '</p>'
        '<p class="warning"><strong>LOCAL REVIEW ONLY · NO CONSENT, AUTHORIZATION, '
        'GRANT OR SCAN PERMISSION.</strong> Retaining restrictions here does not '
        'make them enforceable by the native request database. Independently '
        'authenticated client and operator review are still required. '
        'This HTML file is a sensitive unsigned snapshot.</p></header>'
        '<main><section class="card"><h2>Native request compatibility: '
        + ("HOLD" if packet["held_for_native_submission"] else "No automatic HOLD")
        + '</h2><ul>' + rows + '</ul>'
        '<p>Even without a listed HOLD, this offline packet does NOT submit a request.'
        '</p></section><div class="grid"><section class="card"><h2>Requested assets (not allowed)</h2>'
        '<ul>' + items(source["requested_assets"]) + '</ul></section>'
        '<section class="card"><h2>Excluded assets (must be enforced independently)</h2>'
        '<ul>' + items(source["excluded_assets"]) + '</ul></section></div>'
        '<section class="card"><h2>Requested mode and risk</h2><p>'
        + esc(source["requested_mode"]) + ' · risk ' + esc(source["requested_risk"])
        + ' / 4</p><h3>Proposed activities, not permissions</h3><ul>'
        + activity_items + '</ul></section>'
        '<section class="card"><h2>Time planning — not approved</h2>'
        '<p>Requested local: ' + esc(local["start"] or "—") + ' → '
        + esc(local["end"] or "—") + '</p>'
        '<p>Claimed UTC status: ' + esc(utc.get("status", "No UTC provenance"))
        + ' · source timezone: ' + esc(utc.get("timezone", "Not supplied")) + '</p>'
        '<p>Claimed UTC interval: ' + esc(utc.get("start") or "—")
        + ' → ' + esc(utc.get("end") or "—") + '</p>'
        '<p class="muted">The local/UTC correlation was parsed for consistency '
        'only; timezone identity and approval are not verified.</p></section>'
        '<section class="card"><h2>Purpose and STOP conditions</h2><pre>'
        + esc(source["notes"]) + '</pre></section>'
        '<section class="card"><h2>Untrusted version continuity</h2>'
        '<p>Exact file SHA-256: <code>' + esc(packet["source_file_sha256"])
        + '</code></p><p>Browser revision hash (not authenticated): <code>'
        + esc(packet["browser_revision_sha256_unverified"] or "Not present")
        + '</code></p><p>Generate a new handoff after any file change. A hash '
        'is neither a signature nor a consent record.</p></section>'
        '<section class="card"><h2>Next actions</h2><p>Keep the original Studio '
        'JSON with this privately generated dossier. Resolve every incompatible '
        'restriction in an independently reviewed, persistable domain workflow; '
        'do not delete exclusions or windows just to bypass an intake HOLD.'
        ' Obtain separate valid operator/client authorization and current '
        'revocation checks before any execution elsewhere.</p></section></main>'
        '<footer>INCUBATE M3/M7 · PLAN-LAB ONLY · DRAFT-HOLD · '
        'Do not publish private proposed assets or safety notes.</footer></body></html>'
    )


def save_studio_handoff(path: Path, packet: dict) -> None:
    """Create a new private HTML/JSON handoff without clobbering any existing file."""
    suffix = path.suffix.lower()
    if suffix == ".html":
        content = render_studio_handoff(packet).encode("utf-8")
    elif suffix == ".json":
        content = (json.dumps(packet, ensure_ascii=True, indent=2) + "\n").encode("ascii")
    else:
        raise ValueError("handoff output must be a new .html or .json file")
    if not content or len(content) > MAX_HANDOFF_BYTES:
        raise ValueError("handoff output exceeds 2 MiB")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
