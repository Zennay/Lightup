#!/usr/bin/env python3
"""Publish a scriptless PRIVATE HUMAN byte-comparison brief, never authority."""
from __future__ import annotations
import hashlib
import html
import os
from pathlib import Path
import secrets
import shutil
import install

def publish(items: list[dict], original_receipt: bytes, destination: Path, warning: str) -> None:
    if (not destination.is_absolute() or destination.is_symlink()
            or destination.exists() or destination.parent != destination.parent.resolve(strict=True)):
        raise ValueError("Choose a new literal PRIVATE HTML report destination")
    install.owner_dir(destination.parent)
    receipt_sha = hashlib.sha256(original_receipt).hexdigest()
    rows = "".join(
        f"<tr><td>{item['slot']}</td><td>{item['bytes']}</td>"
        f"<td class='hash'>{html.escape(item['sha256'])}</td><td>BYTE MATCH ONLY</td></tr>"
        for item in items
    )
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN packet comparison</title>
<style>body{font:16px system-ui;color:#172f47;background:#eff3f7;margin:0}
main{max-width:960px;margin:35px auto;background:white;padding:30px;border-radius:13px}
h1{font-size:1.85rem}aside{padding:16px;background:#fff3de;border-left:5px solid #bd7b25;line-height:1.6}
table{border-collapse:collapse;width:100%;margin-top:20px}th,td{padding:11px 8px;border-bottom:1px solid #d3dbe3;text-align:left}
.hash{overflow-wrap:anywhere;font:12px/1.5 monospace}small{line-height:1.6;display:block;margin-top:20px}
@media(max-width:700px){main{margin:0;padding:18px}table{display:block;overflow-x:auto}}</style>
<main><h1>PRIVATE source-free packet comparison</h1>
<aside><strong>REVIEW_ONLY · DRAFT/HOLD · NEVER VERIFIED.</strong>
The selected local PRIVATE file bytes match a separately supplied, UNSIGNED
source-free SHA-256 receipt. This does NOT authenticate a sender, recipient,
client, disclosure approval, live authority, remediation or security finding.
No original file names or bytes are contained in this report.</aside>
<p>Matched locally selected slots: <strong>""" + str(len(items)) + """</strong>.
Original UNSIGNED receipt SHA-256 (PRIVATE): <code>""" + receipt_sha + """</code>.</p>
<table><thead><tr><th>Slot</th><th>Exact bytes</th><th>SHA-256</th>
<th>Limited result</th></tr></thead><tbody>""" + rows + """</tbody></table>
<small>""" + html.escape(warning) + """ Original native admission, independent
real consent including at-use revocation, security/privacy/browser/crypto
reviews, mandatory CI and explicit HUMAN GO remain required.</small></main></html>
""").encode("utf-8")
    receipt = {
        "kind": "lightup.private_unsigned_byte_comparison", "schema_version": 1,
        "disposition": "HUMAN_REVIEW_ONLY_DRAFT_HOLD",
        "authority_granted": False, "sender_authenticated": False,
        "consent_verified": False, "remediation_verified": False,
        "chronology_verified": False, "original_receipt_sha256": receipt_sha,
        "matched_files": items, "warning": warning,
    }
    stage = destination.parent / (".lightup-byte-report-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        install.write_file(stage / "index.html", page)
        install.write_file(stage / "private-byte-comparison.json", install.canonical(receipt))
        if destination.exists():
            raise ValueError("PRIVATE report destination appeared during publication")
        install.exclusive_publish(stage, destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: PRIVATE scriptless local HUMAN byte-comparison report created.")
