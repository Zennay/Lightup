#!/usr/bin/env python3
"""Publish a CSP SHA-256-pinned one-file PRIVATE offline HUMAN triage application.

The original Casework parser is embedded UNMODIFIED from the source-owned path.
The builder never runs a scan, contacts a network, verifies identity or grants authority.
"""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
import re
import tempfile

HUB = Path(__file__).resolve().parent
ROOT = HUB.parent
ORIGINAL = ROOT / "remediation-handoff-inbox" / "original-casework.js"
TARGET = HUB / "triage-standalone.html"
SOURCES = (ORIGINAL, HUB / "triage.js", HUB / "custody.js", HUB / "windows-overlay.js", HUB / "owner-actions.js")
STYLES = (HUB / "theme.css", HUB / "triage.css")
HTML = HUB / "triage.html"


def content(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Required original source absent, symlinked or oversized")
    return path.read_text(encoding="utf-8")


def csp_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode() + "'"


def build() -> bytes:
    html = content(HTML)
    stylesheet = "\n".join("/* original bundle source: " + str(p.relative_to(ROOT)) + " */\n" + content(p) for p in STYLES)
    javascript = "\n;\n".join("/* original bundle source: " + str(p.relative_to(ROOT)) + " */\n" + content(p) for p in SOURCES)
    if "</style" in stylesheet.lower() or "</script" in javascript.lower():
        raise ValueError("Inline closing-tag sequence in original source; HOLD")
    for name in ("theme.css", "triage.css"):
        tag = '<link rel="stylesheet" href="' + name + '">'
        if html.count(tag) != 1:
            raise ValueError("Original CSS link changed; HOLD")
        html = html.replace(tag, "<style>" + stylesheet + "</style>" if name == "theme.css" else "", 1)
    for name in ("../remediation-handoff-inbox/original-casework.js", "triage.js", "custody.js", "windows-overlay.js", "owner-actions.js"):
        tag = '<script src="' + name + '" defer></script>'
        if html.count(tag) != 1:
            raise ValueError("Original script dependency changed; HOLD")
        html = html.replace(tag, "", 1)
    html = html.replace('<a href="index.html">← Operations Hub</a>', '<a href="#intake">↑ Local source intake</a>', 1)
    old = r'<meta http-equiv="Content-Security-Policy" content="[^"]+">'
    policy = "default-src 'none'; script-src " + csp_hash(javascript) + "; style-src " + csp_hash(stylesheet) + "; " + (
        "connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; "
        "frame-src 'none'; form-action 'none'; base-uri 'none'")
    meta = '<meta http-equiv="Content-Security-Policy" content="' + policy + '">'
    html, changed = re.subn(old, lambda _: meta, html, count=1)
    if changed != 1 or html.count("</body>") != 1:
        raise ValueError("Unexpected triage template/CSP metadata; HOLD")
    # Original defer scripts execute only after parse; placing inline JS at end preserves that ordering.
    html = html.replace("</body>", "<script>" + javascript + "</script></body>", 1)
    if any(t in html for t in ('src="triage.js"', 'src="custody.js"', 'src="owner-actions.js"', "rel=\"stylesheet\"")):
        raise ValueError("Unexpected remote/sibling dependency in standalone")
    return html.encode("utf-8")


def main() -> None:
    data = build()
    handle, temporary = tempfile.mkstemp(prefix=".triage-standalone-", dir=HUB)
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
        os.replace(temporary, TARGET)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Published original-source offline HUMAN Inbox as one SHA-pinned HTML file ({len(data)} bytes).")


if __name__ == "__main__":
    main()
