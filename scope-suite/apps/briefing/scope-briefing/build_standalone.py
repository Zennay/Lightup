#!/usr/bin/env python3
"""Package the owned offline briefing sources as one CSP-pinned standalone HTML file."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
STYLE = ROOT / "style.css"
SCRIPT = ROOT / "app.js"
DEST = ROOT / "standalone.html"


def pin(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def build() -> None:
    markup = INDEX.read_text(encoding="utf-8")
    style = STYLE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")

    # Static-owned sources only: never interpolate untrusted files or runtime proposals.
    for source in (style, script):
        if "</style" in source.lower() or "</script" in source.lower():
            raise ValueError("unsafe HTML close marker in owned source")
    old_csp = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; "
        "connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'"
    )
    inline_style = "\n" + style + "\n"
    inline_script = "\n" + script + "\n"
    new_csp = (
        "default-src 'none'; script-src " + pin(inline_script.encode("utf-8")) +
        "; style-src " + pin(inline_style.encode("utf-8")) +
        "; img-src 'none'; connect-src 'none'; form-action 'none'; "
        "base-uri 'none'; object-src 'none'"
    )
    if markup.count(old_csp) != 1:
        raise ValueError("expected exactly one source CSP")
    markup = markup.replace(old_csp, new_csp)
    link = '<link rel="stylesheet" href="./style.css">'
    js = '<script defer src="./app.js"></script>'
    if markup.count(link) != 1 or markup.count(js) != 1:
        raise ValueError("expected one owned style and script reference")
    markup = markup.replace(link, "<style>" + inline_style + "</style>")
    markup = markup.replace(js, "").replace("</body>", "<script>" + inline_script + "</script>\n</body>")
    DEST.write_text(markup, encoding="utf-8")
    print(f"built {DEST.name} bytes={DEST.stat().st_size} sha256={hashlib.sha256(DEST.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    build()
