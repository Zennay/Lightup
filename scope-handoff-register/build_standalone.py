#!/usr/bin/env python3
"""Bundle the wholly offline review-only handoff UI into one integrity-pinned HTML file."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAGE = ROOT / "index.html"
JS = ROOT / "app.js"
CSS = ROOT / "style.css"
OUT = ROOT / "standalone.html"


def pin(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def main() -> None:
    html = PAGE.read_text(encoding="utf-8")
    javascript = JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    if "</script" in javascript.lower() or "</style" in css.lower():
        raise ValueError("Unsafe inline HTML terminator in bundle")
    original = "script-src 'self'; style-src 'self'"
    assert html.count(original) == 1, "Expected exactly one strict CSP template"
    html = html.replace(original, "script-src " + pin(javascript) + "; style-src " + pin(css), 1)
    source_style = '<link rel="stylesheet" href="./style.css">'
    source_script = '<script src="./app.js" defer></script>'
    assert html.count(source_style) == html.count(source_script) == html.count("</body>") == 1
    html = html.replace(source_style, "<style>" + css + "</style>", 1)
    html = html.replace(source_script, "", 1)
    html = html.replace("</body>", "<script>" + javascript + "</script>\n</body>", 1)
    OUT.write_text(html, encoding="utf-8")
    print(f"Built {OUT.name}: {len(html.encode('utf-8'))} bytes; SHA-256={hashlib.sha256(html.encode('utf-8')).hexdigest()}")


if __name__ == "__main__":
    main()
