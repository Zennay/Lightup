#!/usr/bin/env python3
"""Build a self-contained DRAFT/HOLD tabletop with content-hash-bound inline assets.

No target/network/runtime imports. Reproducible from the three sibling source files.
This builds a fictional local educational aid, not actual authorization.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
HTML = ROOT / "index.html"
CSS = ROOT / "style.css"
JS = ROOT / "app.js"
OUTPUT = ROOT / "standalone.html"


def sha_pin(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def replace_once(haystack: str, old: str, new: str) -> str:
    if haystack.count(old) != 1:
        raise ValueError("Expected exactly one source asset/CSP marker: " + old[:64])
    return haystack.replace(old, new, 1)


def build() -> bytes:
    html = HTML.read_text("utf-8")
    css = CSS.read_text("utf-8")
    js = JS.read_text("utf-8")
    if not (html and css and js) or len(html) > 40_000 or len(css) > 60_000 or len(js) > 120_000:
        raise ValueError("Source missing or beyond the fixed local build bounds")
    if "</style" in css.lower() or "</script" in js.lower():
        raise ValueError("Inline-asset HTML terminator not supported")
    html = replace_once(html, "style-src 'self'", "style-src '" + sha_pin(css) + "'")
    html = replace_once(html, "script-src 'self'", "script-src '" + sha_pin(js) + "'")
    html = replace_once(html, '<link rel="stylesheet" href="style.css">', "<style>" + css + "</style>")
    html = replace_once(html, '<script defer src="app.js"></script>', "<script>" + js + "</script>")
    if 'src="app.js"' in html or 'href="style.css"' in html:
        raise ValueError("External companion asset reference remains")
    return html.encode("utf-8")


def main() -> int:
    if sys.argv[1:]:
        print("Usage: python3 build.py (no arguments)", file=sys.stderr)
        return 2
    data = build()
    # The output is a product artifact; fixed path, never arbitrary destinations.
    if len(data) > 220_000:
        raise ValueError("Standalone exceeds bounded build size")
    OUTPUT.write_bytes(data)
    print(f"built={OUTPUT.name} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
