#!/usr/bin/env python3
"""Reproducible offline HTML bundle; no package dependencies or network."""
from __future__ import annotations
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent
html = (root / "index.html").read_text(encoding="utf-8")
css = (root / "style.css").read_text(encoding="utf-8")
js = (root / "app.js").read_text(encoding="utf-8")
def digest(value: str) -> str:
    import base64
    return base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")

policy = (
    "default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; "
    "frame-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; "
    f"style-src 'sha256-{digest(css)}'; script-src 'sha256-{digest(js)}'"
)
marker = '<meta name="viewport" content="width=device-width, initial-scale=1">'
assert html.count(marker) == 1
html = html.replace(marker, marker + '<meta http-equiv="Content-Security-Policy" content="' + policy + '">')
assert html.count('<link rel="stylesheet" href="style.css">') == 1
html = html.replace('<link rel="stylesheet" href="style.css">', '<style>' + css + '</style>')
assert html.count('<script src="app.js" defer></script>') == 1
html = html.replace('<script src="app.js" defer></script>', '<script>' + js + '</script>')
# Offline program contains no dependency on externally hosted pages.
html = html.replace('<a href="https://github.com/Zennay/Lightup/pull/1569">the separate operator readiness desk</a>', 'the separate operator readiness desk (PR #1569)')
(root / "standalone.html").write_text(html, encoding="utf-8")
print("standalone bytes", len(html.encode("utf-8")))
print("standalone sha256", hashlib.sha256(html.encode("utf-8")).hexdigest())
