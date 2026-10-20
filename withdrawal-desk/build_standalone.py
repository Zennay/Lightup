#!/usr/bin/env python3
"""Build the single-file LightUp Withdrawal Desk, without network or dependencies."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
html = (ROOT / "index.html").read_text(encoding="utf-8")
css = (ROOT / "style.css").read_text(encoding="utf-8")
js = (ROOT / "desk.js").read_text(encoding="utf-8")

def digest(body: str) -> str:
    return base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")

old_csp = '''<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'">'''
new_csp = (
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
    "script-src 'sha256-" + digest(js) + "'; "
    "style-src 'sha256-" + digest(css) + "'; "
    "img-src 'none'; connect-src 'none'; form-action 'none'; "
    "base-uri 'none'; object-src 'none'\">"
)
old_css = '<link rel="stylesheet" href="./style.css">'
old_js = '<script src="./desk.js" defer></script>'
if any(html.count(marker) != 1 for marker in (old_csp, old_css, old_js)):
    raise SystemExit("HOLD: source HTML markers changed; standalone not built")
if "</style" in css.lower() or "</script" in js.lower():
    raise SystemExit("HOLD: inline escape boundary found; standalone not built")

html = html.replace(old_csp, new_csp)
html = html.replace(old_css, "<style>" + css + "</style>")
html = html.replace(old_js, "<script>" + js + "</script>")
(ROOT / "standalone.html").write_text(html, encoding="utf-8")
print("Built standalone.html SHA-256", hashlib.sha256(html.encode("utf-8")).hexdigest())
