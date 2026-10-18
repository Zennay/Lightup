#!/usr/bin/env python3
"""Build the private, offline LightUp permission brief with CSP hash pins.

This is a deterministic product packaging command, not a QA/test runner.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "index.html"
STYLE = ROOT / "style.css"
SCRIPT = ROOT / "app.js"
OUTPUT = ROOT / "standalone.html"

def csp_digest(content: str) -> str:
    encoded = base64.b64encode(hashlib.sha256(content.encode("utf-8")).digest()).decode("ascii")
    return f"'sha256-{encoded}'"

def build() -> None:
    page = TEMPLATE.read_text(encoding="utf-8")
    css = STYLE.read_text(encoding="utf-8")
    js = SCRIPT.read_text(encoding="utf-8")

    stylesheet = '<link rel="stylesheet" href="./style.css">'
    external_script = '<script src="./app.js" defer></script>'
    old_policy = "script-src 'self'; style-src 'self';"
    inline_js, inline_css = "\
" + js + "\
", "\
" + css + "\
"
    new_policy = f"script-src {csp_digest(inline_js)}; style-src {csp_digest(inline_css)};"

    if (page.count(stylesheet) != 1 or page.count(external_script) != 1
            or page.count(old_policy) != 1 or page.count("</body>") != 1):
        raise RuntimeError("Unexpected source HTML; refuse to package ambiguous dependencies")
    if "</style" in css.lower() or "</script" in js.lower():
        raise RuntimeError("Embedded HTML terminator found; refuse to package")
    page = page.replace(stylesheet, f"<style>{inline_css}</style>", 1)
    page = page.replace(external_script, "", 1)
    page = page.replace(old_policy, new_policy, 1)
    # Inline script must follow the DOM, unlike the deferred external source version.
    page = page.replace("</body>", f"<script>{inline_js}</script>\n</body>", 1)
    OUTPUT.write_text(page, encoding="utf-8", newline="\n")
    sha256 = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print(f"Built {OUTPUT.name}: sha256:{sha256}")

if __name__ == "__main__":
    build()
