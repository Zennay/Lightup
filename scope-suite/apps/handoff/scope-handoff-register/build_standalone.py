#!/usr/bin/env python3
"""Bundle the wholly offline review-only handoff UI into one integrity-pinned HTML file."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAGE = ROOT / "index.html"
SCRIPTS = ("studio-network-v1.js", "studio-fingerprint-v1.js", "studio-window-v1.js", "human-coordination.js", "permission-reply-import.js", "withdrawal-import.js", "app.js")
CSS = ROOT / "style.css"
OUT = ROOT / "standalone.html"


def pin(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def main() -> None:
    html = PAGE.read_text(encoding="utf-8")
    scripts = [(name, (ROOT / name).read_text(encoding="utf-8")) for name in SCRIPTS]
    css = CSS.read_text(encoding="utf-8")
    if any("</script" in js.lower() for _, js in scripts) or "</style" in css.lower():
        raise ValueError("Unsafe inline HTML terminator in bundle")
    original = "script-src 'self'; style-src 'self'"
    assert html.count(original) == 1, "Expected exactly one strict CSP template"
    html = html.replace(original, "script-src " + " ".join(pin(js) for _, js in scripts) + "; style-src " + pin(css), 1)
    source_style = '<link rel="stylesheet" href="./style.css">'
    assert html.count(source_style) == 1 and html.count("</body>") == 1
    html = html.replace(source_style, "<style>" + css + "</style>", 1)
    for name, javascript in scripts:
        source_script = f'<script src="./{name}" defer></script>'
        assert html.count(source_script) == 1, "Missing or duplicated script " + name
        html = html.replace(source_script, "", 1)
    # All four scripts keep the same source order: Studio parsing -> fingerprint -> time -> app.
    html = html.replace("</body>", "".join("<script>" + js + "</script>\\n" for _, js in scripts) + "</body>", 1)
    OUT.write_text(html, encoding="utf-8")
    print(f"Built {OUT.name}: {len(html.encode('utf-8'))} bytes; SHA-256={hashlib.sha256(html.encode('utf-8')).hexdigest()}")


if __name__ == "__main__":
    main()
