#!/usr/bin/env python3
"""Build isolated LightUp lineage browser artifact; no network or assessments."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE_HTML = ROOT / "index.html"
SOURCE_JS = ROOT / "app.js"
SOURCE_CSS = ROOT / "style.css"
OUT = ROOT / "standalone.html"


def digest(raw: bytes) -> str:
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def build() -> None:
    html = SOURCE_HTML.read_text(encoding="utf-8")
    js = SOURCE_JS.read_text(encoding="utf-8")
    css = SOURCE_CSS.read_text(encoding="utf-8")
    assert "</script" not in js.lower() and "</style" not in css.lower()
    assert html.count('<script src="app.js" defer></script>') == 1
    assert html.count('<link rel="stylesheet" href="style.css">') == 1
    assert html.count("script-src 'self'") == 1
    assert html.count("style-src 'self'") == 1
    html = html.replace("script-src 'self'", "script-src 'sha256-" + digest(js.encode()) + "'")
    html = html.replace("style-src 'self'", "style-src 'sha256-" + digest(css.encode()) + "'")
    html = html.replace(
        '<link rel="stylesheet" href="style.css">', "<style>" + css + "</style>"
    )
    html = html.replace(
        '<script src="app.js" defer></script>', "<script>" + js + "</script>"
    )
    OUT.write_text(html, encoding="utf-8")
    print("Built offline " + OUT.name + " (" + str(OUT.stat().st_size) + " bytes)")
    print("SHA256 " + hashlib.sha256(OUT.read_bytes()).hexdigest())


if __name__ == "__main__":
    build()
