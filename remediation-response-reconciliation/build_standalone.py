#!/usr/bin/env python3
"""Build the PRIVATE offline LightUp HUMAN response register; no network or assessment."""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "index.html"
STYLE = ROOT / "style.css"
SCRIPT = ROOT / "app.js"
OUTPUT = ROOT / "standalone.html"

CSS_MARKER = '<link rel="stylesheet" href="./style.css">'
JS_MARKER = '<script defer src="./app.js"></script>'
CSP_RE = re.compile(r'<meta http-equiv="Content-Security-Policy" content="[^"]+">')


def pinned(data: str) -> str:
    encoded = hashlib.sha256(data.encode("utf-8")).digest()
    return base64.b64encode(encoded).decode("ascii")


def build() -> str:
    html = TEMPLATE.read_text(encoding="utf-8")
    css = STYLE.read_text(encoding="utf-8")
    js = SCRIPT.read_text(encoding="utf-8")

    if html.count(CSS_MARKER) != 1 or html.count(JS_MARKER) != 1:
        raise ValueError("Expected exact standalone HTML template source links")
    if CSP_RE.findall(html).__len__() != 1:
        raise ValueError("Unexpected CSP template")
    if "</script" in js.lower() or "</style" in css.lower():
        raise ValueError("Embedded source contains closing tag delimiter")
    if any(x in html.lower() for x in ("http://", "https://")):
        raise ValueError("Offline template cannot contain external links")
    csp = (
        "default-src 'none'; "
        f"script-src 'sha256-{pinned(js)}'; "
        f"style-src 'sha256-{pinned(css)}'; "
        "connect-src 'none'; object-src 'none'; "
        "form-action 'none'; base-uri 'none'"
    )
    html = CSP_RE.sub(
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">', html
    )
    html = html.replace(CSS_MARKER, "<style>" + css + "</style>")
    html = html.replace(JS_MARKER, "<script>" + js + "</script>")

    if CSS_MARKER in html or JS_MARKER in html:
        raise ValueError("Unbundled relative resources remain")
    return html


def main() -> int:
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--check"):
        print("Usage: python3 build_standalone.py [--check]", file=sys.stderr)
        return 2
    try:
        output = build()
        data = output.encode("utf-8")
        if len(data) > 1024 * 1024:
            raise ValueError("Offline standalone exceeds 1 MiB")
        if len(sys.argv) == 2:
            if not OUTPUT.is_file() or OUTPUT.read_bytes() != data:
                print("HOLD: published HTML differs from pinned source build", file=sys.stderr)
                return 2
            print("Built artifact matches source: " + hashlib.sha256(data).hexdigest())
            return 0
        temp = OUTPUT.with_name(OUTPUT.name + ".tmp")
        temp.write_bytes(data)
        temp.replace(OUTPUT)
        print("Published PRIVATE offline standalone: " + hashlib.sha256(data).hexdigest())
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print("HOLD: cannot produce PRIVATE offline artifact: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
