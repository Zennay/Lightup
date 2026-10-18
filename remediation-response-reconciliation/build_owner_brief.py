#!/usr/bin/env python3
"""Deterministically package read-only PRIVATE human owner brief; no network."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from build_standalone import CSP_RE, ROOT, pinned

TEMPLATE = ROOT / "owner-brief.html"
JS = ROOT / "owner-brief.js"
CSS = ROOT / "style.css"
OUTPUT = ROOT / "owner-brief-standalone.html"
SCRIPT = '<script defer src="./owner-brief.js"></script>'
STYLE = '<link rel="stylesheet" href="./style.css">'


def build() -> str:
    template = TEMPLATE.read_text(encoding="utf-8")
    js = JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    if template.count(SCRIPT) != 1 or template.count(STYLE) != 1:
        raise ValueError("Owner brief requires exact local script/style template links")
    if len(CSP_RE.findall(template)) != 1:
        raise ValueError("Unexpected owner brief CSP source")
    if "</script" in js.lower() or "</style" in css.lower():
        raise ValueError("Embedded script/style contains closing delimiter")
    if "http://" in template.lower() or "https://" in template.lower():
        raise ValueError("Owner brief must remain offline")
    csp = (
        "default-src 'none'; "
        f"script-src 'sha256-{pinned(js)}'; "
        f"style-src 'sha256-{pinned(css)}'; "
        "connect-src 'none'; object-src 'none'; "
        "form-action 'none'; base-uri 'none'"
    )
    merged = CSP_RE.sub(
        '<meta http-equiv="Content-Security-Policy" content="' + csp + '">', template
    )
    merged = merged.replace(STYLE, "<style>" + css + "</style>")
    merged = merged.replace(SCRIPT, "<script>" + js + "</script>")
    if STYLE in merged or SCRIPT in merged:
        raise ValueError("Unbundled owner brief assets remain")
    return merged


def main() -> int:
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--check"):
        print("Usage: python3 build_owner_brief.py [--check]", file=sys.stderr)
        return 2
    try:
        content = build().encode("utf-8")
        if len(content) > 1024 * 1024:
            raise ValueError("Owner brief exceeds 1 MiB")
        if len(sys.argv) == 2:
            if not OUTPUT.is_file() or OUTPUT.read_bytes() != content:
                print("HOLD: standalone owner brief differs from local source", file=sys.stderr)
                return 2
        else:
            temp = OUTPUT.with_name(OUTPUT.name + ".tmp")
            temp.write_bytes(content)
            temp.replace(OUTPUT)
        print("PRIVATE owner brief sha256=" + hashlib.sha256(content).hexdigest())
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
