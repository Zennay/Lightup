#!/usr/bin/env python3
"""Build a self-contained, network-disabled human-review scope packet vault.

No runtime dependencies, no JS execution, no QA suite, and no network use.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent


def csp_hash(blob: str) -> str:
    digest = hashlib.sha256(blob.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def build() -> bytes:
    template = (HERE / "index.html").read_text(encoding="utf-8")
    js = (HERE / "vault.js").read_text(encoding="utf-8")
    css = (HERE / "style.css").read_text(encoding="utf-8")
    link = '<link rel="stylesheet" href="style.css">'
    script = '<script defer src="vault.js"></script>'
    if template.count(link) != 1 or template.count(script) != 1:
        raise ValueError("Unexpected source template — refusing ambiguous build")
    if "</style" in css.lower() or "</script" in js.lower():
        raise ValueError("Embedded HTML closing sequence — refusing unsafe build")
    css_inline = "\n" + css + "\n"
    js_inline = "\n" + js + "\n"
    expected = "script-src 'self'; style-src 'self';"
    if template.count(expected) != 1:
        raise ValueError("Unexpected CSP — refusing unsafe build")
    template = template.replace(
        expected,
        "script-src " + csp_hash(js_inline) + "; style-src " + csp_hash(css_inline) + ";",
        1,
    )
    template = template.replace(link, "<style>" + css_inline + "</style>", 1)
    template = template.replace(script, "<script>" + js_inline + "</script>", 1)
    if 'src="vault.js"' in template or 'href="style.css"' in template:
        raise ValueError("Unbundled source reference in standalone build")
    return template.encode("utf-8")


if __name__ == "__main__":
    output = HERE / "standalone.html"
    output.write_bytes(build())
    print("Wrote standalone.html; SHA-256 " + hashlib.sha256(output.read_bytes()).hexdigest())
