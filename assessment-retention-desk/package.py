#!/usr/bin/env python3
"""Create one 0600 offline browser artifact with exact inline CSP SHA-256 pins.

Source is only these four trusted local product files. Never accesses assessment
data, network, subprocess, user credentials or target assets.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from pathlib import Path
import re

from history import Hold, publish_private


ROOT = Path(__file__).resolve().parent
CSP_TEMPLATE = """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">"""
CSS_TAG = '<link rel="stylesheet" href="desk.css">'
JS_TAG = '<script src="desk.js" defer></script>'
VAULT_TAG = '<script src="vault.js" defer></script>'


def read_source(name, cap):
    path = ROOT / name
    try:
        payload = path.read_bytes()
        if not 1 <= len(payload) <= cap:
            raise Hold("missing or oversized local product component")
        return payload.decode("utf-8", "strict")
    except (OSError, UnicodeError) as exc:
        raise Hold("could not read trusted UTF-8 local product source") from exc


def once(haystack, needle, replacement):
    if haystack.count(needle) != 1:
        raise Hold("original HTML source/layout differs from expected product version")
    return haystack.replace(needle, replacement, 1)


def csp_sha(value):
    digest = hashlib.sha256(value.encode("utf-8", "strict")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def bundle():
    html = read_source("index.html", 100_000)
    css = read_source("desk.css", 100_000)
    js = read_source("desk.js", 200_000)
    vault = read_source("vault.js", 200_000)
    # Source HTML needs distinct inert placeholders; refuse script/style terminator
    # sequences in the bundled assets rather than letting an inline element escape.
    if re.search(r"</\s*(script|style)\b", js + "\n" + vault + "\n" + css, re.IGNORECASE):
        raise Hold("unsafe inline style/script terminator in source")
    csp = (
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "script-src " + csp_sha(js) + " " + csp_sha(vault) + "; style-src " + csp_sha(css) + "; "
        "img-src 'none'; connect-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'\">"
    )
    html = once(html, CSP_TEMPLATE, csp)
    html = once(html, CSS_TAG, "<style>" + css + "</style>")
    html = once(html, JS_TAG, "")
    html = once(html, VAULT_TAG, "")
    html = once(html, "</body>", "<script>" + js + "</script>\n<script>" + vault + "</script>\n</body>")
    if 'src="desk.js"' in html or 'src="vault.js"' in html or 'href="desk.css"' in html:
        raise Hold("external source reference left in purported standalone product")
    return html


def main():
    p = argparse.ArgumentParser(
        description="Build one source-hash-CSP-pinned, local-only LightUp retention desk (no assessment action).")
    p.add_argument("--output", required=True,
                   help="New HTML path under an existing private 0700 directory")
    args = p.parse_args()
    try:
        product = bundle()
        publish_private(args.output, product)
    except Hold as exc:
        p.exit(2, "HOLD: " + str(exc) + "\n")
    print("PRIVATE CSP-hash-pinned single-file offline workroom created (non-authorizing).")


if __name__ == "__main__":
    main()
