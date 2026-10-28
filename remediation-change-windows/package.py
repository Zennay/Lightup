#!/usr/bin/env python3
"""Build a standalone offline change-window board from exact pinned original Casework bytes.

This packages human review UI only. It never runs LightUp, accesses private data,
starts a scanner, authorizes a target or triggers a retest.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "remediation-change-windows"
ORIGINAL = ROOT / "remediation-capacity" / "casework-original-v1.js"
PINNED_ORIGINAL_SHA256 = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"


def build() -> Path:
    original = ORIGINAL.read_bytes()
    if hashlib.sha256(original).hexdigest() != PINNED_ORIGINAL_SHA256:
        raise SystemExit("HOLD: original source-owner Casework module changed.")
    html = (HERE / "index.html").read_text(encoding="utf-8")
    own_js = (HERE / "board.js").read_bytes()
    original_js = original.decode("utf-8", "strict")
    board_js = own_js.decode("utf-8", "strict")
    for script in (original_js, board_js):
        if re.search(r"</\s*script", script, flags=re.I):
            raise SystemExit("HOLD: script cannot be embedded literally.")

    embedded = [
        ('<script src="../remediation-capacity/casework-original-v1.js"></script>', original_js),
        ('<script src="board.js"></script>', board_js),
    ]
    hashes = []
    for marker, source in embedded:
        if html.count(marker) != 1:
            raise SystemExit("HOLD: original script order or reference changed.")
        raw = source.encode("utf-8")
        hashes.append("'sha256-" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii") + "'")
        html = html.replace(marker, "<script>" + source + "</script>", 1)

    if html.count("script-src 'self'") != 1:
        raise SystemExit("HOLD: original CSP source contract changed.")
    html = html.replace("script-src 'self'", "script-src " + " ".join(hashes), 1)
    if 'connect-src \'none\'' not in html:
        raise SystemExit("HOLD: network denial policy missing.")
    output = HERE / "standalone.html"
    content = html.encode("utf-8")
    tmp = HERE / ".standalone.build.tmp"
    tmp.write_bytes(content)
    tmp.replace(output)
    print(f"Built {output.name}: {len(content)} bytes; sha256={hashlib.sha256(content).hexdigest()}")
    return output


if __name__ == "__main__":
    build()
