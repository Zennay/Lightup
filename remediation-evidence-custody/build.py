#!/usr/bin/env python3
"""Deterministic PRIVATE offline browser bundle; source-owner Casework remains unchanged."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXPECTED_ORIGINAL_SHA = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"

def _pin(value: str) -> str:
    return base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")

def build() -> bytes:
    source = (ROOT / "index.template.html").read_text(encoding="utf-8")
    css = (ROOT / "style.css").read_text(encoding="utf-8").strip()
    script = (ROOT / "custody.js").read_text(encoding="utf-8").strip()
    original = (ROOT.parent / "casework" / "remediation-engine.js").read_text(encoding="utf-8")
    if hashlib.sha256(original.encode("utf-8")).hexdigest() != EXPECTED_ORIGINAL_SHA:
        raise ValueError("Original Casework parser drift: HUMAN HOLD.")
    parts = {
        "__STYLE_HASH__": _pin(css),
        "__SCRIPT_HASH__": _pin(script),
        "__ORIGINAL_HASH__": _pin(original),
        "__STYLE__": css,
        "__SCRIPT__": script,
        "__ORIGINAL_JS__": original,
    }
    for marker in parts:
        if source.count(marker) != 1:
            raise ValueError("Missing/duplicate HTML placeholder: " + marker)
    result = source
    for key, value in parts.items():
        result = result.replace(key, value)
    if any(marker in result for marker in parts):
        raise ValueError("Unresolved HTML placeholder: HUMAN HOLD.")
    if "connect-src 'none'" not in result:
        raise ValueError("Offline CSP changed: HUMAN HOLD.")
    return result.encode("utf-8")

if __name__ == "__main__":
    content = build()
    path = ROOT / "standalone.html"
    path.write_bytes(content)
    print("Offline PRIVATE HUMAN app", len(content), "bytes, SHA-256", hashlib.sha256(content).hexdigest())
