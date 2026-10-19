#!/usr/bin/env python3
"""Build offline single-file Casebook transfer. No network, auth, target or test execution."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")

def sha256_csp(value: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii") + "'"

def replace_exact(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError("Missing or ambiguous HTML source anchor: " + before[:75])
    return text.replace(before, after, 1)

def main() -> None:
    html = source("transfer.html")
    css = source("transfer.css")
    script = source("transfer.js")
    if "</style" in css.lower() or "</script" in script.lower():
        raise ValueError("Unsafe inline HTML closing tag in source")
    html = replace_exact(html, "script-src 'self'; style-src 'self'",
                         "script-src " + sha256_csp(script) + "; style-src " + sha256_csp(css))
    html = replace_exact(html, '<link rel="stylesheet" href="transfer.css">', "<style>" + css + "</style>")
    html = replace_exact(html, '<script src="transfer.js" defer></script>', "<script>" + script + "</script>")
    dest = ROOT / "standalone.html"
    dest.write_text(html, encoding="utf-8", newline="\n")
    print(f"{dest.name}: {dest.stat().st_size} bytes, SHA-256 {hashlib.sha256(dest.read_bytes()).hexdigest()}")

if __name__ == "__main__":
    main()
