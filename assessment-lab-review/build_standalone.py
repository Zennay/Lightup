#!/usr/bin/env python3
"""Build a portable offline Lab Review Desk with per-inline-asset CSP hashes.

Source-only bundler. Never reads lab outputs, models, targets, or network data.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "index.html"
OUT = HERE / "standalone.html"


def source_hash(text: str) -> str:
    value = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(value).decode("ascii") + "'"


def main() -> int:
    index = SRC.read_text(encoding="utf-8")
    css = (HERE / "style.css").read_text(encoding="utf-8")
    js = (HERE / "app.js").read_text(encoding="utf-8")
    if "</style" in css.lower() or "</script" in js.lower():
        raise ValueError("unsafe inline closing-tag token")
    old_policy = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                  "connect-src 'none'; img-src 'none'; font-src 'none'; "
                  "object-src 'none'; base-uri 'none'; form-action 'none'")
    policy = old_policy.replace("script-src 'self'", "script-src " + source_hash(js))
    policy = policy.replace("style-src 'self'", "style-src " + source_hash(css))
    if index.count(old_policy) != 1 or index.count('<link rel="stylesheet" href="style.css">') != 1:
        raise ValueError("source HTML or policy mismatch")
    if index.count('<script src="app.js" defer></script>') != 1:
        raise ValueError("source script mismatch")
    built = index.replace(old_policy, policy, 1)
    built = built.replace('<link rel="stylesheet" href="style.css">',
                          "<style>" + css + "</style>", 1)
    built = built.replace('<script src="app.js" defer></script>',
                          "<script>" + js + "</script>", 1)
    OUT.write_bytes(built.encode("utf-8"))
    print("portable offline HTML built:", OUT.name, OUT.stat().st_size, "bytes")
    print("SHA-256:", hashlib.sha256(OUT.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
