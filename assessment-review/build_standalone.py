#!/usr/bin/env python3
"""Reproducibly assemble offline Lab Review Desk into a single local HTML file."""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "index.html").read_text(encoding="utf-8")
CSS = (HERE / "style.css").read_text(encoding="utf-8")
JS = (HERE / "review.js").read_text(encoding="utf-8")
if "</style" in CSS.lower() or "</script" in JS.lower():
    raise SystemExit("Unsafe inline terminator")
csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
def sha256(data: str) -> str:
    return base64.b64encode(hashlib.sha256(data.encode("utf-8")).digest()).decode("ascii")
secure = (
    "default-src 'none'; script-src 'sha256-" + sha256(JS) + "'; "
    "style-src 'sha256-" + sha256(CSS) + "'; "
    "connect-src 'none'; img-src 'none'; font-src 'none'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'"
)
assert SOURCE.count(csp) == 1
assert SOURCE.count('<link rel="stylesheet" href="style.css">') == 1
assert SOURCE.count('<script src="review.js" defer></script>') == 1
result = SOURCE.replace(csp, secure)
result = result.replace('<link rel="stylesheet" href="style.css">', "<style>" + CSS + "</style>")
result = result.replace('<script src="review.js" defer></script>', "<script>" + JS + "</script>")
(HERE / "standalone.html").write_text(result + "\n", encoding="utf-8")
print("Built assessment-review/standalone.html (offline, hashed-CSP)")
