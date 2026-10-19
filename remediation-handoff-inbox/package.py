#!/usr/bin/env python3
"""Build the LightUp offline HUMAN Evidence Handoff Inbox as one portable HTML file.

Offline packaging only: no target, account, scanner, unit suite, authorization,
original source rewrite, external API, network request or deployment.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

def fail(message: str) -> None:
    raise SystemExit("HOLD: " + message)

def hash_value(source: str) -> str:
    return base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")

source = (HERE / "index.html").read_text(encoding="utf-8")
style = (HERE / "style.css").read_text(encoding="utf-8")
script = (HERE / "app.js").read_text(encoding="utf-8")

style_tag = '<link rel="stylesheet" href="style.css">'
script_tag = '<script src="app.js"></script>'
old_csp = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; style-src \'self\'; connect-src \'none\'; img-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
if source.count(style_tag) != 1 or source.count(script_tag) != 1 or source.count(old_csp) != 1:
    fail("original UI entrypoint references changed; review before packaging")
if "</style" in style.lower() or "</script" in script.lower():
    fail("an embedded asset contains a closing HTML tag")

content_policy = (
    "default-src 'none'; "
    "script-src 'sha256-" + hash_value(script) + "'; "
    "style-src 'sha256-" + hash_value(style) + "'; "
    "connect-src 'none'; img-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)
output = source.replace(old_csp, '<meta http-equiv="Content-Security-Policy" content="' + content_policy + '">')
output = output.replace(style_tag, "<style>" + style + "</style>")
output = output.replace(script_tag, "<script>" + script + "</script>")

path = HERE / "standalone.html"
path.write_text(output, encoding="utf-8")
print("Published offline HUMAN app:", path)
print("UTF-8 size:", len(output.encode("utf-8")))
print("SHA-256:", hashlib.sha256(output.encode("utf-8")).hexdigest())
