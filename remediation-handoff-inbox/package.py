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
human_plan = (HERE / "human-workplan.js").read_text(encoding="utf-8")
original_casework = (HERE / "original-casework.js").read_text(encoding="utf-8")
original_casework_pin = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
if hashlib.sha256(original_casework.encode("utf-8")).hexdigest() != original_casework_pin:
    fail("original Casework parser differs from immutable owner-source SHA-256 pin")

style_tag = '<link rel="stylesheet" href="style.css">'
script_tag = '<script src="app.js"></script>'
plan_tag = '<script src="human-workplan.js"></script>'
original_tag = '<script src="original-casework.js"></script>'
old_csp = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; style-src \'self\'; connect-src \'none\'; img-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
if source.count(style_tag) != 1 or source.count(script_tag) != 1 or source.count(plan_tag) != 1 or source.count(original_tag) != 1 or source.count(old_csp) != 1:
    fail("original UI entrypoint references changed; review before packaging")
if "</style" in style.lower() or "</script" in script.lower() or "</script" in original_casework.lower() or "</script" in human_plan.lower():
    fail("an embedded asset contains a closing HTML tag")

content_policy = (
    "default-src 'none'; "
    "script-src 'sha256-" + hash_value(original_casework) + "' 'sha256-" + hash_value(script) + "' 'sha256-" + hash_value(human_plan) + "'; "
    "style-src 'sha256-" + hash_value(style) + "'; "
    "connect-src 'none'; img-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)
output = source.replace(old_csp, '<meta http-equiv="Content-Security-Policy" content="' + content_policy + '">')
output = output.replace(style_tag, "<style>" + style + "</style>")
output = output.replace(original_tag, "<script>" + original_casework + "</script>")
output = output.replace(script_tag, "<script>" + script + "</script>")
output = output.replace(plan_tag, "<script>" + human_plan + "</script>")

path = HERE / "standalone.html"
path.write_text(output, encoding="utf-8")
print("Published offline HUMAN app:", path)
print("UTF-8 size:", len(output.encode("utf-8")))
print("SHA-256:", hashlib.sha256(output.encode("utf-8")).hexdigest())
