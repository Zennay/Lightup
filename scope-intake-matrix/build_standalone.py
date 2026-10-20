#!/usr/bin/env python3
"""Build a portable zero-network scope+original Casebook HUMAN workroom.

Bundle two *owned* product scripts into separately SHA-256 CSP-pinned inline
scripts. Fail closed when an expected source or template marker changes.
No remote CDN, request, generated authorization, CI or QA workflow.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
html = (ROOT / "index.html").read_text(encoding="utf-8")
original_script_policy = "script-src 'self'"
sources = (
    ("app.js", (ROOT / "app.js").read_text(encoding="utf-8")),
    ("casebook_bridge.js", (ROOT / "casebook_bridge.js").read_text(encoding="utf-8")),
)
if html.count(original_script_policy) != 1:
    raise SystemExit("HOLD: changed script policy, standalone not written")
digests = []
for name, body in sources:
    tag = '<script src="./' + name + '" defer></script>'
    if html.count(tag) != 1 or re.search(r"</script", body, re.IGNORECASE):
        raise SystemExit("HOLD: expected source tag missing/duplicate or unsafe inline sequence: " + name)
    digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
    digests.append("'sha256-" + digest + "'")
    html = html.replace(tag, "<script>" + body + "</script>")
html = html.replace(original_script_policy, "script-src " + " ".join(digests))
if html.count("<script>") != len(sources) or re.search(r"<script\s+src=", html, re.IGNORECASE):
    raise SystemExit("HOLD: external or inconsistent script after bundling")
output = ROOT / "standalone.html"
output.write_text(html, encoding="utf-8", newline="\n")
print("Built private offline scoped workroom", output.stat().st_size, "bytes")
