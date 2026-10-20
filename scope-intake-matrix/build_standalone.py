#!/usr/bin/env python3
"""Build a self-contained offline app with a byte-pinned SHA-256 script CSP."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
SOURCE_HTML = (ROOT / "index.html").read_text(encoding="utf-8")
SOURCE_JS = (ROOT / "app.js").read_text(encoding="utf-8")
OLD_TAG = '<script src="./app.js" defer></script>'
OLD_POLICY = "script-src 'self'"
if SOURCE_HTML.count(OLD_TAG) != 1 or SOURCE_HTML.count(OLD_POLICY) != 1:
    raise SystemExit("HOLD: template has changed, refusing to build")
if re.search(r"</script", SOURCE_JS, re.IGNORECASE):
    raise SystemExit("HOLD: unexpected script closing sequence")
digest = base64.b64encode(hashlib.sha256(SOURCE_JS.encode("utf-8")).digest()).decode("ascii")
policy = "script-src 'sha256-" + digest + "'"
standalone = SOURCE_HTML.replace(OLD_POLICY, policy).replace(
    OLD_TAG, "<script>" + SOURCE_JS + "</script>"
)
if "src=\"./app.js\"" in standalone or standalone.count("<script>") != 1:
    raise SystemExit("HOLD: app is not standalone")
output = ROOT / "standalone.html"
output.write_text(standalone, encoding="utf-8", newline="\n")
print("Built strictly offline standalone.html", output.stat().st_size, "bytes")
