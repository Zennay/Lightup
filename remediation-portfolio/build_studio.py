#!/usr/bin/env python3
"""Build the offline, single-file HUMAN Studio with a pinned inline-script CSP.

Production asset builder, not a QA/test runner. No requests or dependencies.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SHELL = ROOT / "studio.template.html"
SCRIPT = ROOT / "studio.js"
DEST = ROOT / "studio.html"


def main() -> int:
    html = SHELL.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    assert html.count("__SCRIPT_SHA256__") == 1
    assert html.count("__INLINE_SCRIPT__") == 1
    assert "</script" not in script.lower()
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    built = html.replace("__SCRIPT_SHA256__", digest).replace("__INLINE_SCRIPT__", script)
    DEST.write_text(built, encoding="utf-8")
    print(f"Private standalone HUMAN Studio written: {DEST.name} (CSP-SHA256)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
