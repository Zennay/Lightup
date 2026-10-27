#!/usr/bin/env python3
"""Build the source-free offline HUMAN Return Studio, pinned single script CSP."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent


def main() -> int:
    template = (HERE / "browser.template.html").read_text(encoding="utf-8")
    javascript = (HERE / "browser.js").read_text(encoding="utf-8")
    if (template.count("__SCRIPT_SHA256__") != 1 or
            template.count("__INLINE_SCRIPT__") != 1 or
            "</script" in javascript.lower()):
        raise ValueError("HOLD: invalid standalone HUMAN browser source template")
    digest = base64.b64encode(hashlib.sha256(javascript.encode("utf-8")).digest()).decode("ascii")
    output = template.replace("__SCRIPT_SHA256__", digest).replace("__INLINE_SCRIPT__", javascript)
    (HERE / "browser.html").write_text(output, encoding="utf-8")
    print("Built source-free offline HUMAN browser.html with pinned inline JS CSP.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
