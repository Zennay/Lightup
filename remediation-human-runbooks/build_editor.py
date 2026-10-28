#!/usr/bin/env python3
"""Offline PRIVATE HUMAN runbook editor source packager.

Reproducible local artifact assembly, not QA, an authorization gate, scanning,
model execution, evidence validation, customer permission or a deployment.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "editor.template.html"
JS = HERE / "editor.js"
CSS = HERE / "editor.css"
DESTINATION = HERE / "standalone.html"


def sha_pin(data: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def make_html() -> bytes:
    template = TEMPLATE.read_text(encoding="utf-8")
    js = JS.read_bytes()
    css = CSS.read_bytes()
    replacements = {
        "<!--LIGHTUP_EDITOR_SCRIPT-->": "<script>" + js.decode("utf-8") + "</script>",
        "<!--LIGHTUP_EDITOR_STYLE-->": "<style>" + css.decode("utf-8") + "</style>",
        "__LIGHTUP_EDITOR_SCRIPT_HASH__": sha_pin(js),
        "__LIGHTUP_EDITOR_STYLE_HASH__": sha_pin(css),
    }
    for anchor, replacement in replacements.items():
        if template.count(anchor) != 1:
            raise ValueError("HOLD: missing or duplicate offline source/CSP marker")
        template = template.replace(anchor, replacement)
    if b"</script" in js.lower() or b"</style" in css.lower():
        raise ValueError("HOLD: inline source crosses HTML element boundary")
    return template.encode("utf-8")


def main() -> None:
    body = make_html()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=HERE, prefix=".lightup-private-human-", suffix=".html", delete=False
        ) as out:
            temporary = Path(out.name)
            out.write(body)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, DESTINATION)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    print("Built offline PRIVATE HUMAN editor: standalone.html")


if __name__ == "__main__":
    main()
