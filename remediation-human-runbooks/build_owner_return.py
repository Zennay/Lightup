#!/usr/bin/env python3
"""Rebuild the isolated offline PRIVATE HUMAN owner return desk.

This is a deterministic local source packager, not an assessment, test runner,
network client, grant, release gate or authorization verification.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "owner-return.template.html"
CSS = ROOT / "owner-return.css"
SCRIPT = ROOT / "owner-return.js"
OUTPUT = ROOT / "owner-return.html"


def csp_hash(content: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")


def render() -> bytes:
    template = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_bytes()
    js = SCRIPT.read_bytes()
    if template.count("<!--OWNER_RETURN_STYLE-->") != 1 or template.count("<!--OWNER_RETURN_SCRIPT-->") != 1:
        raise ValueError("HOLD: missing or duplicate source replacement markers")
    if template.count("__OWNER_SCRIPT_HASH__") != 1 or template.count("__OWNER_STYLE_HASH__") != 1:
        raise ValueError("HOLD: missing or duplicate source CSP pin markers")
    if b"</script" in js.lower() or b"</style" in css.lower():
        raise ValueError("HOLD: inline source would break the offline page boundary")
    if b"<!--OWNER_RETURN_STYLE-->" in css or b"<!--OWNER_RETURN_SCRIPT-->" in js:
        raise ValueError("HOLD: source contains packaging markers")

    html = (template
            .replace("<!--OWNER_RETURN_STYLE-->", "<style>" + css.decode("utf-8") + "</style>")
            .replace("<!--OWNER_RETURN_SCRIPT-->", "<script>" + js.decode("utf-8") + "</script>")
            .replace("__OWNER_SCRIPT_HASH__", csp_hash(js))
            .replace("__OWNER_STYLE_HASH__", csp_hash(css)))
    return html.encode("utf-8")


def main() -> None:
    contents = render()
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".owner-return-", suffix=".html",
            dir=ROOT, delete=False
        ) as f:
            temp_path = Path(f.name)
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, OUTPUT)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    print("Offline PRIVATE HUMAN owner desk packaged locally: owner-return.html")


if __name__ == "__main__":
    main()
