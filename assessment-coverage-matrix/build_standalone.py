#!/usr/bin/env python3
"""Build the private offline one-file LightUp source-declaration matrix (no imports from runtime)."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import os
import tempfile

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "index.template.html"
STYLE = ROOT / "style.css"
SCRIPT = ROOT / "app.js"
DESTINATION = ROOT / "standalone.html"


def _hash(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def build() -> str:
    template = TEMPLATE.read_text(encoding="utf-8")
    css = STYLE.read_text(encoding="utf-8")
    js = ("\n".join((ROOT / name).read_text(encoding="utf-8")
                    for name in ("private-plan-crypto.js", "human-board.js", "workspace-vault.js", "app.js")))
    for placeholder in ("<!--LIGHTUP_CSP-->", "<!--LIGHTUP_STYLE-->", "<!--LIGHTUP_SCRIPT-->"):
        if template.count(placeholder) != 1:
            raise ValueError(f"Expected exactly one {placeholder}")
    if "</script" in js.lower() or "</style" in css.lower():
        raise ValueError("Unsafe inline HTML terminator")
    csp = (
        "default-src 'none'; "
        f"script-src 'sha256-{_hash(js)}'; "
        f"style-src 'sha256-{_hash(css)}'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; "
        "object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"
    )
    # Control the inline code, not the original private source, which is never included.
    page = (template
        .replace("<!--LIGHTUP_CSP-->", '<meta http-equiv="Content-Security-Policy" content="' + csp + '">')
        .replace("<!--LIGHTUP_STYLE-->", "<style>" + css + "</style>")
        .replace("<!--LIGHTUP_SCRIPT-->", "<script>" + js + "</script>"))
    fd, path = tempfile.mkstemp(prefix=".coverage-matrix-", suffix=".html", dir=ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(page)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(path, DESTINATION)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return hashlib.sha256(page.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    print("Built PRIVATE offline " + str(DESTINATION) + " · SHA-256 " + build())
