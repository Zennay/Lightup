#!/usr/bin/env python3
"""Build isolated LightUp lineage browser artifact; no network or assessments."""
from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE_HTML = ROOT / "index.html"
SOURCE_JS = ROOT / "app.js"
SOURCE_CSS = ROOT / "style.css"
OUT = ROOT / "standalone.html"


def digest(raw: bytes) -> str:
    return base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def build() -> None:
    html = SOURCE_HTML.read_text(encoding="utf-8")
    js = SOURCE_JS.read_text(encoding="utf-8")
    css = SOURCE_CSS.read_text(encoding="utf-8")
    # Never rely on assert: python -O must not disable source integrity gates.
    if ("</script" in js.lower() or "</style" in css.lower()
            or html.count('<script src="app.js" defer></script>') != 1
            or html.count('<link rel="stylesheet" href="style.css">') != 1
            or html.count("script-src 'self'") != 1
            or html.count("style-src 'self'") != 1):
        raise ValueError("HOLD: source HTML/JS/CSS markers do not match the trusted standalone template")
    html = html.replace("script-src 'self'", "script-src 'sha256-" + digest(js.encode()) + "'")
    html = html.replace("style-src 'self'", "style-src 'sha256-" + digest(css.encode()) + "'")
    html = html.replace(
        '<link rel="stylesheet" href="style.css">', "<style>" + css + "</style>"
    )
    html = html.replace(
        '<script src="app.js" defer></script>', "<script>" + js + "</script>"
    )
    # Only a complete source-checked artifact may replace the old standalone.
    payload = html.encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=".standalone-", suffix=".tmp", dir=ROOT)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            os.fchmod(stream.fileno(), 0o644)  # public application code, never private source data
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, OUT)
        directory_fd = os.open(ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    print("Built offline " + OUT.name + " (" + str(len(payload)) + " bytes)")
    print("SHA256 " + hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    build()
