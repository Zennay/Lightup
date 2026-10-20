#!/usr/bin/env python3
"""Deterministic offline LightUp HUMAN worksheet Studio single-file builder.

Build-only: no lab results, scanner, model, authorization or target access.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import tempfile

HERE = Path(__file__).resolve().parent
HTML = "worksheet-studio.html"
CSS = "worksheet-studio.css"
SCRIPT = "worksheet-studio.js"
OUTPUT = "worksheet-studio-standalone.html"


def sha_pin(source: str) -> str:
    return base64.b64encode(hashlib.sha256(source.encode("utf-8")).digest()).decode("ascii")


def single(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("unexpected browser template shape; refuse uncertain bundle")
    return text.replace(old, new, 1)


def render() -> str:
    html = (HERE / HTML).read_text(encoding="utf-8")
    css = (HERE / CSS).read_text(encoding="utf-8")
    script = (HERE / SCRIPT).read_text(encoding="utf-8")
    if "</script" in script.lower() or "</style" in css.lower():
        raise ValueError("unsafe literal HTML terminator in app source")
    html = single(html, '<link rel="stylesheet" href="worksheet-studio.css">',
                  "<style>" + css + "</style>")
    html = single(html, '<script src="worksheet-studio.js" defer></script>', "")
    # Inline scripts do not obey defer; inject after the full DOM has been parsed.
    html = single(html, "</body>", "<script>" + script + "</script></body>")
    html = single(html, "script-src 'self'", "script-src 'sha256-" + sha_pin(script) + "'")
    html = single(html, "style-src 'self'", "style-src 'sha256-" + sha_pin(css) + "'")
    # Executable source, stylesheet and CSP are fully local and byte pinned.
    if ('src="worksheet-studio.js"' in html or
            'href="worksheet-studio.css"' in html or
            html.count("<script>") != 1 or html.count("<style>") != 1):
        raise ValueError("incomplete single-file assembly")
    return html


def main() -> int:
    parser = argparse.ArgumentParser(description="Package offline PRIVATE HTML; no test/run")
    parser.add_argument("--output", default=str(HERE / OUTPUT))
    parser.add_argument("--replace", action="store_true",
                        help="explicitly replace an already-built regular file")
    args = parser.parse_args()
    data = render().encode("utf-8")
    target = Path(args.output)
    if target.exists() or target.is_symlink():
        if not args.replace:
            parser.error("output already exists; specify --replace explicitly")
        current = target.lstat()
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            parser.error("will not replace a nonregular, linked or symlink output")
    parent = target.parent
    if not parent.is_dir():
        parser.error("output parent directory does not exist")
    fd, temporary = tempfile.mkstemp(prefix=".lightup-private-", suffix=".html", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd != -1:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Built PRIVATE offline one-file HUMAN Studio: " + target.name +
          " (SHA-256 " + hashlib.sha256(data).hexdigest() + ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
