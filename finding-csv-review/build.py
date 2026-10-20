"""Deterministically build the independent LightUp HUMAN desk as one offline HTML.

Source-only software build. No CSV, tenant/evidence data, network or tests.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parent
MAX_ASSET = 256 * 1024


def asset(name: str) -> str:
    # Read only regular, one-link, not-symlink project source files.
    path = ROOT / name
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > MAX_ASSET:
            raise ValueError("Non-canonical source asset")
        with os.fdopen(os.dup(fd), "rb") as handle:
            data = handle.read(MAX_ASSET + 1)
        if len(data) != meta.st_size:
            raise ValueError("Source asset changed during build")
        return data.decode("utf-8", errors="strict")
    finally:
        os.close(fd)


def source_hash(contents: str) -> str:
    return base64.b64encode(hashlib.sha256(contents.encode("utf-8")).digest()).decode("ascii")


def build() -> bytes:
    page = asset("index.html")
    script = asset("app.js")
    vault = asset("vault.js")
    css = asset("style.css")
    if "</script" in script.lower() or "</script" in vault.lower() or "</style" in css.lower():
        raise ValueError("Inline asset contains forbidden closing tag")
    css_ref = '<link rel="stylesheet" href="./style.css">'
    js_ref = '<script defer src="./app.js"></script>'
    vault_ref = '<script defer src="./vault.js"></script>'
    csp_ref = "script-src 'self'; style-src 'self'"
    for marker in (css_ref, js_ref, vault_ref, csp_ref):
        if page.count(marker) != 1:
            raise ValueError("Source HTML marker changed")
    page = page.replace(css_ref, "<style>" + css + "</style>")
    page = page.replace(js_ref, "<script>" + script + "</script>")
    page = page.replace(vault_ref, "<script>" + vault + "</script>")
    page = page.replace('<a href="./README.md">Local operator instructions</a>',
        "Standalone local PRIVATE software · see source README for operator guidance")
    page = page.replace(csp_ref,
        "script-src 'sha256-" + source_hash(script) + "' 'sha256-" +
        source_hash(vault) + "'; style-src 'sha256-" + source_hash(css) + "'")
    if css_ref in page or js_ref in page or vault_ref in page or csp_ref in page:
        raise ValueError("Unexpected unbundled source")
    # It is still unsigned software: local hashes cannot authenticate authorship.
    return page.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build isolated offline HUMAN workroom")
    parser.add_argument("--output", type=Path, default=ROOT / "standalone.html")
    args = parser.parse_args()
    try:
        contents = build()
        output = args.output.absolute()
        if not output.parent.is_dir() or output.is_symlink():
            raise ValueError("Choose an existing trusted directory and new file name")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(output, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        print("REVIEW_ONLY: one-file offline PRIVATE HUMAN desk written")
        print("bytes:", len(contents))
        print("unsigned local sha256:", hashlib.sha256(contents).hexdigest())
        return 2
    except (OSError, UnicodeError, ValueError) as exc:
        print("HOLD: offline build not published (" + type(exc).__name__ + ")", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
