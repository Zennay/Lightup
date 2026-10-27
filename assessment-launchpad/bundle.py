#!/usr/bin/env python3
"""Build portable single-file offline LightUp launch composer from owned assets.

Only repackages trusted local source. No runtime, network, subprocess or tests.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
CSP_BEFORE = ("default-src 'none'; script-src 'self'; style-src 'self'; "
              "connect-src 'none'; img-src 'none'; object-src 'none'; "
              "form-action 'none'; base-uri 'none'")


def inline_portable() -> bytes:
    html = (ROOT / "index.html").read_text("utf-8")
    js = (ROOT / "app.js").read_text("utf-8")
    css = (ROOT / "style.css").read_text("utf-8")
    if "</script" in js.lower() or "</style" in css.lower():
        raise ValueError("unsafe inline source terminator")
    sha_js = base64.b64encode(hashlib.sha256(js.encode()).digest()).decode("ascii")
    sha_css = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode("ascii")
    after = (f"default-src 'none'; script-src 'sha256-{sha_js}'; "
             f"style-src 'sha256-{sha_css}'; connect-src 'none'; "
             "img-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'")
    if html.count(CSP_BEFORE) != 1:
        raise ValueError("unexpected original CSP")
    html = html.replace(CSP_BEFORE, after)
    stylesheet = '  <link rel="stylesheet" href="./style.css">'
    script = '  <script src="./app.js" defer></script>'
    if html.count(stylesheet) != 1 or html.count(script) != 1 or html.count("</body>") != 1:
        raise ValueError("unexpected launchpad asset layout")
    html = html.replace(stylesheet, "  <style>" + css + "</style>")
    html = html.replace(script, "")
    html = html.replace("</body>", "<script>" + js + "</script>\n</body>")
    return html.encode("utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Package local offline launchpad as CSP-pinned standalone HTML")
    p.add_argument("--output", required=True, metavar="NEW_PRIVATE_HTML")
    args = p.parse_args(argv)
    try:
        data = inline_portable()
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try: os.unlink(args.output)
            except OSError: pass
            raise
        print("OFFLINE_COMPOSER_CREATED — PRIVATE DRAFT/HOLD; NO NETWORK OR AUTHORITY")
        return 2
    except (ValueError, OSError, TypeError, UnicodeError):
        print("OFFLINE_COMPOSER_HOLD — cannot publish portable UI", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
