#!/usr/bin/env python3
"""Build one portable, local-only HTML artifact with exact pinned inline CSP.

Production artifact builder, not a test runner. Never overwrites existing output.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path


def digest(value: str) -> str:
    return base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")


def build(folder: Path, output: Path) -> None:
    folder = folder.resolve(strict=True)
    html = (folder / "index.html").read_text(encoding="utf-8")
    css = (folder / "style.css").read_text(encoding="utf-8")
    js = (folder / "app.js").read_text(encoding="utf-8")

    if "</style" in css.lower() or "</script" in js.lower():
        raise ValueError("Cannot embed escaped HTML termination inside source.")
    style = "\n" + css + "\n"
    script = "\n" + js + "\n"
    link = '<link rel="stylesheet" href="./style.css">'
    script_ref = '<script defer src="./app.js"></script>'
    policy = "default-src 'none'; script-src 'self'; style-src 'self';"
    if html.count(link) != 1 or html.count(script_ref) != 1 or html.count(policy) != 1:
        raise ValueError("Source template drift: refusing to create unpinned portable HTML.")
    html = html.replace(link, "<style>" + style + "</style>")
    html = html.replace(script_ref, "<script>" + script + "</script>")
    html = html.replace(
        policy,
        "default-src 'none'; script-src 'sha256-" + digest(script) +
        "'; style-src 'sha256-" + digest(style) + "';"
    )
    if "src=\"./app.js\"" in html or 'href="./style.css"' in html:
        raise ValueError("Unexpected external local resource in portable HTML.")
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(html)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    print("Built portable HTML at", output, "bytes", output.stat().st_size)
    print("This build does not assert browser, security or release approval.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build static human-only LightUp twin review HTML")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("standalone.html"))
    args = parser.parse_args()
    build(Path(__file__).resolve().parent, args.output)


if __name__ == "__main__":
    main()
