#!/usr/bin/env python3
"""Rebuild the exact CSP-pinned PRIVATE offline LightUp disclosure HTML products.

No network, subprocess, target, permission changes or original source modification.
Generated output is text-only and cannot authorize anything.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRODUCTS = (
    ("index.html", "desk.js", "PRIVATE-disclosure-standalone.html",
     'href="./verify.html"', 'href="./PRIVATE-verify-standalone.html"'),
    ("verify.html", "verify.js", "PRIVATE-verify-standalone.html",
     'href="./index.html"', 'href="./PRIVATE-disclosure-standalone.html"'),
)


def pin(data: str) -> str:
    return base64.b64encode(hashlib.sha256(data.encode("utf-8")).digest()).decode("ascii")


def exact_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("source structure changed; refuse ambiguous packaging")
    return source.replace(old, new, 1)


def render(html_name: str, js_name: str, old_link: str, new_link: str) -> bytes:
    html = (HERE / html_name).read_text(encoding="utf-8")
    js = (HERE / js_name).read_text(encoding="utf-8")
    css = (HERE / "desk.css").read_text(encoding="utf-8")
    if "</script" in js.lower() or "</style" in css.lower():
        raise ValueError("unsafe inline boundary")
    html = exact_once(html, '<script defer src="./' + js_name + '"></script>', "")
    html = exact_once(html, '<link rel="stylesheet" href="./desk.css">', "<style>" + css + "</style>")
    html = exact_once(
        html, "script-src 'self'; style-src 'self';",
        "script-src 'sha256-" + pin(js) + "'; style-src 'sha256-" + pin(css) + "';",
    )
    html = exact_once(html, old_link, new_link)
    html = exact_once(html, "</body>", "<script>" + js + "</script></body>")
    if "connect-src 'none'" not in html or "default-src 'none'" not in html:
        raise ValueError("network deny CSP missing")
    return html.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exact offline LightUp PRIVATE HTML packager")
    parser.add_argument("--output-dir", type=Path, help="Write exclusive PRIVATE copies to existing directory; no overwrite")
    args = parser.parse_args()
    products = [(name, render(html, js, old, new))
                for html, js, name, old, new in PRODUCTS]
    if args.output_dir:
        dest = args.output_dir.resolve(strict=True)
        if not dest.is_dir() or dest.is_symlink():
            raise ValueError("must choose an existing real private directory")
        if any((dest / name).exists() or (dest / name).is_symlink() for name, _ in products):
            raise FileExistsError("output already exists; no overwrite")
        for name, data in products:
            target = dest / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            print(name + ": written privately")
    else:
        for name, expected in products:
            saved = (HERE / name).read_bytes()
            if saved != expected:
                raise ValueError(name + ": generated asset stale; refuse misleading release")
            print(name + ": source-exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
