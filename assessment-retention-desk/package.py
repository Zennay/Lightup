#!/usr/bin/env python3
"""Create one 0600 offline browser artifact with exact inline CSP SHA-256 pins.

Source is only these four trusted local product files. Never accesses assessment
data, network, subprocess, user credentials or target assets.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat

from history import Hold, publish_private


ROOT = Path(__file__).resolve().parent
CSP_TEMPLATE = """<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">"""
CSS_TAG = '<link rel="stylesheet" href="desk.css">'
JS_TAG = '<script src="desk.js" defer></script>'
VAULT_TAG = '<script src="vault.js" defer></script>'


def read_source(name, cap):
    path = ROOT / name
    try:
        payload = path.read_bytes()
        if not 1 <= len(payload) <= cap:
            raise Hold("missing or oversized local product component")
        return payload.decode("utf-8", "strict")
    except (OSError, UnicodeError) as exc:
        raise Hold("could not read trusted UTF-8 local product source") from exc


def once(haystack, needle, replacement):
    if haystack.count(needle) != 1:
        raise Hold("original HTML source/layout differs from expected product version")
    return haystack.replace(needle, replacement, 1)


def csp_sha(value):
    digest = hashlib.sha256(value.encode("utf-8", "strict")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def bundle():
    html = read_source("index.html", 100_000)
    css = read_source("desk.css", 100_000)
    js = read_source("desk.js", 200_000)
    vault = read_source("vault.js", 200_000)
    # Source HTML needs distinct inert placeholders; refuse script/style terminator
    # sequences in the bundled assets rather than letting an inline element escape.
    if re.search(r"</\s*(script|style)\b", js + "\n" + vault + "\n" + css, re.IGNORECASE):
        raise Hold("unsafe inline style/script terminator in source")
    csp = (
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "script-src " + csp_sha(js) + " " + csp_sha(vault) + "; style-src " + csp_sha(css) + "; "
        "img-src 'none'; connect-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'\">"
    )
    html = once(html, CSP_TEMPLATE, csp)
    html = once(html, CSS_TAG, "<style>" + css + "</style>")
    html = once(html, JS_TAG, "")
    html = once(html, VAULT_TAG, "")
    html = once(html, "</body>", "<script>" + js + "</script>\n<script>" + vault + "</script>\n</body>")
    if 'src="desk.js"' in html or 'src="vault.js"' in html or 'href="desk.css"' in html:
        raise Hold("external source reference left in purported standalone product")
    return html



def read_private_output(path):
    """Read an existing standalone artifact safely, without following file links."""
    target = Path(path)
    parent_fd = None
    fd = None
    try:
        parent_fd = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        parent = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise Hold("reopen requires an existing owner-only 0700 parent directory")
        before = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= 1_000_000):
            raise Hold("saved standalone is not a bounded owner-only 0600 regular file")
        fd = os.open(
            target.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(fd)

        def identity(item):
            return (item.st_dev, item.st_ino, item.st_uid, stat.S_IMODE(item.st_mode),
                    item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)

        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
            raise Hold("saved standalone changed between directory admission and open")
        chunks = []
        total = 0
        while total <= 1_000_000:
            block = os.read(fd, min(65_536, 1_000_001 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        after = os.fstat(fd)
        if total != opened.st_size or total > 1_000_000 or identity(after) != identity(opened):
            raise Hold("saved standalone changed or exceeded its read boundary")
        return b"".join(chunks)
    except Hold:
        raise
    except OSError as exc:
        raise Hold("could not safely reopen the existing private standalone") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def main():
    p = argparse.ArgumentParser(
        description="Build one source-hash-CSP-pinned, local-only LightUp retention desk (no assessment action).")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output",
                      help="Create a new HTML path under an existing private 0700 directory")
    mode.add_argument("--reopen",
                      help="Read-only byte-for-byte reopen of an existing private 0600 standalone")
    args = p.parse_args()
    try:
        product = bundle()
        if args.reopen:
            existing = read_private_output(args.reopen)
            if not hmac.compare_digest(existing, product.encode("utf-8", "strict")):
                raise Hold("saved standalone differs from the current source bundle; no file changed")
            print("REVIEW_ONLY: saved standalone matches current source byte-for-byte; no output written.")
            print("CSP pins and embedded assets match current product sources; no authority or release created.")
            return
        publish_private(args.output, product)
    except Hold as exc:
        p.exit(2, "HOLD: " + str(exc) + "\n")
    print("PRIVATE CSP-hash-pinned single-file offline workroom created (non-authorizing).")


if __name__ == "__main__":
    main()
