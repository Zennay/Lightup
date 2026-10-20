#!/usr/bin/env python3
"""Build one independent offline PRIVATE recovery HTML, SHA-pinned to local browser.js."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import sys

MAX_JS = 300_000
MAX_HTML = 300_000
SCRIPT_MARKER = '<script src="./browser.js" defer></script>'
CSP_MARKER = "script-src 'self'"

class Hold(Exception):
    pass

def ordinary_source(path: Path, max_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise Hold("missing original ordinary source file")
    st = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
        raise Hold("unexpected oversized or nonregular builder source")
    raw = path.read_bytes()
    if len(raw) != st.st_size or len(raw) > max_bytes:
        raise Hold("source changed during read")
    raw.decode("utf-8", "strict")
    return raw

def build():
    parser = argparse.ArgumentParser(
        description="Compile complete local PRIVATE recovery desk with SHA-256 CSP script pin; DRAFT/HOLD")
    parser.add_argument("--output", required=True, help="New standalone.html in existing owner-only directory")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        raise Hold("output exists; never overwrite an older offline app")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise Hold("output parent must already exist")
    parent_st = parent.stat(follow_symlinks=False)
    if parent_st.st_uid != os.getuid() or parent_st.st_mode & 0o077:
        raise Hold("output parent must be owned by this user and 0700 private")
    root = Path(__file__).resolve().parent
    html = ordinary_source(root / "index.html", MAX_HTML).decode("utf-8")
    js_bytes = ordinary_source(root / "browser.js", MAX_JS)
    javascript = js_bytes.decode("utf-8")
    if ("</script" in javascript.lower() or html.count(SCRIPT_MARKER) != 1
            or html.count(CSP_MARKER) != 1):
        raise Hold("source marker conflict or inline script unsafe")
    digest = base64.b64encode(hashlib.sha256(js_bytes).digest()).decode("ascii")
    html = html.replace(CSP_MARKER, "script-src 'sha256-" + digest + "'")
    html = html.replace(SCRIPT_MARKER, "<script>" + javascript + "</script>")
    result = html.encode("utf-8")
    if len(result) > MAX_HTML + MAX_JS:
        raise Hold("compiled offline app exceeded budget")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(result)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            output.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    print(f"DRAFT/HOLD: standalone CSP-pinned offline browser built: {output}")
    print(f"Script SHA-256 CSP pin: {digest}")

if __name__ == "__main__":
    try:
        build()
    except (Hold, OSError, ValueError, UnicodeError) as err:
        print(f"HOLD: {err}", file=sys.stderr)
        raise SystemExit(3)
