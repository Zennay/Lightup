#!/usr/bin/env python3
"""Rebuild a portable source-free HUMAN Attention Workboard. No network/QA/scans."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

BASE = Path(__file__).resolve().parent
HTML = BASE / "human-lab-attention.html"
JAVASCRIPT = BASE / "human-lab-attention.js"
JS_REFERENCE = '<script defer src="human-lab-attention.js"></script>'
CSP_REFERENCE = "script-src 'self';"


def build() -> bytes:
    html = HTML.read_text(encoding="utf-8")
    js = JAVASCRIPT.read_text(encoding="utf-8")
    if html.count(JS_REFERENCE) != 1 or html.count(CSP_REFERENCE) != 1:
        raise ValueError("HOLD: HUMAN attention script/CSP has changed unexpectedly")
    if html.count("<script") != 1 or re.search(r"</\s*script", js, re.IGNORECASE):
        raise ValueError("HOLD: unexpected JavaScript markup")
    if "\x00" in html or "\x00" in js:
        raise ValueError("HOLD: invalid local source bytes")
    script = "\n" + js.rstrip("\n") + "\n"
    sha = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    packed = html.replace(CSP_REFERENCE, "script-src 'sha256-" + sha + "';", 1)
    packed = packed.replace(JS_REFERENCE, "<script>" + script + "</script>", 1)
    if JS_REFERENCE in packed or packed.count("<script>") != 1:
        raise ValueError("HOLD: incomplete portable HUMAN workboard")
    for policy in ("default-src 'none'", "connect-src 'none'", "form-action 'none'"):
        if policy not in packed:
            raise ValueError("HOLD: required offline CSP missing")
    return packed.encode("utf-8")


def publish(output: Path, payload: bytes) -> None:
    parent = output.parent.absolute()
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise ValueError("HOLD: output parent must be an ordinary directory")
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError("HOLD: output parent must be owned with 0700 permissions")
    if parent == BASE.parent or BASE.parent in parent.parents:
        raise ValueError("HOLD: PRIVATE output must be outside the repository")
    if output.exists() or output.is_symlink():
        raise ValueError("HOLD: output already exists; no overwrites")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if fd != -1:
            os.close(fd)
        output.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="New .html path under an existing private 0700 directory")
    args = parser.parse_args()
    try:
        if args.output.suffix.lower() != ".html":
            raise ValueError("HOLD: standalone attention output must have .html extension")
        payload = build()
        publish(args.output, payload)
    except (OSError, UnicodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Created source-free HUMAN attention workboard:", args.output)
    print("Bytes:", len(payload))
    print("UNSIGNED SHA-256:", hashlib.sha256(payload).hexdigest())
    print("REVIEW_ONLY / DRAFT-HOLD. Not a source receipt, approval or consent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
