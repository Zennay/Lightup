#!/usr/bin/env python3
"""Build a single-file, offline, non-authorizing LightUp HUMAN Lab Route Desk.

Product packaging only: never opens original lab evidence, scans, or grants.
Uses the *same* already-reviewed discussion UI sources as the two-file desk.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
ORIGINAL_HTML = BASE / "human-lab-route.html"
ORIGINAL_JS = BASE / "human-lab-route.js"
SCRIPT_ELEMENT = '<script defer src="human-lab-route.js"></script>'
SCRIPT_POLICY = "script-src 'self';"
SCRIPT_CLOSE = re.compile(r"</\s*script", re.IGNORECASE)


def build() -> bytes:
    html = ORIGINAL_HTML.read_text(encoding="utf-8")
    js = ORIGINAL_JS.read_text(encoding="utf-8")
    # Refuse unanticipated packaging changes rather than weakening CSP.
    if html.count(SCRIPT_ELEMENT) != 1 or html.count(SCRIPT_POLICY) != 1:
        raise ValueError("HOLD: the original JS reference or CSP is not canonical")
    if html.count("<script") != 1 or SCRIPT_CLOSE.search(js):
        raise ValueError("HOLD: unexpected script markup")
    if "\x00" in html or "\x00" in js:
        raise ValueError("HOLD: NUL byte in local software")
    # Hash the exact inline script text, including newlines. CSP hashes are
    # software integrity restrictions, not publisher signatures or consent.
    inline_js = "\n" + js.rstrip("\n") + "\n"
    digest = base64.b64encode(hashlib.sha256(inline_js.encode("utf-8")).digest()).decode("ascii")
    bundled = html.replace(
        SCRIPT_POLICY,
        "script-src 'sha256-" + digest + "';",
        1,
    ).replace(
        SCRIPT_ELEMENT,
        "<script>" + inline_js + "</script>",
        1,
    )
    if SCRIPT_ELEMENT in bundled or bundled.count("<script>") != 1:
        raise ValueError("HOLD: incomplete local script bundling")
    if "connect-src 'none'" not in bundled or "default-src 'none'" not in bundled:
        raise ValueError("HOLD: original no-network CSP missing")
    return bundled.encode("utf-8")


def publish(output: Path, data: bytes) -> None:
    # Never put private HUMAN discussion software in a shared or unowned
    # parent, nor inside the source checkout. No symlink target or overwrite.
    parent = output.parent.absolute()
    parent_stat = parent.lstat()
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise ValueError("HOLD: output parent is not an ordinary directory")
    if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise ValueError("HOLD: choose an owner-only 0700 parent directory")
    if parent == BASE.parent or BASE.parent in parent.parents:
        raise ValueError("HOLD: output must remain outside source checkout")
    if output.exists() or output.is_symlink():
        raise ValueError("HOLD: output already exists; never overwrite a HUMAN file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if fd != -1:
            os.close(fd)
        output.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True,
        help="New .html path in a private 0700 owner-controlled directory outside the checkout (never overwritten)",
    )
    args = parser.parse_args()
    try:
        if args.output.suffix.lower() != ".html":
            raise ValueError("HOLD: output must end with .html")
        payload = build()
        publish(args.output, payload)
    except (OSError, UnicodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Created local source-only HUMAN Lab Route Desk:", args.output)
    print("Bytes:", len(payload))
    print("UNSIGNED SHA-256:", hashlib.sha256(payload).hexdigest())
    print("REVIEW_ONLY / DRAFT-HOLD. This digest is not consent, trust or approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
