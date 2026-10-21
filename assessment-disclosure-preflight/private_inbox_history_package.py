"""Build the one-file source-only PRIVATE HUMAN History Desk.

This builder never reads customer sources, network data, grant state or
private HUMAN worksheets. A generated file is unsigned software, not review,
verified provenance, consent or authority to execute an assessment.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
HTML = "private-inbox-history-studio.html"
CSS = "private-inbox-history-studio.css"
JS = "private-inbox-history-studio.js"
COMPOSE_JS = "private-inbox-history-compose.js"
OUTPUT = "private-inbox-history-standalone.html"
MAX_ASSET = 128 * 1024
MAX_OUTPUT = 256 * 1024

STYLE_TAG = '<link href="./private-inbox-history-studio.css" rel="stylesheet">'
SCRIPT_TAG = '<script src="./private-inbox-history-studio.js" defer></script>'
COMPOSE_TAG = '<script src="./private-inbox-history-compose.js" defer></script>'
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"


def original_bytes(name: str) -> bytes:
    path = ROOT / name
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ASSET):
            raise ValueError("source-only browser file invalid")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(MAX_ASSET + 1)
        after = os.fstat(fd)
        if (not 0 < len(data) <= MAX_ASSET or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
            len(data) != before.st_size):
            raise ValueError("source-only browser file changed during read")
        if b"\x00" in data:
            raise ValueError("binary browser source refused")
        data.decode("utf-8", "strict")
        return data
    finally:
        os.close(fd)


def compose() -> bytes:
    html = original_bytes(HTML).decode("utf-8")
    style = original_bytes(CSS).decode("utf-8")
    script = original_bytes(JS).decode("utf-8")
    composer = original_bytes(COMPOSE_JS).decode("utf-8")
    if (html.count(STYLE_TAG) != 1 or html.count(SCRIPT_TAG) != 1 or
        html.count(COMPOSE_TAG) != 1 or html.count("</body>") != 1 or
        html.count(CSP) != 1 or
        "</style" in style.lower() or "</script" in script.lower() or "</script" in composer.lower()):
        raise ValueError("history desk source HTML/CSS/JS inconsistent")
    js_hash = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    compose_hash = base64.b64encode(hashlib.sha256(composer.encode("utf-8")).digest()).decode("ascii")
    css_hash = base64.b64encode(hashlib.sha256(style.encode("utf-8")).digest()).decode("ascii")
    strict_csp = (
        "default-src 'none'; script-src 'sha256-" + js_hash + "' 'sha256-" + compose_hash + "'; "
        "script-src-attr 'none'; style-src 'sha256-" + css_hash + "'; "
        "style-src-attr 'none'; connect-src 'none'; img-src 'none'; "
        "object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"
    )
    # Inline scripts DO NOT honor the external defer attribute. Running
    # scripts in <head> before their DOM controls exist breaks standalone UI.
    # Move both original modules to end-of-body in exact source order.
    result = (html.replace(CSP, strict_csp)
              .replace(STYLE_TAG, "<style>" + style + "</style>")
              .replace(SCRIPT_TAG, "")
              .replace(COMPOSE_TAG, "")
              .replace("</body>", "<script>" + script + "</script>\n" +
                       "<script>" + composer + "</script>\n</body>")
              .encode("utf-8"))
    if not 0 < len(result) <= MAX_OUTPUT:
        raise ValueError("standalone history desk exceeds source-only bound")
    return result


def existing_output() -> bytes:
    fd = os.open(ROOT / OUTPUT, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_OUTPUT:
            raise ValueError("standalone HTML file invalid")
        with os.fdopen(fd, "rb", closefd=False) as reader:
            raw = reader.read(MAX_OUTPUT + 1)
        after = os.fstat(fd)
        if len(raw) != before.st_size or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns):
            raise ValueError("standalone HTML changed during read")
        return raw
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or inspect unsigned offline HUMAN History Desk")
    parser.add_argument("action", choices=("build", "verify-current"))
    parser.add_argument("--replace", action="store_true",
                        help="explicitly update only the existing generated standalone HTML")
    args = parser.parse_args()
    try:
        if args.action == "verify-current":
            if args.replace:
                raise ValueError("--replace not permitted for read-only verify-current")
            expected = compose()
            if existing_output() != expected:
                raise ValueError("standalone history HTML differs from original source assets")
            print("REVIEW_ONLY: unsigned one-file PRIVATE History Desk matches original software assets")
            return 2
        data = compose()
        output = ROOT / OUTPUT
        if output.exists() or output.is_symlink():
            if not args.replace:
                raise ValueError("existing standalone requires explicit --replace")
            existing_output()  # deny aliases, binary/oversized or changed output.
        elif args.replace:
            raise ValueError("--replace cannot create an absent standalone")
        fd, staging = tempfile.mkstemp(prefix=".lightup-private-history-", dir=ROOT)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as writer:
                writer.write(data)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(staging, output)
            directory = os.open(ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(staging):
                os.unlink(staging)
        print("REVIEW_ONLY: unsigned local history browser built:", len(data),
              "bytes, sha256", hashlib.sha256(data).hexdigest())
        return 2
    except (OSError, TypeError, ValueError, UnicodeError, MemoryError):
        print("HOLD: original private browser source/standalone not admitted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
