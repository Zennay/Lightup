#!/usr/bin/env python3
"""Bundle only the static offline LightUp private team reply editor.

No target contacts, scans, tests, authentication, grant or source DB access.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile

DIRECTORY = Path(__file__).resolve().parent
HTML_SOURCE = DIRECTORY / "team-reply.html"
JS_SOURCE = DIRECTORY / "team-reply.js"
OUTPUT = DIRECTORY / "team-reply-standalone.html"
JS_MARKER = '<script src="./team-reply.js"></script>'


def _read_regular(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Only an original regular local team reply source is allowed.")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise ValueError("Original team reply source exceeds build size bounds.")
    raw.decode("utf-8", errors="strict")
    return raw


def build() -> bytes:
    document = _read_regular(HTML_SOURCE, 128_000).decode("utf-8")
    source = _read_regular(JS_SOURCE, 256_000)
    if b"</script" in source.lower() or b"<!--" in source:
        raise ValueError("Unsafe HTML delimiter in executable script.")
    if document.count(JS_MARKER) != 1 or document.count("script-src 'self'") != 1:
        raise ValueError("Original team reply HTML or CSP source has changed unexpectedly.")
    digest = base64.b64encode(hashlib.sha256(source).digest()).decode("ascii")
    document = document.replace("script-src 'self'", "script-src 'sha256-" + digest + "'")
    document = document.replace(JS_MARKER, "<script>" + source.decode("utf-8") + "</script>")
    if "<script src=" in document:
        raise ValueError("Unresolved external JavaScript source.")
    return document.encode("utf-8")


def main() -> None:
    raw = build()
    if OUTPUT.is_symlink():
        raise ValueError("Will not replace a symlinked output.")
    fd, temporary = tempfile.mkstemp(prefix=".lightup-team-reply-", dir=str(DIRECTORY))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, OUTPUT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Private offline team reply bundle: {} bytes, SHA-256 {}".format(
        len(raw), hashlib.sha256(raw).hexdigest()
    ))


if __name__ == "__main__":
    main()
