#!/usr/bin/env python3
"""Reproducible local-only single-file build of the HUMAN remediation ticket desk.

No network, authentication, customer data or target interaction. The pre-existing
Casework parser remains unmodified and is checked by source SHA-256 before bundling.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ENGINE = ROOT / "casework" / "remediation-engine.js"
INDEX = HERE / "index.html"
APP = HERE / "ticket-desk.js"
PINNED_ENGINE_SHA256 = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
ORIGINAL_ENGINE = '<script src="../casework/remediation-engine.js"></script>'
ORIGINAL_APP = '<script src="./ticket-desk.js"></script>'


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build() -> bytes:
    engine = ENGINE.read_bytes()
    if _sha(engine) != PINNED_ENGINE_SHA256:
        raise ValueError("Original source-owner Casework parser changed: fail closed; do not rebase silently.")
    app = APP.read_bytes()
    page = INDEX.read_bytes().decode("utf-8")
    if page.count(ORIGINAL_ENGINE) != 1 or page.count(ORIGINAL_APP) != 1:
        raise ValueError("Unexpected source script references, refusing standalone build.")
    for name, data in [("Original engine", engine), ("Ticket desk", app)]:
        if b"</script" in data.lower():
            raise ValueError(name + " contains inline-script end delimiter; refusing build.")
        data.decode("utf-8")
    hashes = []
    for item in (engine, app):
        exact_inline = b"\\n" + item + b"\\n"
        hashes.append("'sha256-" + base64.b64encode(hashlib.sha256(exact_inline).digest()).decode("ascii") + "'")
    if page.count("script-src 'self'") != 1:
        raise ValueError("CSP no longer has expected scripts source.")
    page = page.replace("script-src 'self'", "script-src " + " ".join(hashes))
    page = page.replace(ORIGINAL_ENGINE, "<script>\n" + engine.decode("utf-8") + "\n</script>")
    page = page.replace(ORIGINAL_APP, "<script>\n" + app.decode("utf-8") + "\n</script>")
    if ORIGINAL_ENGINE in page or ORIGINAL_APP in page or "connect-src 'none'" not in page:
        raise ValueError("Offline security policy or bundle script replacement failed.")
    return page.encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a private standalone LightUp HUMAN ticket desk")
    parser.add_argument("--output", type=Path, required=True, help="New local output path, never overwritten")
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    payload = build()
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    print(f"Built offline PRIVATE single HTML: {output}")
    print(f"Byte count: {len(payload)}; SHA-256: {_sha(payload)}")


if __name__ == "__main__":
    main()
