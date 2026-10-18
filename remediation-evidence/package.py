#!/usr/bin/env python3
"""Build a private, self-contained LightUp Evidence Review HTML from pinned local sources.

Packaging only: never calls a model, scanner, external URL, grant, database or test suite.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OWN = ROOT / "remediation-evidence"
UPSTREAM = ROOT / "casework" / "remediation-engine.js"
OWNER_SHA = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
ENGINE_TAG = '<script src="../casework/remediation-engine.js"></script>'
REVIEW_TAG = '<script src="./review.js"></script>'
TARGET = OWN / "standalone.html"


def checked_source(path: Path, max_size: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Only regular local non-symlink source files are supported.")
    result = path.read_bytes()
    if not result or len(result) > max_size:
        raise ValueError("Source file outside size bounds.")
    result.decode("utf-8", errors="strict")
    return result


def csp_hash(raw: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")


def build() -> bytes:
    engine = checked_source(UPSTREAM, 256_000)
    if hashlib.sha256(engine).hexdigest() != OWNER_SHA:
        raise ValueError("Original Casework engine differs from pinned source owner.")
    review = checked_source(OWN / "review.js", 256_000)
    template = checked_source(OWN / "index.html", 128_000).decode("utf-8")
    for js in (engine, review):
        if b"</script" in js.lower() or b"<!--" in js:
            raise ValueError("Script text is unsafe for inline HTML packaging.")
    if template.count(ENGINE_TAG) != 1 or template.count(REVIEW_TAG) != 1:
        raise ValueError("Unrecognized offline HTML script references.")
    if template.count("script-src 'self'") != 1:
        raise ValueError("Expected exactly one original script CSP.")
    hashes = "script-src '{}' '{}'".format(csp_hash(engine), csp_hash(review))
    result = template.replace("script-src 'self'", hashes)
    result = result.replace(ENGINE_TAG, "<script>" + engine.decode("utf-8") + "</script>")
    result = result.replace(REVIEW_TAG, "<script>" + review.decode("utf-8") + "</script>")
    if "script src=" in result:
        raise ValueError("Unexpected external script reference left in artifact.")
    return result.encode("utf-8")


def main() -> None:
    artifact = build()
    if TARGET.is_symlink():
        raise ValueError("Will not replace a symlink destination.")
    fd, name = tempfile.mkstemp(prefix=".evidence-bundle-", dir=str(OWN))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(artifact)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, 0o644)
        os.replace(name, TARGET)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print("Offline bundle bytes={} SHA-256={}".format(
        len(artifact), hashlib.sha256(artifact).hexdigest()
    ))


if __name__ == "__main__":
    main()
