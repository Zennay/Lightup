#!/usr/bin/env python3
"""Build an entirely offline, original-source SHA-pinned Evidence Artifact Ledger."""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "remediation-artifact-ledger"
ORIGINAL = ROOT / "casework" / "remediation-engine.js"
ORIGINAL_SHA256 = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
OUTPUT = HERE / "standalone.html"


def hash_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def token(data: bytes) -> str:
    return "'sha256-" + base64.b64encode(hash_bytes(data)).decode("ascii") + "'"


def build() -> bytes:
    html = (HERE / "index.html").read_text(encoding="utf-8")
    js_original = ORIGINAL.read_bytes()
    if hash_bytes(js_original).hex() != ORIGINAL_SHA256:
        raise ValueError("Original Casework source owner bytes changed. Refusing to build.")
    js_own = (HERE / "ledger.js").read_bytes()
    js_requests = (HERE / "request-board.js").read_bytes()
    css = (HERE / "style.css").read_bytes()
    for name, value in [("original JavaScript", js_original), ("ledger JavaScript", js_own), ("request JavaScript", js_requests)]:
        if b"</script" in value.lower() or b"<!--" in value:
            raise ValueError("Unsafe inline script terminator in " + name)
    if b"</style" in css.lower() or b"<!--" in css:
        raise ValueError("Unsafe CSS terminator")
    needle = "script-src 'self'; style-src 'self'"
    if html.count(needle) != 1:
        raise ValueError("CSP script/style contract must occur once")
    html = html.replace(needle,
                        "script-src " + token(js_original) + " " + token(js_own) + " " + token(js_requests)
                        + "; style-src " + token(css))
    for source, value in [
        ('<script src="../casework/remediation-engine.js"></script>', js_original),
        ('<script src="ledger.js"></script>', js_own),
        ('<script src="request-board.js"></script>', js_requests),
        ('<link rel="stylesheet" href="style.css">', css),
    ]:
        if html.count(source) != 1:
            raise ValueError("Missing or duplicated source token: " + source)
        if source.startswith("<link"):
            replacement = "<style>" + value.decode("utf-8") + "</style>"
        else:
            replacement = "<script>" + value.decode("utf-8") + "</script>"
        html = html.replace(source, replacement)
    if "<script src=" in html or "<link rel=" in html or "unsafe-inline" in html:
        raise ValueError("Expected a fully self-contained, CSP-bound offline page")
    return html.encode("utf-8")



def build_owner_reply() -> bytes:
    """Build an independent offline HUMAN response app with no original-casework privileges."""
    html = (HERE / "owner-reply.html").read_text(encoding="utf-8")
    script = (HERE / "owner-reply.js").read_bytes()
    css = (HERE / "style.css").read_bytes()
    if b"</script" in script.lower() or b"<!--" in script or b"</style" in css.lower():
        raise ValueError("Unsafe owner response embedded script/style terminator")
    needle = "script-src 'self'; style-src 'self'"
    if html.count(needle) != 1:
        raise ValueError("Owner response CSP must be unambiguous")
    html = html.replace(needle, "script-src " + token(script) + "; style-src " + token(css))
    for source, data in (
        ('<script src="owner-reply.js"></script>', script),
        ('<link rel="stylesheet" href="style.css">', css),
    ):
        if html.count(source) != 1:
            raise ValueError("Missing original HUMAN owner reply asset token")
        html = html.replace(source,
            ("<script>" + data.decode("utf-8") + "</script>") if source.startswith("<script")
            else ("<style>" + data.decode("utf-8") + "</style>"))
    if "<script src=" in html or "<link rel=" in html or "unsafe-inline" in html:
        raise ValueError("Nonportable owner HUMAN response file")
    return html.encode("utf-8")

def main() -> None:
    result = build()
    fd, path = tempfile.mkstemp(prefix=".ledger-", suffix=".html", dir=HERE)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(result)
            out.flush()
            os.fsync(out.fileno())
        os.replace(path, OUTPUT)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    print(f"LightUp standalone Evidence Artifact Ledger: {len(result)} bytes, sha256={hash_bytes(result).hex()}")
    owner = build_owner_reply()
    target = HERE / "owner-reply-standalone.html"
    fd, path = tempfile.mkstemp(prefix=".owner-reply-", suffix=".html", dir=HERE)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(owner)
            out.flush()
            os.fsync(out.fileno())
        os.replace(path, target)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    print(f"LightUp private HUMAN owner reply: {len(owner)} bytes, sha256={hash_bytes(owner).hex()}")


if __name__ == "__main__":
    main()
