#!/usr/bin/env python3
"""Build the private, offline single-owner human Reply Desk as one CSP-pinned HTML."""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORIGINAL = HERE.parent / "casework" / "remediation-engine.js"
EXPECTED_SHA256 = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
OUTPUT = HERE / "owner-reply-standalone.html"

def pin(data: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode("ascii") + "'"

def build() -> bytes:
    engine = ORIGINAL.read_bytes()
    if hashlib.sha256(engine).hexdigest() != EXPECTED_SHA256:
        raise ValueError("Original Casework engine changed; independent owner review required.")
    source = (HERE / "owner-reply.html").read_text("utf-8")
    css = (HERE / "owner-reply.css").read_bytes()
    assets = {
        '<script src="../casework/remediation-engine.js"></script>': engine,
        '<script src="owner-private-json.js"></script>': (HERE / "owner-private-json.js").read_bytes(),
        '<script src="owner-protocol.js"></script>': (HERE / "owner-protocol.js").read_bytes(),
        '<script src="owner-reply.js"></script>': (HERE / "owner-reply.js").read_bytes(),
    }
    existing = "script-src 'self'; style-src 'self'"
    if source.count(existing) != 1:
        raise ValueError("Invalid original CSP template.")
    source = source.replace(existing, "script-src " + " ".join(pin(v) for v in assets.values()) +
                            "; style-src " + pin(css))
    style = '<link rel="stylesheet" href="owner-reply.css">'
    if source.count(style) != 1:
        raise ValueError("Missing source style anchor.")
    source = source.replace(style, "<style>" + css.decode("utf-8") + "</style>")
    for needle,data in assets.items():
        if source.count(needle) != 1:
            raise ValueError("Missing or duplicate original script reference.")
        source = source.replace(needle,"<script>" + data.decode("utf-8") + "</script>")
    return source.encode("utf-8")

def main() -> None:
    result=build()
    if OUTPUT.is_symlink():
        raise ValueError("Refusing existing symlink.")
    tmp=HERE / ".owner-reply-standalone.tmp"
    if tmp.exists() or tmp.is_symlink():
        raise ValueError("Existing temporary output requires owner review.")
    try:
        with tmp.open("xb") as fd:
            fd.write(result)
            fd.flush()
            os.fsync(fd.fileno())
        os.replace(tmp,OUTPUT)
    finally:
        tmp.unlink(missing_ok=True)
    print(OUTPUT.name,len(result),"bytes",hashlib.sha256(result).hexdigest())

if __name__=="__main__":
    main()
