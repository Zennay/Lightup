#!/usr/bin/env python3
"""Build a one-file, network-disabled human calendar from pinned Casework sources.

Purely local file packaging. Never calls the LightUp domain, a scanner or a network.
"""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCE = ROOT / "casework" / "remediation-engine.js"
EXPECTED_SOURCE_SHA256 = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
OUTPUT = HERE / "standalone.html"

def pin(text: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text).digest()).decode("ascii") + "'"

def build() -> bytes:
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != EXPECTED_SOURCE_SHA256:
        raise ValueError("Original Casework source changed. Independent owner review required.")
    app = (HERE / "app.js").read_bytes()
    css = (HERE / "style.css").read_bytes()
    html = (HERE / "index.html").read_text("utf-8")
    script_policy = "script-src " + " ".join([pin(source), pin(app)])
    style_policy = "style-src " + pin(css)
    old = "script-src 'self'; style-src 'self'"
    if html.count(old) != 1:
        raise ValueError("Missing source CSP anchor.")
    html = html.replace(old, script_policy + "; " + style_policy)
    replacements = [
        ('<link rel="stylesheet" href="style.css">', "<style>\n" + css.decode("utf-8") + "\n</style>"),
        ('<script src="../casework/remediation-engine.js"></script>', "<script>\n" + source.decode("utf-8") + "\n</script>"),
        ('<script src="app.js"></script>', "<script>\n" + app.decode("utf-8") + "\n</script>"),
    ]
    for needle, replace in replacements:
        if html.count(needle) != 1:
            raise ValueError("Missing or duplicated resource: " + needle)
        html = html.replace(needle, replace)
    return html.encode("utf-8")

def main() -> None:
    artifact = build()
    if OUTPUT.is_symlink():
        raise ValueError("Refusing existing symlink output.")
    temp = HERE / ".standalone.html.tmp"
    if temp.exists() or temp.is_symlink():
        raise ValueError("Pending output must be manually reviewed.")
    try:
        with temp.open("xb") as handle:
            handle.write(artifact)
            handle.flush()
            import os
            os.fsync(handle.fileno())
        temp.replace(OUTPUT)
    finally:
        temp.unlink(missing_ok=True)
    print("Local, offline-only standalone:", OUTPUT.name)
    print("Bytes:", len(artifact), "SHA-256:", hashlib.sha256(artifact).hexdigest())

if __name__ == "__main__":
    main()
