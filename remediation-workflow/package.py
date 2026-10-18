#!/usr/bin/env python3
"""Deterministic, offline, SHA-CSP-pinned LightUp Remediation Cockpit bundle.

No external network, executable target, client DB, QA/test runner or authorization.
Original owner source bytes are immutable input and cannot be changed silently.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "remediation-workflow"
OUTPUT = HERE / "standalone.html"
SCRIPTS = (
    ("../casework/remediation-engine.js", "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"),
    ("../remediation-capacity/planner.js", "eee5563fef05e2b2b6d0de306827b3f440ace2dc23ef74ca44550b2869ca1fc1"),
    ("../remediation-capacity/draft.js", "934eb7b17ee0ba2d4c1e1eca485b1f043a5e36c89478fbcb042b9340b3a68747"),
    ("desk.js", None),
    ("cockpit.js", None),
)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build() -> bytes:
    template = (HERE / "index.html").read_text(encoding="utf-8")
    csp = "script-src 'self'"
    if template.count(csp) != 1:
        raise ValueError("Expected one exact original script CSP")
    snippets: list[tuple[str, str, str]] = []
    for path, pinned_digest in SCRIPTS:
        origin = (HERE / path).resolve()
        if not origin.is_relative_to(ROOT.resolve()):
            raise ValueError("Unexpected source root")
        data = origin.read_bytes()
        if pinned_digest is not None and sha256(data) != pinned_digest:
            raise ValueError("Original upstream owner script changed: " + path)
        if b"</script" in data.lower() or b"<!--" in data:
            raise ValueError("Unsafe inline-script terminator in source: " + path)
        source = data.decode("utf-8")
        token = '<script src="' + path + '"></script>'
        if template.count(token) != 1:
            raise ValueError("Missing or ambiguous original script tag: " + path)
        digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        snippets.append((token, source, "'sha256-" + digest + "'"))
    template = template.replace(csp, "script-src " + " ".join(p[2] for p in snippets))
    for token, source, _ in snippets:
        template = template.replace(token, "<script>" + source + "</script>")
    if "<script src=" in template:
        raise ValueError("External JS reference left in supposedly standalone HTML")
    # Standalone users can still import all private drafts without sibling paths.
    # Avoid showing broken intra-checkout links on the portable one-file version.
    template = template.replace('<section class="card"><h2>Original standalone workspaces</h2>',
                                '<section class="card" hidden><h2>Original standalone workspaces</h2>')
    return template.encode("utf-8")

def main() -> None:
    artifact = build()
    fd, name = tempfile.mkstemp(prefix=".workflow-", suffix=".html", dir=HERE)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(artifact)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, OUTPUT)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print("Offline LightUp remediation cockpit:", len(artifact), "bytes", sha256(artifact))

if __name__ == "__main__":
    main()
