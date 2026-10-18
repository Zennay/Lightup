#!/usr/bin/env python3
"""Build one fully offline, CSP-hash-pinned LightUp Client Brief app.

Packaging is not a test, origin attestation, authorisation or release approval.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
UPSTREAM_DIGEST = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
SRC_CSP = (
    "<meta http-equiv=\"Content-Security-Policy\" "
    "content=\"default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'none'; connect-src 'none'; form-action 'none'; "
    "object-src 'none'; base-uri 'none'\">"
)
STYLE_TAG = '<link rel="stylesheet" href="theme.css">'
SCRIPT_TAGS = {
    "remediation-engine.js": '<script src="remediation-engine.js"></script>',
    "casework-import.js": '<script src="casework-import.js"></script>',
    "readiness-import.js": '<script src="readiness-import.js"></script>',
    "session-draft.js": '<script src="session-draft.js"></script>',
    "studio-scope-network.js": '<script src="studio-scope-network.js"></script>',
    "studio-planning-window.js": '<script src="studio-planning-window.js"></script>',
    "studio-scope-fingerprint.js": '<script src="studio-scope-fingerprint.js"></script>',
    "studio-proposal-import.js": '<script src="studio-proposal-import.js"></script>',
    "report-history.js": '<script src="report-history.js"></script>',
    "report-history-view.js": '<script src="report-history-view.js"></script>',
    "human-actions.js": '<script src="human-actions.js"></script>',
    "followup-tracker.js": '<script src="followup-tracker.js"></script>',
    "app.js": '<script src="app.js"></script>',
}


def one_replace(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError("Expected exactly one known template placeholder")
    return text.replace(before, after, 1)


def csp_hash(raw: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii") + "'"


def main() -> None:
    engine = (ROOT / "remediation-engine.js").read_bytes()
    if hashlib.sha256(engine).hexdigest() != UPSTREAM_DIGEST:
        raise ValueError("Pinned Casework source has changed; refuse bundling")
    pinned_studio = {
        "studio-scope-network.js": "6a06c93b7395b9c8b0b3b857e04ed677559b6fef4e2a9ef894b993cbfd25abe4",
        "studio-scope-fingerprint.js": "5f89ce8c7a979787048c355da8e0c9e2688819b287c1a4811df824d58e04c90e",
        "studio-planning-window.js": "17f1536e80c390016bfb60a7655ccec55ad462d980cdf29dbee7a263d10b7a21",
    }
    for filename, pinned in pinned_studio.items():
        if hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() != pinned:
            raise ValueError("Original Studio component changed; refuse unreviewed packaging: " + filename)
    css = (ROOT / "theme.css").read_bytes()
    scripts = {name: (ROOT / name).read_bytes() for name in SCRIPT_TAGS}
    if any(b"</script" in raw.lower() for raw in scripts.values()):
        raise ValueError("Unexpected HTML closing script tag in source")
    if b"</style" in css.lower():
        raise ValueError("Unexpected HTML closing style tag in source")
    # Preserve source bytes inside the UTF-8 HTML document. Avoid external URL,
    # JS dependencies, credential prompts, unsigned permission claims or sockets.
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    script_hashes = " ".join(csp_hash(raw) for raw in scripts.values())
    css_hash = csp_hash(css)
    dest_csp = (
        '<meta http-equiv="Content-Security-Policy" content="'
        "default-src 'none'; script-src " + script_hashes
        + "; style-src " + css_hash
        + "; img-src 'none'; connect-src 'none'; form-action 'none'; "
        'object-src \'none\'; base-uri \'none\'">'
    )
    page = one_replace(page, SRC_CSP, dest_csp)
    page = one_replace(page, STYLE_TAG, "<style>" + css.decode("utf-8") + "</style>")
    for name, tag in SCRIPT_TAGS.items():
        page = one_replace(page, tag, "<script>" + scripts[name].decode("utf-8") + "</script>")
    out = ROOT / "standalone.html"
    out.write_bytes(page.encode("utf-8"))
    print(
        "Built standalone offline LightUp client brief:",
        out.name, out.stat().st_size, "bytes; SHA-256", hashlib.sha256(out.read_bytes()).hexdigest()
    )


if __name__ == "__main__":
    main()
