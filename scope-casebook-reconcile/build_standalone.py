#!/usr/bin/env python3
"""Create CSP SHA-pinned, offline one-file HUMAN review desk from pinned original source."""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT.parent / "scope-casebook-transfer" / "human-board.js"
PINNED_ORIGINAL_SHA256 = "7900001ddcaff502ba6d1adf053b527e3aa620946b34bcf7eb7c8b042340682b"

def build() -> None:
    source = ORIGINAL.read_bytes()
    if hashlib.sha256(source).hexdigest() != PINNED_ORIGINAL_SHA256:
        raise SystemExit("HOLD: pinned original source changed; manual source-owner review required")
    adapter = source.decode("utf-8")
    app = (ROOT / "app.js").read_text(encoding="utf-8")
    css = (ROOT / "style.css").read_text(encoding="utf-8")
    draft = (ROOT / "draft.js").read_text(encoding="utf-8")
    notes = (ROOT / "notes.js").read_text(encoding="utf-8")
    receipt = (ROOT / "receipt.js").read_text(encoding="utf-8")
    revision = (ROOT / "revision.js").read_text(encoding="utf-8")
    timeline = (ROOT / "timeline.js").read_text(encoding="utf-8")
    bulk = (ROOT / "bulk.js").read_text(encoding="utf-8")
    portfolio = (ROOT / "portfolio.js").read_text(encoding="utf-8")
    preview = (ROOT / "preview.js").read_text(encoding="utf-8")
    note_bulk = (ROOT / "note-bulk.js").read_text(encoding="utf-8")
    js = adapter + "\n" + app + "\n" + notes + "\n" + draft + "\n" + receipt + "\n" + revision + "\n" + timeline + "\n" + bulk + "\n" + portfolio + "\n" + preview + "\n" + note_bulk
    digest = lambda t: base64.b64encode(hashlib.sha256(t.encode("utf-8")).digest()).decode("ascii")
    policy = ("default-src 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'; "
              "form-action 'none'; connect-src 'none'; img-src 'none'; "
              "style-src 'sha256-" + digest(css) + "'; script-src 'sha256-" + digest(js) + "'")
    html = ((ROOT / "index.template.html").read_text(encoding="utf-8")
            .replace("__CSP__", policy).replace("__STYLE__", css).replace("__SCRIPT__", js))
    if any(tag in html for tag in ("__CSP__", "__STYLE__", "__SCRIPT__")):
        raise SystemExit("HOLD: incomplete offline artifact")
    (ROOT / "standalone.html").write_text(html, encoding="utf-8")
    print("Generated offline standalone.html (" + str(len(html.encode("utf-8"))) + " bytes)")

if __name__ == "__main__":
    build()
