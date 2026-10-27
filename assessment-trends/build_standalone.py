#!/usr/bin/env python3
"""Build the offline LightUp Lab Trajectory into one CSP-pinned local HTML."""
from __future__ import annotations
import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def digest(source: bytes) -> str:
    return base64.b64encode(hashlib.sha256(source).digest()).decode("ascii")

def main() -> None:
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "style.css").read_text(encoding="utf-8")
    js = (ROOT / "app.js").read_text(encoding="utf-8")
    assert "</style" not in css.lower() and "</script" not in js.lower()
    css_tag = '<link rel="stylesheet" href="style.css">'
    script_tag = '<script src="app.js" defer></script>'
    assert html.count(css_tag) == html.count(script_tag) == 1
    policy = "; ".join((
        "default-src 'none'", "base-uri 'none'", "form-action 'none'",
        "connect-src 'none'", "img-src 'none'", "object-src 'none'",
        "frame-src 'none'",
        "style-src 'sha256-" + digest(css.encode("utf-8")) + "'",
        "script-src 'sha256-" + digest(js.encode("utf-8")) + "'",
    ))
    result = html.replace("</title>", '</title><meta http-equiv="Content-Security-Policy" content="' + policy + '">')
    result = result.replace(css_tag, "<style>" + css + "</style>")
    result = result.replace(script_tag, "<script>" + js + "</script>")
    output = ROOT / "standalone.html"
    output.write_text(result, encoding="utf-8")
    print("Wrote", output.name, "bytes", output.stat().st_size,
          "sha256", hashlib.sha256(result.encode("utf-8")).hexdigest())

if __name__ == "__main__":
    main()
