#!/usr/bin/env python3
"""Build standalone offline LightUp human-only remediation vault; no network."""
from pathlib import Path
from hashlib import sha256
from base64 import b64encode

HERE = Path(__file__).resolve().parent
html = (HERE / "index.html").read_text(encoding="utf-8")
style = (HERE / "style.css").read_text(encoding="utf-8")
app = (HERE / "app.js").read_text(encoding="utf-8")

def pin(contents: str) -> str:
    return "'sha256-" + b64encode(sha256(contents.encode("utf-8")).digest()).decode("ascii") + "'"

policy = "; ".join([
    "default-src 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "connect-src 'none'",
    "worker-src 'none'",
    "img-src 'none'",
    "font-src 'none'",
    "style-src " + pin(style),
    "script-src " + pin(app),
])
assert html.count("@@CSP@@") == 1 and html.count("@@STYLE@@") == 1 and html.count("@@APP@@") == 1
assert "</script" not in app.lower() and "</style" not in style.lower()
output = (html.replace("@@CSP@@", policy)
              .replace("@@STYLE@@", style)
              .replace("@@APP@@", app))
file = HERE / "standalone.html"
file.write_text(output, encoding="utf-8")
print("Built", file.name, len(output.encode("utf-8")), "bytes", "sha256:", sha256(output.encode("utf-8")).hexdigest())
