"""Deterministic offline LightUp remediation-capacity single-file packager.

Product build tooling only. Does not validate consent, test security controls,
run any scanner, read customer files, fetch a network resource or deploy.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
STYLE = ROOT / "style.css"
PLANNER = ROOT / "planner.js"
APP = ROOT / "app.js"
OUTPUT = ROOT / "standalone.html"


def digest(content: str) -> str:
    return base64.b64encode(hashlib.sha256(content.encode("utf-8")).digest()).decode("ascii")


def replace_exact(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("Expected exactly one package insertion point")
    return source.replace(old, new, 1)


def main() -> None:
    html = INDEX.read_text(encoding="utf-8")
    css = STYLE.read_text(encoding="utf-8")
    js1 = PLANNER.read_text(encoding="utf-8")
    js2 = APP.read_text(encoding="utf-8")
    if "</style" in css.lower() or any("</script" in item.lower() for item in (js1, js2)):
        raise ValueError("Source contains an unsafe inline HTML delimiter")
    if len(css) + len(js1) + len(js2) > 300_000:
        raise ValueError("Unexpectedly large source bundle")

    html = replace_exact(html, '<link rel="stylesheet" href="./style.css">',
                         "<style>" + css + "</style>")
    for name in ("planner", "app"):
        html = replace_exact(html, '<script src="./' + name + '.js" defer></script>', "")
    scripts = "<script>" + js1 + "</script>\n<script>" + js2 + "</script>\n"
    html = replace_exact(html, "</body>", scripts + "</body>")
    html = replace_exact(
        html,
        "script-src 'self'; style-src 'self';",
        "script-src 'sha256-" + digest(js1) + "' 'sha256-" + digest(js2) + "'; "
        + "style-src 'sha256-" + digest(css) + "';",
    )
    if "http://" in html or "https://" in html or "localStorage" in html or "fetch(" in html:
        raise ValueError("Standalone may not contain remote or persistent behaviour")
    OUTPUT.write_text(html, encoding="utf-8")
    print("Built private offline HTML:", OUTPUT.name, OUTPUT.stat().st_size, "bytes")
    print("SHA256:", hashlib.sha256(OUTPUT.read_bytes()).hexdigest())
    print("Build output is not authentication, a consent grant or release evidence.")


if __name__ == "__main__":
    main()
