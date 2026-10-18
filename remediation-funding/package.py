"""Generate the standalone non-authorizing LightUp funding review app."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "standalone.html"


def sha256_csp(data: str) -> str:
    return base64.b64encode(hashlib.sha256(data.encode("utf-8")).digest()).decode("ascii")


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError("Unmatched HTML packaging insertion")
    return text.replace(before, after, 1)


def build() -> None:
    html = (HERE / "index.html").read_text(encoding="utf-8")
    css = (HERE / "style.css").read_text(encoding="utf-8")
    scripts = [(name, (HERE / f"{name}.js").read_text(encoding="utf-8"))
               for name in ("model", "app")]
    if len(html) + len(css) + sum(len(js) for _, js in scripts) > 250_000:
        raise ValueError("Unexpectedly large standalone source")
    if "</style" in css.lower() or any("</script" in js.lower() for _, js in scripts):
        raise ValueError("Unsafe HTML inline delimiter")
    html = replace_once(html, '<link rel="stylesheet" href="./style.css">',
                        "<style>" + css + "</style>")
    for name, _ in scripts:
        html = replace_once(html, f'<script src="./{name}.js" defer></script>', "")
    inline = "\n".join("<script>" + js + "</script>" for _, js in scripts)
    html = replace_once(html, "</body>", inline + "\n</body>")
    html = replace_once(html, "script-src 'self'; style-src 'self';",
                        "script-src " +
                        " ".join("'sha256-" + sha256_csp(js) + "'" for _, js in scripts) +
                        "; style-src 'sha256-" + sha256_csp(css) + "';")
    if any(fragment in html for fragment in ("http://", "https://", "localStorage", "fetch(", "XMLHttpRequest(")):
        raise ValueError("Network or persistence guard refused standalone")
    OUTPUT.write_text(html, encoding="utf-8")
    print("Built", OUTPUT, OUTPUT.stat().st_size, "bytes")
    print("SHA256:", hashlib.sha256(OUTPUT.read_bytes()).hexdigest())
    print("BUILD_ONLY; no consent, security release, scan or authority.")


if __name__ == "__main__":
    build()
