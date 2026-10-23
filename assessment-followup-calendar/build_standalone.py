#!/usr/bin/env python3
"""Build fully offline, CSP-digest-pinned standalone HUMAN calendar HTML (production asset)."""
from __future__ import annotations
import argparse
import base64
import hashlib
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
TARGET = HERE / "standalone.html"


def digest(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def build() -> str:
    page = (HERE / "index.html").read_text(encoding="utf-8")
    script = (HERE / "app.js").read_text(encoding="utf-8")
    style = (HERE / "style.css").read_text(encoding="utf-8")
    assert page.count('<link rel="stylesheet" href="./style.css">') == 1
    assert page.count('<script src="./app.js" defer></script>') == 1
    assert "</script" not in script.lower() and "</style" not in style.lower()
    old = 'script-src \'self\'; style-src \'self\''
    assert page.count(old) == 1
    page = page.replace(old, "script-src 'sha256-" + digest(script) +
                        "'; style-src 'sha256-" + digest(style) + "'")
    page = page.replace('<link rel="stylesheet" href="./style.css">',
                        "<style>\n" + style + "\n</style>")
    page = page.replace('<script src="./app.js" defer></script>',
                        "<script>\n" + script + "\n</script>")
    # Hashes must match actual inline element data including the inserted newline bytes.
    page = page.replace("sha256-" + digest(script), "sha256-" + digest("\n" + script + "\n"))
    page = page.replace("sha256-" + digest(style), "sha256-" + digest("\n" + style + "\n"))
    assert 'href="./style.css"' not in page and 'src="./app.js"' not in page
    return page


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replace", action="store_true",
                        help="Explicitly replace a previously built standalone asset")
    args = parser.parse_args()
    if TARGET.exists() and not args.replace:
        parser.error("standalone already exists; use --replace")
    content = build()
    fd, temp_path = tempfile.mkstemp(prefix=".standalone.", dir=HERE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, TARGET)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    print(f"Built {TARGET.name}: {len(content.encode('utf-8'))} UTF-8 bytes")


if __name__ == "__main__":
    main()
