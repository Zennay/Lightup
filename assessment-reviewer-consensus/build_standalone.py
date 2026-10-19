"""Rebuild the portable standalone PRIVATE HUMAN reviewer app from its owned sources.

This is a production packaging utility, not a QA/test suite. No network, targets or
customer data; the output is only self-contained HTML, CSS and JavaScript.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parent
MODULES = (
    "original-plan-decrypt.js",
    "original-plan-encrypt.js",
    "private-workspace.js",
    "studio.js",
)
SCRIPT = re.compile(r"<script>(.*?)</script>", re.DOTALL)
STYLE = re.compile(r"<style>(.*?)</style>", re.DOTALL)
SCRIPT_HASH = re.compile(r"script-src 'sha256-[A-Za-z0-9+/=]+'")
STYLE_HASH = re.compile(r"style-src 'sha256-[A-Za-z0-9+/=]+'")


def pin(contents: str) -> str:
    raw = hashlib.sha256(contents.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(raw).decode("ascii")


def exactly_once(pattern: re.Pattern[str], text: str, replacement: str) -> str:
    matched = list(pattern.finditer(text))
    if len(matched) != 1:
        raise ValueError("The standalone source changed structure: no unique replacement")
    return text[: matched[0].start()] + replacement + text[matched[0].end() :]


def render(template: str) -> str:
    body = "\n".join((ROOT / name).read_text(encoding="utf-8") for name in MODULES)
    if not body:
        raise ValueError("No browser source")
    style = STYLE.search(template)
    if style is None:
        raise ValueError("No locally bundled stylesheet")
    css = style.group(1)
    result = exactly_once(SCRIPT, template, "<script>" + body + "</script>")
    result = exactly_once(
        SCRIPT_HASH, result, "script-src '" + pin(body) + "'"
    )
    result = exactly_once(
        STYLE_HASH, result, "style-src '" + pin(css) + "'"
    )
    if "<script src=" in result or "<link rel=" in result:
        raise ValueError("Standalone product cannot depend on external scripts or styles")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, type=Path,
        help="Destination HTML; requires an existing private/local output parent",
    )
    args = parser.parse_args()
    destination = args.output.expanduser().absolute()
    if not destination.parent.is_dir():
        parser.error("Output parent directory must already exist")
    # The only HTML template is the independently owned, source-controlled offline app.
    template = (ROOT / "reviewer-studio.html").read_text(encoding="utf-8")
    rendered = render(template)
    descriptor = -1
    temp_name = ""
    try:
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".lightup-reviewer-studio-", suffix=".tmp", dir=destination.parent
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(rendered.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, destination)
        temp_name = ""
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temp_name:
            os.unlink(temp_name)
    print("Built local, offline, SHA-256-CSP-pinned PRIVATE reviewer app:", destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
