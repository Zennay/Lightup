"""Build LightUp's PRIVATE HUMAN workroom as one exact, offline HTML file.

No original lab source, HUMAN notes, vaults, network fetches or runtime imports.
The resulting content is static product code only, never confidential client data.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import tempfile

ASSETS = {
    "review-studio.html": 128 * 1024,
    "review-studio.css": 80 * 1024,
    "review-vault.js": 256 * 1024,
    "review-studio.js": 512 * 1024,
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; "
       "base-uri 'none'; form-action 'none'")
CSS_REF = '<link rel="stylesheet" href="./review-studio.css">'
JS_REFS = (
    '<script src="./review-vault.js" defer></script>',
    '<script src="./review-studio.js" defer></script>',
)


def _admit(path: Path, maximum: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
            raise ValueError("static product asset is not admitted")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if not 0 < len(raw) <= maximum:
            raise ValueError("static product asset exceeds maximum size")
        value = raw.decode("utf-8", errors="strict")
        if "\x00" in value:
            raise ValueError("NUL in product asset")
        return value
    finally:
        os.close(fd)


def _pin(source: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(source.encode("utf-8")).digest()
    ).decode("ascii")


def compose(assets: dict[str, str]) -> str:
    if set(assets) != set(ASSETS):
        raise ValueError("complete static source inventory required")
    html = assets["review-studio.html"]
    css = assets["review-studio.css"]
    vault = assets["review-vault.js"]
    studio = assets["review-studio.js"]
    if "</style" in css.lower() or "</script" in vault.lower() or "</script" in studio.lower():
        raise ValueError("inline HTML delimiter refused in static source")
    old = 'content="' + CSP + '"'
    new_policy = (
        "default-src 'none'; "
        f"script-src '{_pin(chr(10) + vault)}' '{_pin(chr(10) + studio)}'; "
        f"style-src '{_pin(chr(10) + css)}'; "
        "connect-src 'none'; img-src 'none'; object-src 'none'; "
        "frame-src 'none'; base-uri 'none'; form-action 'none'"
    )
    if html.count(old) != 1 or html.count(CSS_REF) != 1 or any(
        html.count(anchor) != 1 for anchor in JS_REFS
    ):
        raise ValueError("original HTML or CSP interface differs from pinned builder")
    html = html.replace(old, 'content="' + new_policy + '"')
    html = html.replace(CSS_REF, "<style>\n" + css + "</style>")
    html = html.replace(JS_REFS[0], "<script>\n" + vault + "</script>")
    html = html.replace(JS_REFS[1], "<script>\n" + studio + "</script>")
    # SHA-256 CSP hashes above cover the exact leading newline plus source
    # inside each inline element, matching the literal markup inserted here.
    return html


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a PRIVATE local-only static workroom")
    parser.add_argument("--output", default="standalone.html",
                        help="new output basename in the source directory")
    args = parser.parse_args()
    if Path(args.output).name != args.output or args.output in ASSETS:
        parser.error("output must be a new basename, not a source asset")
    directory = Path(__file__).resolve().parent
    sources = {name: _admit(directory / name, limit) for name, limit in ASSETS.items()}
    output = compose(sources)
    fd, staged = tempfile.mkstemp(prefix=".lightup-standalone-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(output.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staged, directory / args.output)
        dirfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(staged)
        except FileNotFoundError:
            pass
    print("Offline PRIVATE HUMAN standalone published exclusively; no approval or network")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
