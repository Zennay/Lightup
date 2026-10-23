"""Build the source-only LightUp PRIVATE HUMAN reconciliation studio as one offline HTML.

No original lab evidence, private reviews, targets, passwords, sessions, models,
network access, consent or release behavior. Static assets only. Optional
offline builder reads the four original source assets beside this file.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import tempfile

LIMITS = {
    "reconcile-studio.html": 128 * 1024,
    "reconcile-studio.css": 80 * 1024,
    "review-vault.js": 256 * 1024,
    "reconcile-studio.js": 512 * 1024,
}
ORIGINAL_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'none'; img-src 'none'; object-src 'none'; "
    "frame-src 'none'; base-uri 'none'; form-action 'none'"
)
CSS_MARKER = '<link rel="stylesheet" href="./reconcile-studio.css">'
VAULT_MARKER = '<script src="./review-vault.js" defer></script>'
JS_MARKER = '<script src="./reconcile-studio.js" defer></script>'


def read_asset(path: Path, limit: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("static input not admitted")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        if not 0 < len(raw) <= limit or b"\x00" in raw:
            raise ValueError("source too large or NUL")
        return raw.decode("utf-8", "strict")
    finally:
        os.close(fd)


def sha_pin(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def compose(assets: dict[str, str]) -> str:
    if set(assets) != set(LIMITS):
        raise ValueError("original static inventory required")
    page, css, vault, js = (assets[name] for name in LIMITS)
    if any(danger in value.lower() for danger, value in (
        ("</style", css), ("</script", vault), ("</script", js)
    )):
        raise ValueError("unsafe inline HTML delimiter in source asset")
    old_csp = 'content="' + ORIGINAL_CSP + '"'
    if any(page.count(marker) != 1 for marker in
           (old_csp, CSS_MARKER, VAULT_MARKER, JS_MARKER, "</body>")):
        raise ValueError("source HTML differs from pinned static contract")
    policy = (
        "default-src 'none'; "
        f"script-src '{sha_pin(chr(10) + vault)}' '{sha_pin(chr(10) + js)}'; "
        f"style-src '{sha_pin(chr(10) + css)}'; "
        "connect-src 'none'; img-src 'none'; object-src 'none'; "
        "frame-src 'none'; base-uri 'none'; form-action 'none'"
    )
    result = page.replace(old_csp, 'content="' + policy + '"')
    result = result.replace(CSS_MARKER, "<style>\n" + css + "</style>")
    result = result.replace(VAULT_MARKER, "")
    result = result.replace(JS_MARKER, "")
    # The local script is deliberately moved to the bottom: inline scripts
    # have no defer semantics, so it must run only after the DOM is parsed.
    result = result.replace("</body>", "<script>\n" + vault + "</script>\n"
                            "<script>\n" + js + "</script>\n</body>")
    if len(result.encode("utf-8")) > 1024 * 1024:
        raise ValueError("source-only portable HTML too large")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Build local PRIVATE HUMAN one-file workroom")
    parser.add_argument("--output", default="reconcile-standalone.html")
    args = parser.parse_args()
    if Path(args.output).name != args.output or args.output in LIMITS:
        parser.error("output must be a new basename beside the source")
    root = Path(__file__).resolve().parent
    html = compose({name: read_asset(root / name, maximum) for name, maximum in LIMITS.items()})
    fd, tmp = tempfile.mkstemp(prefix=".lightup-reconcile-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(html.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        os.link(tmp, root / args.output)
        dirfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    print("PRIVATE local one-file software built exclusively; no client or release authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
