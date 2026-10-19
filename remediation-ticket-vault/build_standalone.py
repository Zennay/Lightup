#!/usr/bin/env python3
"""Build private offline WebCrypto ticket vault as a CSP-hash-pinned single HTML file."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
SCRIPT = ROOT / "vault-web.js"
TAG = '<script src="./vault-web.js"></script>'


def build() -> bytes:
    html = INDEX.read_text(encoding="utf-8")
    script = SCRIPT.read_bytes()
    if b"</script" in script.lower():
        raise ValueError("Embedded script end-tag is forbidden.")
    script.decode("utf-8", errors="strict")
    if html.count(TAG) != 1 or html.count("script-src 'self'") != 1:
        raise ValueError("Unexpected external script or CSP layout.")
    exact_bytes = b"\n" + script + b"\n"
    digest = base64.b64encode(hashlib.sha256(exact_bytes).digest()).decode("ascii")
    html = html.replace("script-src 'self'", "script-src 'sha256-" + digest + "'")
    html = html.replace(TAG, "<script>\n" + script.decode("utf-8") + "\n</script>")
    if TAG in html or "connect-src 'none'" not in html or "form-action 'none'" not in html:
        raise ValueError("Unsafe or incomplete offline vault bundle.")
    return html.encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Brand-new private local file; must not already exist")
    args = parser.parse_args()
    result = build()
    path = args.output.expanduser().absolute()
    if not path.parent.is_dir():
        raise ValueError("Choose an existing private directory.")
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(result)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    print(f"Built {len(result)} byte offline vault HTML (0600): {path}")
    print("SHA-256:", hashlib.sha256(result).hexdigest())


if __name__ == "__main__":
    main()
