#!/usr/bin/env python3
"""Build a standalone offline LightUp human scope-preparation workspace.

This is a packaging tool, not a test runner and not an authorization tool.
It reads exactly the local, reviewed static sources; no network or plugins.
Each embedded script is pinned in a CSP SHA-256 allowlist.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
HTML = HERE / "scope-readiness.html"
SOURCES = (
    "strict-local-json.js",
    "scope-local-lineage.js",
    "scope-revision-review.js",
    "scope-readiness.js",
)
SOURCE_TAG = re.compile(
    r'<script\s+src="\./([^"]+)"\s+defer></script>',
    flags=re.ASCII,
)
CSP_TAG = re.compile(
    r'(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]+)(">)',
    flags=re.ASCII,
)


def build() -> str:
    html = HTML.read_text(encoding="utf-8")
    listed = SOURCE_TAG.findall(html)
    if tuple(listed) != SOURCES:
        raise ValueError(
            "The HTML script list changed: manual source-owner review required."
        )
    if len(CSP_TAG.findall(html)) != 1:
        raise ValueError("Require exactly one original restrictive CSP.")
    hashes = []
    bundles = []
    for source in SOURCES:
        code = (HERE / source).read_text(encoding="utf-8")
        # A literal closing script tag would terminate the inline element.
        # Refuse ambiguous source rather than performing a lossy rewrite.
        if re.search(r"</script\s*>", code, flags=re.IGNORECASE):
            raise ValueError("Embedded JavaScript contains a closing script tag.")
        # Hash exactly the bytes the HTML tokenizer will read.
        code = "\n" + code.rstrip("\n") + "\n"
        sha = base64.b64encode(hashlib.sha256(code.encode("utf-8")).digest()).decode("ascii")
        hashes.append("'sha256-" + sha + "'")
        bundles.append("<script>" + code + "</script>")
    replacements = iter(bundles)
    html = SOURCE_TAG.sub(lambda _: next(replacements), html)

    def restrict_csp(match: re.Match[str]) -> str:
        original = match.group(2)
        directives = [p.strip() for p in original.split(";") if p.strip()]
        if not any(p == "default-src 'none'" for p in directives):
            raise ValueError("Refusing to weaken default-src 'none'.")
        if not any(p == "connect-src 'none'" for p in directives):
            raise ValueError("Refusing to weaken connect-src 'none'.")
        script_directives = [d for d in directives if d.startswith("script-src ")]
        if script_directives != ["script-src 'self'"]:
            raise ValueError("Unexpected source CSP script directive.")
        directives = [
            "script-src " + " ".join(hashes) if p.startswith("script-src ") else p
            for p in directives
        ]
        # No unsafe-inline or wildcard script permissions: hashes only.
        return match.group(1) + "; ".join(directives) + match.group(3)

    html = CSP_TAG.sub(restrict_csp, html)
    if SOURCE_TAG.search(html):
        raise ValueError("Residual remote/relative script source refused.")
    return html


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bundle LightUp private scope coordination as one self-contained HTML file."
    )
    parser.add_argument(
        "--output", type=Path,
        default=HERE / "scope-readiness-standalone.html",
        help="HTML output path (defaults to a sibling of the source files)",
    )
    args = parser.parse_args()
    out = args.output.expanduser().resolve()
    # Guard against accidental replacement of original source files.
    if out in (HTML.resolve(), *(HERE / source).resolve() for source in SOURCES):
        raise ValueError("Cannot overwrite a source file.")
    out.parent.mkdir(parents=True, exist_ok=True)
    result = build()
    out.write_text(result, encoding="utf-8")
    print(f"Created offline, hash-pinned standalone HTML: {out} ({len(result.encode('utf-8'))} bytes)")
    print("DRAFT/HOLD — local review only, no authorization, grant, release, scan or backend.")


if __name__ == "__main__":
    main()
