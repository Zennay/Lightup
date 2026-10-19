#!/usr/bin/env python3
"""Build a standalone SHA-256-CSP-pinned PRIVATE human-source continuity reviewer.

This only embeds source-owned HTML/CSS/JS, no network, scanning, authentication, QA,
execution of real targets or changes to original findings.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile

HUB=Path(__file__).resolve().parent
OUTPUT=HUB/"source-continuity-standalone.html"
STYLES=(HUB/"theme.css",HUB/"triage.css")
SCRIPT=HUB/"source-continuity.js"
SOURCE=HUB/"source-continuity.html"


def read(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
        raise ValueError("Original PRIVATE document source missing, symlinked or oversized")
    return path.read_text(encoding="utf-8")


def pinned(s: str) -> str:
    return "'sha256-"+base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode("ascii")+"'"


def build() -> bytes:
    html=read(SOURCE)
    css="\n".join("/* PRIVATE original stylesheet "+f.name+" */\n"+read(f) for f in STYLES)
    js="/* PRIVATE original source continuity script */\n"+read(SCRIPT)
    if "</style" in css.lower() or "</script" in js.lower():
        raise ValueError("Unsafe original inline tag closing sequence; HOLD")
    for filename in ("theme.css","triage.css"):
        tag='<link rel="stylesheet" href="'+filename+'">'
        if html.count(tag)!=1:raise ValueError("Source style dependency changed; HOLD")
        html=html.replace(tag,"<style>"+css+"</style>" if filename=="theme.css" else "",1)
    tag='<script src="source-continuity.js" defer></script>'
    if html.count(tag)!=1:raise ValueError("Source code dependency changed; HOLD")
    html=html.replace(tag,"",1)
    html=html.replace('<a href="index.html">← Operations Hub</a>','<a href="#compare">↑ Local source comparison</a>',1)
    html=html.replace('<a href="triage.html">HUMAN Inbox</a>','',1)
    csp="default-src 'none'; script-src "+pinned(js)+"; style-src "+pinned(css)+"; img-src 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'"
    old='<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; style-src \'self\'; img-src \'none\'; connect-src \'none\'; object-src \'none\'; frame-src \'none\'; form-action \'none\'; base-uri \'none\'">'
    if html.count(old)!=1:raise ValueError("Original CSP changed; HOLD")
    html=html.replace(old,'<meta http-equiv="Content-Security-Policy" content="'+csp+'">',1)
    if html.count("</body>")!=1:raise ValueError("Original HTML body changed; HOLD")
    html=html.replace("</body>","<script>"+js+"</script></body>",1)
    if "src=\"source-continuity.js\"" in html or 'rel="stylesheet"' in html:
        raise ValueError("Standalone still depends on separate JS/CSS")
    return html.encode("utf-8")


def main()->None:
    data=build()
    fd,tmp=tempfile.mkstemp(prefix=".private-original-human-continuity-",dir=HUB)
    try:
        with os.fdopen(fd,"wb") as f:f.write(data)
        os.replace(tmp,OUTPUT)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    print(f"Published PRIVATE original HUMAN Source Continuity standalone: {len(data)} bytes")


if __name__=="__main__":
    main()
