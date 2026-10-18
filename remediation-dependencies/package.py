#!/usr/bin/env python3
"""Package offline human dependency board with byte-pinned, unchanged original Casework.

Build only; no scanner, network, customer records, grant or authorization.
"""
from __future__ import annotations
import hashlib
import base64
import os
from pathlib import Path

HERE=Path(__file__).resolve().parent
ORIGINAL=HERE.parent/"casework"/"remediation-engine.js"
ORIGINAL_SHA256="c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
OUT=HERE/"standalone.html"

def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def pin(data:bytes)->str:
    return "'sha256-"+base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")+"'"

def build()->bytes:
    source=ORIGINAL.read_bytes()
    if sha(source)!=ORIGINAL_SHA256:
        raise ValueError("Original Casework owner source changed. Independent review required.")
    engine=(HERE/"engine.js").read_bytes()
    app=(HERE/"app.js").read_bytes()
    css=(HERE/"style.css").read_bytes()
    html=(HERE/"index.html").read_text("utf-8")
    anchor="script-src 'self'; style-src 'self'"
    if html.count(anchor)!=1:
        raise ValueError("Unexpected CSP template")
    html=html.replace(anchor,"script-src "+' '.join(pin(x) for x in (source,engine,app))+
                      "; style-src "+pin(css))
    subs=[
        ('<link rel="stylesheet" href="style.css">',"<style>"+css.decode("utf-8")+"</style>"),
        ('<script src="../casework/remediation-engine.js"></script>',"<script>"+source.decode("utf-8")+"</script>"),
        ('<script src="engine.js"></script>',"<script>"+engine.decode("utf-8")+"</script>"),
        ('<script src="app.js"></script>',"<script>"+app.decode("utf-8")+"</script>"),
    ]
    for before,after in subs:
        if html.count(before)!=1:
            raise ValueError("Missing/ambiguous source asset")
        html=html.replace(before,after)
    return html.encode("utf-8")

if __name__=="__main__":
    result=build()
    if OUT.is_symlink():raise ValueError("Refusing symlink destination")
    temp=HERE/".standalone.tmp"
    if temp.exists() or temp.is_symlink():raise ValueError("Pending packaging artifact requires review")
    try:
        with temp.open("xb") as target:
            target.write(result);target.flush();os.fsync(target.fileno())
        temp.replace(OUT)
    finally:
        temp.unlink(missing_ok=True)
    print(OUT.name,len(result),"bytes",sha(result))
