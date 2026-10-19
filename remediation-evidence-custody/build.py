#!/usr/bin/env python3
"""Deterministic, self-contained PRIVATE offline browser bundle, not a QA suite."""
from pathlib import Path
import base64
import hashlib

ROOT = Path(__file__).resolve().parent
source = (ROOT / "index.template.html").read_text(encoding="utf-8")
css = (ROOT / "style.css").read_text(encoding="utf-8").strip()
script = (ROOT / "custody.js").read_text(encoding="utf-8").strip()
original_path = ROOT.parent / "casework" / "remediation-engine.js"
original = original_path.read_text(encoding="utf-8")
EXPECTED_ORIGINAL_SHA = "c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225"
if hashlib.sha256(original.encode("utf-8")).hexdigest() != EXPECTED_ORIGINAL_SHA:
    raise SystemExit("Original Casework parser changed; HUMAN HOLD, no bundle.")

def pin(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")

for marker in ("__STYLE_HASH__", "__SCRIPT_HASH__", "__ORIGINAL_HASH__", "__STYLE__", "__SCRIPT__", "__ORIGINAL_JS__"):
    if source.count(marker) != 1:
        raise SystemExit("Missing/duplicate template marker: " + marker)
bundle = (source.replace("__STYLE_HASH__", pin(css)).replace("__SCRIPT_HASH__", pin(script))
         .replace("__STYLE__", css).replace("__SCRIPT__", script)
         .replace("__ORIGINAL_HASH__", pin(original)).replace("__ORIGINAL_JS__", original))
if any(x in bundle for x in ("__STYLE__", "__SCRIPT__", "__STYLE_HASH__", "__SCRIPT_HASH__", "__ORIGINAL_HASH__", "__ORIGINAL_JS__")):
    raise SystemExit("Unexpected unresolved placeholder")
path = ROOT / "standalone.html"
path.write_text(bundle, encoding="utf-8")
blob = bundle.encode("utf-8")
print("Offline PRIVATE HUMAN app", len(blob), "bytes, SHA-256", hashlib.sha256(blob).hexdigest())
