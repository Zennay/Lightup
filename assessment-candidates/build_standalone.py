#!/usr/bin/env python3
"""Deterministic offline single-file builder; no network, QA or tests."""
from pathlib import Path
import hashlib, base64
ROOT=Path(__file__).resolve().parent
html=(ROOT/'index.html').read_text(encoding='utf8')
css=(ROOT/'style.css').read_text(encoding='utf8')
js=(ROOT/'app.js').read_text(encoding='utf8')
if '</style' in css.lower() or '</script' in js.lower(): raise SystemExit('unsafe delimiter')
def sha(s):return base64.b64encode(hashlib.sha256(s.encode('utf8')).digest()).decode('ascii')
policy="; ".join(["default-src 'none'","base-uri 'none'","form-action 'none'",
  "connect-src 'none'","img-src 'none'","object-src 'none'","frame-src 'none'",
  "style-src 'sha256-"+sha(css)+"'","script-src 'sha256-"+sha(js)+"'"])
assert html.count('<link rel="stylesheet" href="style.css">')==1
assert html.count('<script src="app.js" defer></script>')==1
html=html.replace('</title>','</title><meta http-equiv="Content-Security-Policy" content="'+policy+'">')
html=html.replace('<link rel="stylesheet" href="style.css">','<style>'+css+'</style>')
html=html.replace('<script src="app.js" defer></script>','<script>'+js+'</script>')
target=ROOT/'standalone.html'
target.write_text(html,encoding='utf8')
print('Bundled',target.name,len(html.encode('utf8')),'bytes; sha256',hashlib.sha256(html.encode('utf8')).hexdigest())
