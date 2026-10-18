#!/usr/bin/env python3
"""Reproducible local single-file HTML builder; never contacts a target."""
from pathlib import Path
import hashlib, base64
from make_fixture_pack import make
ROOT=Path(__file__).resolve().parent
html=(ROOT/'index.html').read_text(encoding='utf-8')
css=(ROOT/'style.css').read_text(encoding='utf-8')
fixture=make().read_text(encoding='utf-8')
js=(ROOT/'app.js').read_text(encoding='utf-8')
if '</style' in css.lower() or '</script' in js.lower() or '</script' in fixture.lower(): raise SystemExit('invalid inline delimiter')
def sh(t):return base64.b64encode(hashlib.sha256(t.encode('utf-8')).digest()).decode('ascii')
policy="; ".join(["default-src 'none'","base-uri 'none'","connect-src 'none'",
    "form-action 'none'","object-src 'none'","frame-src 'none'","img-src 'none'",
    "style-src 'sha256-"+sh(css)+"'","script-src 'sha256-"+sh(fixture)+"' 'sha256-"+sh(js)+"'"])
assert html.count('<link rel="stylesheet" href="style.css">')==1
assert html.count('<script src="fixture-pack.js" defer></script>')==1
assert html.count('<script src="app.js" defer></script>')==1
html=html.replace('</title>',"</title><meta http-equiv=\"Content-Security-Policy\" content=\""+policy+"\">")
html=html.replace('<link rel="stylesheet" href="style.css">','<style>'+css+'</style>')
html=html.replace('<script src="fixture-pack.js" defer></script>','<script>'+fixture+'</script>')
html=html.replace('<script src="app.js" defer></script>','<script>'+js+'</script>')
out=ROOT/'standalone.html'
out.write_text(html,encoding='utf-8')
print('Build',out.name,out.stat().st_size,'bytes; sha256',hashlib.sha256(out.read_bytes()).hexdigest())