#!/usr/bin/env python3
"""Build a single private portable source-bound mapping Studio; no QA/test runner."""
from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent

CSS = r"""
:root{color-scheme:light;--ink:#1b2b45;--muted:#566579;--line:#d6dfeb;--paper:#f2f5fa;--action:#214c88;--warning:#85450f}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:var(--paper)}
.hero{background:linear-gradient(125deg,#102a52,#244b78);color:white;padding:3rem max(1.5rem,calc((100vw - 1100px)/2))}
.hero h1{font-size:clamp(2rem,5vw,3.2rem);letter-spacing:-.045em;line-height:1.12;margin:.4rem 0 1rem}
.hero .lede{max-width:800px;font-size:1.05rem;color:#e1eafa}
.eyebrow{text-transform:uppercase;font-size:.78rem;font-weight:800;letter-spacing:.14em;color:#a7c7f5}
.warning{margin-top:1.6rem;background:#fff7ea;color:#563213;border-left:4px solid #e6a14c;padding:1rem 1.2rem;border-radius:.25rem;max-width:950px}
main{max-width:1130px;margin:0 auto;padding:1.5rem 1.5rem 3rem}
.panel{background:white;border:1px solid var(--line);border-radius:14px;box-shadow:0 8px 28px #10243e09;padding:1.5rem 1.75rem;margin:1.15rem 0}
.panel p{color:var(--muted);margin:.3rem 0 1.15rem}
.section-title{display:flex;align-items:flex-start;gap:1rem;margin-bottom:.75rem}
.step{display:inline-flex;justify-content:center;align-items:center;flex:none;background:#eaf1fc;color:#214c88;border-radius:11px;font-size:.82rem;font-weight:900;width:2.5rem;height:2.5rem}
h2{font-size:1.3rem;letter-spacing:-.02em;margin:0}h3{font-size:1rem}
.file-grid,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem}
.grid.two{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
label{font-size:.89rem;font-weight:700;display:block;margin:.8rem 0}
label .sub{display:block;font-weight:400}.sub{font-size:.84rem;color:var(--muted)}
input,select,textarea{display:block;width:100%;font:inherit;border:1px solid #b6c4d9;background:#fbfcff;color:var(--ink);border-radius:7px;padding:.7rem .8rem;margin:.35rem 0}
input:focus-visible,select:focus-visible,textarea:focus-visible,button:focus-visible{outline:3px solid #d8a24b;outline-offset:2px}
input[type=file]{padding:.6rem;cursor:pointer;max-width:100%}
button{background:var(--action);color:white;font:inherit;font-weight:700;padding:.7rem 1rem;border:0;border-radius:7px;cursor:pointer;margin:.4rem .25rem .4rem 0}
button:hover{filter:brightness(1.13)}button.minor{font-size:.8rem;background:#e8eff8;color:#244b78;padding:.4rem .65rem}
button.danger{background:#fff1ef;color:#8f2c23}
#link-count{font-size:.9rem}.table-wrap{max-width:100%;overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:630px;font-size:.89rem}
th,td{text-align:left;padding:.8rem .6rem;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:#465b77;background:#f4f7fc}
.message{border:1px solid #b6c7df;border-radius:9px;background:#e8f2ff;padding:1rem 1.2rem;margin:1rem 0}
.message.error{background:#fff0eb;color:#8d2f20;border-color:#e7b1a5}
code{background:#f0f3f8;border:1px solid #e4eaf3;border-radius:4px;padding:.15rem .3rem;overflow-wrap:anywhere}
.inspector-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:1rem;margin-top:1.1rem}
.source-preview{border:1px solid var(--line);border-radius:9px;padding:1rem;margin-top:1rem;background:#f8faff;overflow-wrap:anywhere}
.source-preview h3{margin:.1rem 0 .4rem;font-size:1rem}.source-preview ul{padding-left:1.2rem;max-height:260px;overflow:auto}
.source-preview li{margin:.35rem 0}.metric-mini{display:grid;grid-template-columns:1fr auto;gap:.25rem .75rem;font-size:.8rem}
.metric-mini dt{color:var(--muted)}.metric-mini dd{margin:0;text-align:right}
footer{padding:2rem 1.5rem;text-align:center;font-size:.82rem;color:var(--muted);border-top:1px solid var(--line)}
@media(max-width:600px){main{padding:1rem}.panel{padding:1.1rem}.hero{padding:2rem 1.2rem}.section-title{gap:.55rem}}
@media print{.hero{background:white;color:black;padding:1rem}.hero .lede{color:black}.panel{box-shadow:none}.warning{color:black}button,input,select,textarea,.table-wrap{break-inside:avoid}}
""".strip()


def hash_for_csp(data: bytes) -> str:
    return base64.b64encode(sha256(data).digest()).decode("ascii")


def build():
    template = (HERE / "template.html").read_text("utf-8")
    script = (HERE / "mapping-studio.js").read_text("utf-8")
    if "</script" in script.lower() or "</style" in CSS.lower():
        raise ValueError("inline source would terminate its intended HTML container")
    if template.count("{{SCRIPT}}") != 1 or template.count("{{CSS}}") != 1 or template.count("{{CSP}}") != 1:
        raise ValueError("template placeholders changed")
    script_bytes = script.encode("utf-8")
    style_bytes = CSS.encode("utf-8")
    csp = ("default-src 'none'; connect-src 'none'; form-action 'none'; "
           "base-uri 'none'; img-src 'none'; object-src 'none'; "
           "script-src 'sha256-" + hash_for_csp(script_bytes) +
           "'; style-src 'sha256-" + hash_for_csp(style_bytes) + "'")
    packaged = template.replace("{{CSP}}", csp).replace("{{CSS}}", CSS).replace("{{SCRIPT}}", script)
    if "{{" in packaged:
        raise ValueError("unresolved template token")
    destination = HERE / "standalone.html"
    destination.write_bytes(packaged.encode("utf-8"))
    print("Built private no-network standalone Studio:", destination.name, destination.stat().st_size,
          "bytes; sha256", sha256(destination.read_bytes()).hexdigest())


if __name__ == "__main__":
    build()
