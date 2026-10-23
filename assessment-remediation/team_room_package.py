#!/usr/bin/env python3
"""Portable, no-network, hash-CSP LightUp human team room compiler."""
from __future__ import annotations

import base64
from hashlib import sha256
from pathlib import Path

HERE = Path(__file__).resolve().parent

CSS = """
:root{--ink:#1c2a3e;--muted:#56677d;--line:#d4dfea;--bg:#f1f5fa;--deep:#17365d;--alert:#7e381d}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,sans-serif}
header{background:linear-gradient(115deg,#12283f,#1f4b76);color:#fff;padding:3rem max(1.4rem,calc((100vw - 1080px)/2))}
header h1{font-size:clamp(2rem,5vw,3.25rem);letter-spacing:-.045em;line-height:1.05;margin:.7rem 0}
header p{max-width:840px;color:#d8e9f7}aside{background:#fff5e5;color:#6e381b;border-left:4px solid #f0b55f;border-radius:4px;padding:1rem;margin-top:1.5rem;max-width:980px}
.overline{font-size:.8rem!important;color:#b5dafb!important;font-weight:800;letter-spacing:.15em}
main{max-width:1120px;margin:auto;padding:1rem 1.5rem 3rem}
section{border:1px solid var(--line);border-radius:12px;padding:1.5rem 1.7rem;background:white;margin:1.4rem 0;box-shadow:0 9px 24px #1630550a}
.heading{display:flex;align-items:flex-start;gap:1rem}.step{display:inline-flex;align-items:center;justify-content:center;border-radius:10px;background:#e3efff;color:var(--deep);font-weight:900;width:2.5rem;height:2.5rem;flex-shrink:0}
h2{font-size:1.35rem;letter-spacing:-.025em;margin:0}h3{font-size:1rem;margin:1.6rem 0 .3rem}
section p{color:var(--muted);margin:.3rem 0 1.2rem}
label{font-weight:700;display:block;font-size:.91rem;margin:1rem 0}
input:not([type=checkbox]),select,textarea{width:100%;margin:.35rem 0;background:#f9fbfe;border:1px solid #b9c9dd;border-radius:6px;padding:.7rem;font:inherit;color:var(--ink)}
input:focus-visible,select:focus-visible,textarea:focus-visible,button:focus-visible{outline:3px solid #e5ab43;outline-offset:3px}
button{padding:.7rem 1rem;border:0;border-radius:6px;background:#1e5089;color:white;font:inherit;font-weight:750;cursor:pointer;margin:.2rem .25rem .2rem 0}
button.secondary{background:#e6edf7;color:#1e5089;border:1px solid #a7bcd7}
button:hover{filter:brightness(1.12)}
.items{display:grid;gap:.5rem;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));max-height:350px;overflow:auto;padding:.5rem}
button.choice{text-align:left;background:#f0f5fc;color:#1b3c62;border:1px solid #c4d7f0;font-size:.84rem;overflow-wrap:anywhere}
button.choice[aria-pressed=true]{background:#d6e6fc;border-color:#22508a}
.pair{font-weight:700;color:#20436b!important;background:#edf5ff;padding:.85rem;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.25rem}
.confirm{display:flex;align-items:center;gap:.5rem;font-weight:550}.confirm input{flex-shrink:0}
.notice{border:1px solid #c4d4e7;padding:.85rem;background:#e9f4ff;border-radius:6px}
.notice.error{color:#8a2f21;background:#fff0eb;border-color:#e4b4aa}
.sub{font-size:.85rem;color:var(--muted)}
code{overflow-wrap:anywhere;border-radius:3px;background:#eaf0f7;color:#21446c;padding:.1rem .3rem}
footer{text-align:center;font-size:.78rem;color:var(--muted);border-top:1px solid var(--line);padding:1.8rem}
@media(max-width:650px){main{padding:.8rem}section{padding:1rem}header{padding:2rem 1.4rem}}
@media print{.items,input,textarea,button{display:none}section{box-shadow:none}}
""".strip()


def digest(blob):
    return base64.b64encode(sha256(blob).digest()).decode("ascii")


def build():
    template = (HERE / "team-room.template.html").read_text("utf-8")
    script = (HERE / "team-room.js").read_text("utf-8")
    if "</script" in script.lower() or "</style" in CSS.lower():
        raise ValueError("source contains unexpected HTML closing tag")
    for token in ("{{SCRIPT}}", "{{CSS}}", "{{CSP}}"):
        if template.count(token) != 1:
            raise ValueError("missing or repeated exact template placeholder")
    csp = ("default-src 'none'; connect-src 'none'; base-uri 'none'; "
           "form-action 'none'; object-src 'none'; img-src 'none'; "
           "script-src 'sha256-" + digest(script.encode("utf-8")) +
           "'; style-src 'sha256-" + digest(CSS.encode("utf-8")) + "'")
    page = (template.replace("{{CSP}}", csp)
            .replace("{{CSS}}", CSS).replace("{{SCRIPT}}", script))
    if "{{" in page:
        raise ValueError("unknown token remained")
    dest = HERE / "team-room.html"
    dest.write_bytes(page.encode("utf-8"))
    print("Offline private team room", len(page.encode("utf-8")),
          "bytes SHA256", sha256(dest.read_bytes()).hexdigest())


if __name__ == "__main__":
    build()
