"""Portable script-free launcher for original source-bound coordination bundle."""
from __future__ import annotations

from hashlib import sha256
from base64 import b64encode

CSS = """:root{font-family:system-ui,-apple-system,sans-serif;background:#091723;color:#e9f5fa}*{box-sizing:border-box}body{max-width:980px;margin:0 auto;padding:clamp(18px,5vw,65px);line-height:1.65}a{color:#a3f4ee}h1{font-size:clamp(2.25rem,5vw,4rem);line-height:1.08;letter-spacing:-.055em}header{padding:36px;border-radius:24px;border:1px solid #466578;background:linear-gradient(125deg,#184355,#10202c)}.flag{color:#ffe5a6;font-weight:800;font-size:.75rem;letter-spacing:.12em}h2{font-size:1.3rem}.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:15px;margin:20px 0}.card{display:block;padding:22px;border:1px solid #315971;border-radius:18px;background:#123143;text-decoration:none}.card strong{display:block;font-size:1.08rem}.card span{color:#abc7d6;display:block;margin-top:12px;font-size:.88rem}.card:hover{border-color:#a3f4ee;background:#154459}.disclaimer{border-left:5px solid #d7bc7d;padding:18px;background:#283748;margin-top:22px}.disclaimer p{margin:0}footer{color:#8ca6b7;font-size:.87rem;margin-top:35px}@media(max-width:600px){.cards{grid-template-columns:1fr}header{padding:20px}}@media print{body{background:white;color:black}header,.card,.disclaimer{color:black;background:white;border:1px solid #aaa}}"""


def render(*, is_private: bool, with_followup: bool, with_studio: bool, hold: bool,
           with_agenda: bool = False) -> bytes:
    links = [
        ("archive-dashboard.html", "Archived source overview",
         "Previously indexed private source classes, counts and byte-integrity information."),
    ]
    if with_followup:
        links.append(("human-worklist.html", "Human follow-up board",
                      "Source-bound operator coordination stages. Never a security clearance."))
    if with_agenda:
        links.append(("human-agenda.html", "Human follow-up agenda",
                      "Original source-bound human planning attention; dates never imply security authority."))
    if with_studio:
        links.append(("archive-studio.html", "Interactive Archive Studio",
                      "Owner-private, memory-only human planning and draft JSON export."))
    cards = "".join(
        '<a class="card" href="' + filename + '"><strong>' + title +
        '</strong><span>' + description + '</span></a>'
        for filename, title, description in links
    )
    hash_css = b64encode(sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    state = "HOLD" if hold else "REVIEW_ONLY"
    privacy = "OWNER PRIVATE — contains sensitive source metadata" if is_private else "AGGREGATE ONLY — no source fingerprints"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; img-src 'none'; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; style-src 'sha256-{hash_css}'">
<title>LightUp — Offline Lab Review Room</title><style>{CSS}</style></head><body>
<header><div class="flag">LIGHTUP / ASSESSMENT REVIEW / LOCAL ONLY</div>
<h1>Human review room</h1>
<p>Open previously captured lab source inventory and optional source-bound human follow-up.
This standalone packet does not contain original findings, evidence files, clients or target details.</p>
<div class="flag">{privacy} · INCUBATE M3/M7 · DRAFT/HOLD · {state}</div></header>
<main><h2>Choose a local work surface</h2><div class="cards">{cards}</div>
<div class="disclaimer"><h2>No execution authority</h2>
<p>Metadata and human follow-up are unsigned, unverified planning inputs. Missing sources do not indicate remediation.
Never infer consent, customer identity, owned scope, a verified fix, model quality, PASS or GO.
The original independent source, security/privacy, CI and genuine human authorization gates remain mandatory.</p></div>
</main><footer>No network, remote scripts, storage, cookies, authorization or actions on a target.
The optional interactive Studio only edits and downloads local drafts, which require original Python source validation.</footer>
</body></html>"""
    return page.encode("utf-8")
