#!/usr/bin/env python3
"""Original-source-only, scriptless landing portal for the PRIVATE suite.

This is informational navigation only. The actual native original source
admission, consent and release gates live outside this software-only UI.
"""
from __future__ import annotations
import html

MODULES = (
    ("01", "Operatorstudio", "operator.html",
     "Werkstappen en lokale terminalcommando’s",
     "Van oorspronkelijke evidence naar afzonderlijk bronvrije HUMAN-overdracht, veilige ontvangst en echte HUMAN-opvolging."),
    ("02", "Originele casework", "casework/index.html",
     "Herstelplanning op originele evidence",
     "Open de ongewijzigde oorspronkelijke casework-workroom voor brongebonden, handmatig gecontroleerde hersteladviezen."),
    ("03", "Evidence Artifact Ledger", "remediation-artifact-ledger/standalone.html",
     "Brongebonden evidence inventaris",
     "Werk in de oorspronkelijke eigenaaromgeving. Deel nooit de originele private evidence-workroom als bronvrije overdracht."),
    ("04", "HUMAN Portfolio Studio", "remediation-portfolio/studio.html",
     "Capaciteit, menselijke prioriteit en opvolging",
     "Sorteer en plan bronvrije HUMAN-beslissingen; dit is geen geverifieerde technische fix of goedgekeurde scope."),
    ("05", "Encrypted HUMAN handoff", "remediation-human-handoff/browser.html",
     "Beperkte privéoverdracht",
     "Oorspronkelijke selectieve HUMAN-opvolging via apart goedgekeurde versleutelde lokale overdracht."),
)

DOCS = (
    ("Volledige native handleiding", "remediation-integrated-workspace/README.md"),
    ("Eén Cockpit en HUMAN-journal", "remediation-integrated-workspace/SINGLE_REVIEW.md"),
    ("Versleutelde HUMAN-notities", "remediation-integrated-workspace/JOURNAL_VAULT.md"),
    ("Bronvrij HUMAN-reviewpakket", "remediation-integrated-workspace/REVIEW_PACKAGE.md"),
    ("Oorspronkelijke evidence-bronacceptatie", "remediation-evidence-bundle-integrity/README.md"),
    ("Oorspronkelijke ontvanger en tijdlijn", "remediation-recipient-trend/README.md"),
)

def render(standalone: bool = False) -> bytes:
    # Standalone start.html lives one directory BELOW the installed root layout.
    prefix = "../" if standalone else ""
    docs_link = "README.md" if standalone else "remediation-integrated-workspace/README.md"
    cards = "\n".join(
        '<article class="module"><div class="no">' + html.escape(num) +
        '</div><h3><a href="' + html.escape(link if link == "operator.html" else prefix + link, quote=True) + '">' +
        html.escape(title) + '</a></h3><p class="topic">' +
        html.escape(topic) + '</p><p>' + html.escape(description) +
        '</p><a class="textlink" href="' + html.escape(link if link == "operator.html" else prefix + link, quote=True) +
        '">Open lokale module <span aria-hidden="true">↗</span></a></article>'
        for num, title, link, topic, description in MODULES
    )
    links = "\n".join(
        '<li><a href="' + html.escape(link if link == "operator.html" else prefix + link, quote=True) +
        '">' + html.escape(title) + '</a></li>'
        for title, link in DOCS
    )
    return ("""<!doctype html><html lang="nl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer">
<title>LightUp · PRIVATE offline HUMAN evidence workroom</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;font-synthesis:none;color:#1b3046;background:#f1f5f9}
*{box-sizing:border-box}body{margin:0}a{color:inherit}
a:focus-visible{outline:3px solid #62bfd0;outline-offset:4px;border-radius:3px}
.wrap{max-width:1180px;padding:28px 24px 70px;margin:auto}
header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:8px 0 22px}
.brand{font-size:1.25rem;font-weight:850;letter-spacing:-.04em}.brand span{color:#287c85}
.header-state{font-weight:700;color:#426475;font-size:.77rem;letter-spacing:.045em}
.hero{position:relative;overflow:hidden;background:#0b2338;border-radius:23px;color:#eefcff;padding:clamp(30px,5vw,64px)}
.hero:after{content:"";position:absolute;top:-205px;right:-160px;width:420px;height:420px;border-radius:50%;border:80px solid rgba(68,186,198,.12)}
.eyebrow{color:#8be7dc;font-weight:850;letter-spacing:.16em;text-transform:uppercase;font-size:.73rem}
h1{font-size:clamp(2.25rem,5.5vw,4.8rem);line-height:1.02;letter-spacing:-.06em;max-width:860px;margin:20px 0}
.hero p{font-size:1.05rem;line-height:1.72;color:#d6eaf2;max-width:690px}
.hero-actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}
.primary,.secondary{display:inline-flex;align-items:center;border-radius:9px;padding:14px 19px;text-decoration:none;font-weight:800}
.primary{background:#a5e9dd;color:#0e3044}.primary:hover{background:white}
.secondary{border:1px solid #6b96a7;color:white}.secondary:hover{background:#2b5366}
.hold{border:1px solid #d4e1e9;border-left:5px solid #ab782e;background:white;padding:20px 25px;margin:22px 0;border-radius:11px;line-height:1.55}
.hold strong{display:block;color:#714c22;margin-bottom:5px}
section{margin-top:44px}.section-head{display:flex;gap:20px;align-items:baseline;justify-content:space-between}
h2{font-size:1.7rem;letter-spacing:-.04em;margin:0 0 16px}
.section-head p{font-size:.91rem;color:#567086;margin:0}
.journey{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.journey article{background:white;border:1px solid #d8e3ec;border-radius:12px;padding:23px 21px}
.journey .step{font-size:.78rem;font-weight:850;color:#0b7884;letter-spacing:.1em}
.journey h3{font-size:1.12rem;line-height:1.38;letter-spacing:-.02em;margin:14px 0 9px}
.journey p{color:#53697f;font-size:.91rem;line-height:1.6;margin:0}
.modules{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}
.module{border:1px solid #d8e2ea;border-radius:13px;background:#fff;padding:25px;display:flex;flex-direction:column;align-items:start;min-height:243px}
.module:first-child{grid-column:1/-1;background:#e6f5f4;border-color:#b5dcd8}
.module .no{font-size:.75rem;letter-spacing:.12em;font-weight:850;color:#187a82}
.module h3{font-size:1.32rem;margin:12px 0 8px;letter-spacing:-.03em}
.module h3 a{text-decoration:none}.module h3 a:hover{text-decoration:underline}
.module .topic{color:#20495b;font-weight:750}
.module p{color:#53677a;font-size:.89rem;line-height:1.57;margin:5px 0 12px}
.textlink{margin-top:auto;color:#126774;font-weight:750;text-decoration:none}
.textlink:hover{text-decoration:underline}
.docs{background:white;border-radius:13px;padding:25px;border:1px solid #d8e2ea}
.docs ul{columns:2;list-style:none;margin:0;padding:0}
.docs li{break-inside:avoid;padding:10px 0;border-bottom:1px solid #e7edf2}
.docs a{color:#1d647b;text-decoration:none;font-weight:650}
.docs a:hover{text-decoration:underline}
.footer{color:#577083;line-height:1.65;font-size:.82rem;padding-top:29px;border-top:1px solid #dae3ec;margin-top:44px}
@media(max-width:760px){.wrap{padding:15px 12px 40px}.header-state{display:none}.journey,.modules{grid-template-columns:1fr}.module:first-child{grid-column:auto}.docs ul{columns:1}.hero{padding:28px 22px}.section-head{display:block}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
</style></head><body><div class="wrap">
<header><div class="brand">Light<span>Up</span><span aria-hidden="true"> / </span>PRIVATE</div>
<div class="header-state">OFFLINE EVIDENCE · HUMAN ONLY · DRAFT/HOLD</div></header>
<main>
<div class="hero"><div class="eyebrow">PRIVATE evidence-remediation suite</div>
<h1>Van evidence naar<br>menselijke opvolging.</h1>
<p>Een volledige offline werkruimte voor oorspronkelijke bewijsvoering, handmatige herstelplanning,
bronvrije overdracht en privé HUMAN-opvolging. Er worden geen klanten, targets of netwerken benaderd.</p>
<div class="hero-actions"><a class="primary" href="operator.html">Open offline operatorstudio →</a>
<a class="secondary" href='""" + docs_link + """'>Bekijk de native handleiding</a></div>
</div>
<aside class="hold" role="note"><strong>INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD</strong>
Dit is uitsluitend broncode/software voor PRIVATE HUMAN-opvolging, geen werkende assessmentdienst en
geen toestemming voor scans, grants, retests, live targets of automatische remediation.
Checksum, encryptie en lokale HUMAN-notities bewijzen geen afzender, originele bron, werkelijke
klanttoestemming of verholpen kwetsbaarheid. Bestaande originele CI-, privacy-, security-,
source-owner- en HUMAN GO-gates blijven verplicht.</aside>
<section><h2>Zo werkt bronvrije HUMAN-overdracht</h2>
<div class="journey">
<article><div class="step">01 / ORIGINAL OWNER</div><h3>Verwerk echte oorspronkelijke evidence</h3>
<p>Open de oorspronkelijke casework en evidence ledger. Maak een nieuwe PRIVATE eigenaarwerkkamer,
scheid de bronvrije Cockpit en bereid alleen na echte goedkeuring een versleuteld pakket en
een privé, niet-ondertekend fingerprintbewijs voor.</p></article>
<article><div class="step">02 / PRIVATE RECIPIENT</div><h3>Controleer ontvangen pakketbytes</h3>
<p>Vergelijk lokaal het daadwerkelijk ontvangen bronvrije pakket met het afzonderlijke PRIVATE
fingerprintbewijs vóór de oorspronkelijke native decryptie. Gelijke bytes zijn geen identiteit of toestemming.</p></article>
<article><div class="step">03 / HUMAN FOLLOW-UP</div><h3>Bewaar en hervat menselijke opvolging</h3>
<p>Gebruik de originele brongebonden, menselijk ingevulde review en optionele encryptie van het
HUMAN-journal. Geen conclusie wordt automatisch een geverifieerde technische fix.</p></article>
</div></section>
<section><div class="section-head"><h2>Offline modules</h2>
<p>Alle links openen lokaal — niets wordt geïnstalleerd of verstuurd.</p></div>
<div class="modules">""" + cards + """</div></section>
<section><h2>Oorspronkelijke guides</h2><div class="docs"><ul>""" + links + """</ul>
<p>Voor native software-only installatie op eigen geautoriseerde Linux: maak een
privé 0700 bovenliggende map, gebruik een NIEUWE doelmap en raadpleeg
de volledige gids. Gebruik nooit originele clientdata in een software-only ZIP.</p></div></section>
</main><footer class="footer">
© LightUp · PRIVATE HUMAN-only offline software. Originele bronnen, werkelijke ontvangeridentiteit,
losstaande cliënt/operator consent inclusief intrekking op actietijd, onafhankelijke security/privacy/crypto-
beoordeling en expliciete HUMAN GO zijn niet door deze interface bewezen.
Deze pagina gebruikt geen scripts, cookies, opslag, externe lettertypen, netwerk of tracking.
</footer></div></body></html>""").encode("utf-8")

if __name__ == "__main__":
    import sys
    sys.stdout.buffer.write(render(standalone=True))
