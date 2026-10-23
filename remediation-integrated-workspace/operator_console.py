#!/usr/bin/env python3
"""Build the completely local PRIVATE HUMAN operator command composer.

Browser output ONLY prepares operator-visible commands. No network, shell,
filesystem access or source admission occurs inside the browser.
"""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path

from private_desk import OPERATIONS, WARNING

HERE = Path(__file__).resolve().parent
CATEGORIES = {
    "owner": "Source owner",
    "owner-package": "Source owner",
    "owner-encrypted": "Source owner",
    "owner-encrypted-receipt": "Source owner",
    "recipient": "Recipient",
    "archives": "Recipient",
    "pack": "Recipient",
    "unpack": "Recipient",
    "review": "HUMAN review",
    "continue-review": "HUMAN review",
    "brief": "HUMAN review",
    "seal-journal": "HUMAN continuity",
    "open-journal": "HUMAN continuity",
    "rekey-journal": "HUMAN continuity",
    "encrypt-cockpit": "Private transfer",
    "decrypt-cockpit": "Private transfer",
    "pack-review": "Private transfer",
    "receive-review": "Private transfer",
    "fingerprint-create": "Byte comparison",
    "fingerprint-compare": "Byte comparison",
    "install": "Software only",
    "inspect-archive": "Software only",
    "receive-software": "Software only",
    "inspect-software": "Software only",
    "inspect-checkout": "Software only",
    "reopen-passport": "Software only",
}

def render() -> bytes:
    css = (HERE / "operator_ui.css").read_bytes()
    js = (HERE / "operator_ui.js").read_bytes()
    fingerprint_js = (HERE / "fingerprint_ui.js").read_bytes()
    operations = [{
        "name": name,
        "purpose": purpose,
        "category": CATEGORIES[name],
        "fields": [{
            "flag": flag, "label": label, "repeat": repeat, "required": required
        } for flag, label, repeat, required in fields],
    } for name, (_, _, fields, purpose) in OPERATIONS.items()]
    source = json.dumps(operations, ensure_ascii=True, separators=(",", ":"))
    # JSON is only data (not executable); forbid HTML/script terminators.
    source = source.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    css_text = css.decode("utf-8")
    js_text = js.decode("utf-8")
    fingerprint_text = fingerprint_js.decode("utf-8")
    css_hash = "sha256-" + __import__("base64").b64encode(hashlib.sha256(css).digest()).decode("ascii")
    js_hash = "sha256-" + __import__("base64").b64encode(hashlib.sha256(js).digest()).decode("ascii")
    fingerprint_hash = "sha256-" + __import__("base64").b64encode(hashlib.sha256(fingerprint_js).digest()).decode("ascii")
    policy = ("default-src 'none'; script-src '" + js_hash +
              "' '" + fingerprint_hash + "'; style-src '" + css_hash +
              "'; connect-src 'none'; img-src 'none'; font-src 'none'; "
              "object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'")
    return ("""<!doctype html>
<html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content='""" + html.escape(policy, quote=True) + """'>
<title>LightUp — PRIVATE operatorstudio</title>
<style>""" + css_text + """</style></head>
<body><main class="shell">
<header><div class="eyebrow">LIGHTUP / PRIVATE OPERATOR DESK</div>
<h1>Offline HUMAN werkruimte</h1>
<p class="lead">Van echte oorspronkelijke evidence naar bronvrije HUMAN-opvolging.
Kies een bestaande native workflow en bereid lokaal het bijbehorende terminalcommando voor.</p>
<div class="state"><span class="dot"></span> INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD</div>
</header>
<div class="notice" role="note"><strong>Geen uitvoerings- of vrijgavebevoegdheid.</strong>
De browser leest geen bestanden en voert geen commando's uit.
Alleen de bestaande native Python-tools kunnen na expliciete operatoractie
bronbestanden controleren en nieuwe private lokale output publiceren.
Versleuteling en checksums bewijzen geen identiteit, echte toestemming of fix.</div>
<section class="journey" aria-label="Gids voor echte PRIVATE bronvrije overdracht">
<h2>Van oorspronkelijke evidence naar menselijke opvolging</h2>
<p>Drie onafhankelijke lokale HUMAN-stappen. De pakketoverdracht tussen machines
gebeurt uitsluitend na afzonderlijke echte toestemming, nooit automatisch.</p>
<div class="journey-grid">
<article><span>01 · ORIGINAL OWNER</span><h3>Maak versleuteld pakket en eigen fingerprintbewijs</h3>
<p>Oorspronkelijke privé-evidence blijft bij de bronhouder; alleen de afzonderlijke native
bronvrije Cockpit wordt lokaal versleuteld naar een nieuw .luhx-bestand plus apart privé, niet-ondertekend JSON-fingerprintbewijs.</p>
<button type="button" data-workflow="owner-encrypted-receipt">Bereid originele eigenaarsoverdracht voor</button></article>
<article><span>02 · PRIVATE RECIPIENT</span><h3>Open de werkelijk ontvangen overdracht</h3>
<p>Gebruik uitsluitend het apart geautoriseerd ontvangen .luhx-bestand én bijbehorend privé unsigned .json-fingerprintbewijs; controleer bytes vóór decryptie.
De ontvanger maakt lokaal een PRIVATE HUMAN-werkruimte, geen scan of fix.</p>
<button type="button" data-workflow="archives">Bereid ontvangst en HUMAN-review voor</button></article>
<article><span>03 · HUMAN FOLLOW-UP</span><h3>Bewaar menselijke antwoorden versleuteld</h3>
<p>Na handmatige brongebonden beoordeling kunnen bestaande echte HUMAN-journalantwoorden
lokaal worden verzegeld. Bronidentiteit, toestemming en retest blijven extern.</p>
<button type="button" data-workflow="seal-journal">Bereid versleuteld HUMAN-journal voor</button></article>
</div></section>
<section class="fingerprint" aria-label="Offline bytefingerprint zonder upload">
<h2>PRIVATE ontvangen pakket lokaal vergelijken</h2>
<p>Bereken SHA-256 van de <strong>exacte lokale bytes</strong> van bronvrije
overdrachtspakketten. Gelijke fingerprints tonen uitsluitend byte-identiteit,
NOOIT echte bronherkomst, afzender, consent of bewezen fixes.</p>
<label for="packet-files">Kies lokale bronvrije .luhx / .luhz / .luhp bestanden en eventuele ontvangen kopieën</label>
<input type="file" id="packet-files" multiple accept=".luhx,.luhz,.luhp">
<div class="tools">
<button type="button" id="packet-analyze">Bereken lokaal SHA-256</button>
<button type="button" id="packet-export" disabled>Download PRIVATE unsigned hashreceipt</button>
<button type="button" id="packet-clear" class="secondary">Wis fingerprints</button>
</div>
<p id="packet-message" role="status" aria-live="polite">Alle bytes blijven lokaal;
maximaal acht bestanden, 20 MiB per bestand en 64 MiB samen.</p>
<div id="packet-result" class="fingerprint-result"></div>
<div class="fingerprint-match">
<label for="packet-expected">Ontvangen oorspronkelijke SHA-256, optioneel
(alleen na apart geautoriseerde uitwisseling)</label>
<input id="packet-expected" type="text" inputmode="latin" spellcheck="false"
autocomplete="off" maxlength="64" placeholder="64 kleine hexadecimale tekens">
<label for="packet-expected-size">Verwachte oorspronkelijke grootte in bytes, optioneel</label>
<input id="packet-expected-size" type="text" inputmode="numeric"
autocomplete="off" maxlength="12" placeholder="Bijvoorbeeld 102400">
<p id="packet-expected-result" aria-live="polite" role="status"></p>
<small>Vergelijk met het afzonderlijk ontvangen bronhouder-fingerprint.
Dit is een ONDERTEKEND: nee / REVIEW_ONLY hulpmiddel; SHA op zichzelf
bewijst nooit de identiteit van de bronhouder of toestemming.</small>
</div>

<p id="packet-comparison" class="fingerprint-comparison" aria-live="polite"></p>
<small>Een PRIVATE checksum is niet ondertekend; wie het bronpakket en
de fingerprint beheerst, kan beide vervangen. Native ontvangst, afzonderlijke
actuele toestemming en onafhankelijke securityreview blijven verplicht.</small>
</section>
<div class="layout">
<aside class="nav"><h2>Werkstappen</h2>
<p>Kies een opdracht. Alles blijft in browsergeheugen; er is geen netwerk,
backend, browseropslag of automatische upload.</p>
<label for="category">Categorie</label><select id="category"></select>
<label for="search">Vind opdracht</label><input id="search" type="search" maxlength="90"
placeholder="Bijv. encryptie, HUMAN, archief" autocomplete="off">
<div id="actions" class="action-list" role="group" aria-label="Native workflows"></div>
</aside>
<section class="content">
<div class="step">01 / VOORBEREIDEN</div>
<h2 id="chosen-title">Kies een native workflow</h2>
<p id="purpose" class="muted">Alleen oorspronkelijke bronpakketten en expliciete HUMAN-selecties.</p>
<div id="fields"></div>
<p id="special" class="hint"></p>
<div class="step">02 / PRIVÉCOMMANDo</div>
<p>Dit commando is uitsluitend een <strong>lokale voorbereiding</strong>.
Plak het pas na eigen controle in een geautoriseerde, privé Linux-terminal
in de root van de geïnstalleerde offline suite.
Nieuwe outputpaden mogen nog niet bestaan; de bovenliggende directory moet
van de operator zijn en uitsluitend voor die operator toegankelijk.</p>
<textarea id="command" aria-label="Opdracht voor privéterminal" rows="5"
readonly spellcheck="false" placeholder="Vul eerst de benodigde absolute paden in."></textarea>
<div class="tools">
<button type="button" id="copy" disabled>Kopieer terminalcommando</button>
<button type="button" id="reset" class="secondary">Wis ingevoerde paden</button>
</div>
<p id="message" class="message" aria-live="polite"></p>
<div class="step">03 / CONTROLEREN</div>
<div class="checks"><p>Controleer apart de oorspronkelijke bestanden,
bronhouder, gevraagde HUMAN handeling en echte toestemming.
Gebruik geen bestaande outputbestemming.
Voor .luhz geldt: <strong>niet versleuteld, niet ondertekend</strong>.
Voor .luhx / .luhj: wachtwoord wordt uitsluitend door de native CLI in de terminal gevraagd
en versleuteling authenticeert geen verzender of klant.</p>
<p>Native uitvoer REVIEW_ONLY of HOLD is nooit een scanbevel, grant,
retestbewijs, herstelbewijs of vrijgave naar productie.</p></div>
</section></div>
<footer>Geen scripts of paden gedeeld met externe diensten. Geen browsergeschiedenis
van bronbestanden, geen netwerk, geen accountlogin, geen client-authority.
De originele offline startpagina blijft beschikbaar via de vorige browserpagina.</footer>
<script type="application/json" id="operations">""" + source + """</script>
<script>""" + js_text + """</script><script>""" + fingerprint_text + """</script></main></body></html>
""").encode("utf-8")

if __name__ == "__main__":
    import sys
    sys.stdout.buffer.write(render())
