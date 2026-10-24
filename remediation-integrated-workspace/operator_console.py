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
    "owner": "Bronhouder",
    "owner-package": "Bronhouder",
    "owner-encrypted": "Bronhouder",
    "owner-encrypted-receipt": "Bronhouder",
    "recipient": "Ontvangst",
    "archives": "Ontvangst",
    "pack": "Ontvangst",
    "unpack": "Ontvangst",
    "review": "Beoordeling",
    "continue-review": "Beoordeling",
    "brief": "Beoordeling",
    "seal-journal": "Notities",
    "open-journal": "Notities",
    "rekey-journal": "Notities",
    "encrypt-cockpit": "Privéoverdracht",
    "decrypt-cockpit": "Privéoverdracht",
    "pack-review": "Privéoverdracht",
    "receive-review": "Privéoverdracht",
    "fingerprint-create": "Bestandscontrole",
    "fingerprint-compare": "Bestandscontrole",
    "install": "Offline software",
    "inspect-archive": "Offline software",
    "fingerprint-archive": "Offline software",
    "receive-software": "Offline software",
    "inspect-software": "Offline software",
    "inspect-checkout": "Offline software",
    "reopen-passport": "Offline software",
}


# Operator-facing labels only. CLI operation identifiers and contracts stay fixed.
ACTION_LABELS = {
    "owner": "Start brononderzoek",
    "owner-package": "Maak offline pakket",
    "owner-encrypted": "Versleutel overdracht",
    "owner-encrypted-receipt": "Maak versleutelde overdracht",
    "recipient": "Open ontvangen dossiers",
    "archives": "Controleer en open pakket",
    "pack": "Pak dossier in",
    "unpack": "Pak dossier uit",
    "review": "Start beoordeling",
    "continue-review": "Hervat beoordeling",
    "brief": "Maak samenvatting",
    "seal-journal": "Beveilig notities",
    "open-journal": "Open beveiligde notities",
    "rekey-journal": "Wijzig notitiesleutel",
    "encrypt-cockpit": "Versleutel dossier",
    "decrypt-cockpit": "Ontsleutel dossier",
    "pack-review": "Verpak beoordeling",
    "receive-review": "Ontvang beoordeling",
    "fingerprint-create": "Maak pakketvingerafdruk",
    "fingerprint-compare": "Controleer pakketvingerafdruk",
    "install": "Maak offline werkruimte",
    "inspect-archive": "Controleer softwarepakket",
    "fingerprint-archive": "Maak softwarechecksum",
    "receive-software": "Ontvang software",
    "inspect-software": "Controleer installatie",
    "inspect-checkout": "Vergelijk met broncode",
    "reopen-passport": "Open integriteitsrapport"
}

# Brief Dutch UI copy only; native CLI descriptions and review gates are unchanged.
ACTION_PURPOSES = {
    "owner": "Bereid de bron voor; originele gegevens blijven lokaal.",
    "owner-package": "Maak een apart pakket zonder originele bewijsbestanden.",
    "owner-encrypted": "Versleutel een pakket lokaal, zonder het te verzenden.",
    "owner-encrypted-receipt": "Maak een versleuteld pakket met apart controlebewijs.",
    "recipient": "Open ontvangen dossiers voor menselijke beoordeling.",
    "archives": "Controleer en open een werkelijk ontvangen pakket.",
    "pack": "Maak een onversleuteld pakket. Deel het niet zonder toestemming.",
    "unpack": "Controleer en open een lokaal ontvangen pakket.",
    "review": "Beoordeel één dossier, zonder aannames over eerdere momenten.",
    "continue-review": "Ga verder met opgeslagen antwoorden uit hetzelfde dossier.",
    "brief": "Maak een leesbare samenvatting van menselijke notities.",
    "seal-journal": "Versleutel je notities met een wachtwoord.",
    "open-journal": "Open versleutelde notities in een privémap.",
    "rekey-journal": "Wijzig het wachtwoord van versleutelde notities.",
    "encrypt-cockpit": "Versleutel een lokaal dossier; niets wordt verstuurd.",
    "decrypt-cockpit": "Open een lokaal versleuteld dossier.",
    "pack-review": "Verpak een beoordeling voor afzonderlijk toegestane overdracht.",
    "receive-review": "Controleer een ontvangen beoordeling voordat je die opent.",
    "fingerprint-create": "Maak een privécontrolebewijs van exacte pakketbytes.",
    "fingerprint-compare": "Vergelijk pakketbytes met een apart controlebewijs.",
    "install": "Maak een privéwerkruimte met de bestaande software.",
    "inspect-archive": "Controleer een software-ZIP zonder installatie of wijzigingen.",
    "fingerprint-archive": "Maak een afzonderlijke privéchecksum voor een software-ZIP.",
    "receive-software": "Ontvang een gecontroleerde software-ZIP in een nieuwe privémap.",
    "inspect-software": "Controleer bestanden van een bestaande installatie.",
    "inspect-checkout": "Vergelijk de installatie met broncode en maak een rapport.",
    "reopen-passport": "Open het bestaande integriteitsrapport opnieuw ter controle.",
}

def render() -> bytes:
    # The offline browser source is part of the trusted local checkout.
    # Do not follow attacker-swapped source symlinks via Path.read_bytes();
    # use the same descriptor-pinned, single-link source admission used for
    # the original native ZIP and installed software integrity checks.
    from install import read_checkout_source
    css = read_checkout_source(HERE / "operator_ui.css")
    js = read_checkout_source(HERE / "operator_ui.js")
    fingerprint_js = read_checkout_source(HERE / "fingerprint_ui.js")
    if set(ACTION_LABELS) != set(OPERATIONS) or set(ACTION_PURPOSES) != set(OPERATIONS):
        raise ValueError("Offline Dutch operator copy must cover exactly the native actions")
    operations = [{
        "name": name,
        "label": ACTION_LABELS[name],
        "purpose": ACTION_PURPOSES[name],
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
<header><div class="eyebrow">LIGHTUP / OFFLINE WERKPLEK</div>
<h1>Offline werkruimte</h1>
<p class="lead">Bereid een veilige opdracht voor, of vergelijk zelfgekozen bestanden lokaal.
Er gebeurt niets automatisch en er wordt niets verstuurd.</p>
<div class="state"><span class="dot"></span> INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD</div>
</header>
<div class="notice" role="note"><strong>Alleen lokale controle. Geen toestemming of vrijgave.</strong>
De browser leest uitsluitend bestanden die je zelf selecteert voor een lokale
SHA-256-vergelijking. Er wordt niets geüpload of automatisch uitgevoerd.
Nieuwe privébestanden worden alleen door de native Python-tools gemaakt na
jouw expliciete opdracht. Een checksum bewijst geen afzender, toestemming of herstel.</div>
<details class="extra-tools">
<summary>Andere offline hulpmiddelen <span>Overdracht, pakketten en SHA-256 vergelijken</span></summary>
<section class="journey" aria-label="Gids voor echte PRIVATE bronvrije overdracht">
<h2>Drie stappen, van pakket tot beoordeling</h2>
<p>Drie onafhankelijke lokale HUMAN-stappen. De pakketoverdracht tussen machines
gebeurt uitsluitend na afzonderlijke echte toestemming, nooit automatisch.</p>
<div class="journey-grid">
<article><span>01 · BRONHOUDER</span><h3>Maak versleuteld pakket en eigen fingerprintbewijs</h3>
<p>Oorspronkelijke privé-evidence blijft bij de bronhouder; alleen de afzonderlijke native
bronvrije Cockpit wordt lokaal versleuteld naar een nieuw .luhx-bestand plus apart privé, niet-ondertekend JSON-fingerprintbewijs.</p>
<button type="button" data-workflow="owner-encrypted-receipt">Bereid originele eigenaarsoverdracht voor</button></article>
<article><span>02 · ONTVANGER</span><h3>Open de werkelijk ontvangen overdracht</h3>
<p>Gebruik uitsluitend het apart geautoriseerd ontvangen .luhx-bestand én bijbehorend privé unsigned .json-fingerprintbewijs; controleer bytes vóór decryptie.
De ontvanger maakt lokaal een PRIVATE HUMAN-werkruimte, geen scan of fix.</p>
<button type="button" data-workflow="archives">Bereid ontvangst en HUMAN-review voor</button></article>
<article><span>03 · BEOORDELAAR</span><h3>Bewaar menselijke antwoorden versleuteld</h3>
<p>Na handmatige brongebonden beoordeling kunnen bestaande echte HUMAN-journalantwoorden
lokaal worden verzegeld. Bronidentiteit, toestemming en retest blijven extern.</p>
<button type="button" data-workflow="seal-journal">Bereid versleuteld HUMAN-journal voor</button></article>
</div></section>
<section class="fingerprint" aria-label="Offline bytefingerprint zonder upload">
<h2>PRIVATE ontvangen pakket lokaal vergelijken</h2>
<p>Bereken SHA-256 van de <strong>exacte lokale bytes</strong> van bronvrije
overdrachtspakketten. Gelijke fingerprints tonen uitsluitend byte-identiteit,
NOOIT echte bronherkomst, afzender, consent of bewezen fixes.</p>
<label for="packet-files">Kies lokale bronvrije pakketten of LightUps software-only.zip</label>
<input type="file" id="packet-files" multiple accept=".luhx,.luhz,.luhp,.zip">
<div class="tools">
<button type="button" id="packet-analyze">Bereken lokaal SHA-256</button>
<button type="button" id="packet-export" disabled>Download privé JSON-controleoverzicht</button>
<button type="button" id="packet-export-software" disabled>Download softwarechecksum (.sha256)</button>
<button type="button" id="packet-clear" class="secondary">Wis fingerprints</button>
</div>
<p id="packet-message" role="status" aria-live="polite">Alle bytes blijven lokaal;
maximaal acht bestanden: 20 MiB per bronvrij pakket, 15 MB per software-only.zip en 64 MiB samen.</p>
<div id="packet-result" class="fingerprint-result"></div>
<div class="fingerprint-match">
<label for="packet-expected-file">Afzonderlijk ontvangen .sha256-bestand, optioneel</label>
<input type="file" id="packet-expected-file" accept=".sha256">
<small>Maximaal 65 bytes; alleen lokaal vergelijken, nooit als afzenderbewijs.</small>
<label for="packet-expected">Ontvangen oorspronkelijke SHA-256, optioneel
(alleen na apart geautoriseerde uitwisseling)</label>
<input id="packet-expected" type="text" inputmode="latin" spellcheck="false"
autocomplete="off" maxlength="64" placeholder="64 kleine hexadecimale tekens">
<label for="packet-expected-size">Verwachte oorspronkelijke grootte in bytes, optioneel</label>
<input id="packet-expected-size" type="text" inputmode="numeric"
autocomplete="off" maxlength="12" placeholder="Bijvoorbeeld 102400">
<p id="packet-expected-result" aria-live="polite" role="status"></p>
<small>Vergelijk met het afzonderlijk ontvangen controlebestand.
Dit bewijs is niet digitaal ondertekend. Een gelijke SHA-256 bewijst
geen afzender of toestemming.</small>
</div>

<p id="packet-comparison" class="fingerprint-comparison" aria-live="polite"></p>
<small>Een PRIVATE checksum is niet ondertekend; wie het bronpakket en
de fingerprint beheerst, kan beide vervangen. Alleen de vaste naam
<strong>software-only.zip</strong> wordt als softwarearchief gehasht;
willekeurige ZIP-bestanden en originele klantevidence blijven geweigerd.
SHA-256 vergelijken is GEEN softwaretoelating: gebruik daarvoor native
<code>inspect-archive</code>. Afzonderlijke actuele toestemming en
onafhankelijke securityreview blijven verplicht.</small>
</section>
<section class="fingerprint" aria-label="Offline software ZIP checksum vergelijken">
<h2>Ontvangen PRIVATE softwarepakket controleren</h2>
<p>Vergelijk uitsluitend het originele bestand met de exacte naam
<code>software-only.zip</code> met een apart ontvangen
<code>.sha256</code>-bestand. Een anders genoemd ZIP-bestand wordt geweigerd,
zelfs wanneer iemand een bijpassende checksum heeft. Deze pagina leest
uitsluitend twee gekozen lokale bestanden in het geheugen. Maximaal 15.000.000 bytes
voor de ZIP en exact 65 bytes voor de checksum (64 kleine hextekens en LF).</p>
<label for="software-zip">Originele ontvangen software-ZIP</label>
<input id="software-zip" type="file" accept=".zip">
<label for="software-sha256">Apart ontvangen originele PRIVATE .sha256-checksum</label>
<input id="software-sha256" type="file" accept=".sha256">
<div class="tools">
<button id="software-compare" type="button">Vergelijk exacte lokale bytes</button>
<button id="software-clear" type="button" class="secondary">Wis resultaat</button>
</div>
<p id="software-result" role="status" aria-live="polite">
Er is nog geen softwarepakket gelezen of verzonden.</p>
<small>Gelijke SHA-256 bewijst geen afzender of toestemming. Dit is alleen
een vroege lokale bytesvergelijking. Voer daarna de native
<code>inspect-archive --expected-sha256-file</code> uit voor volledige
ZIP-structuur-, bron- en autorisatiegrenzen. Geen installatie, upload,
browseropslag, toestemming of automatische actie.</small>
</section>
</details>
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
<div class="step">02 / PRIVÉCOMMANDO</div>
<p>Dit commando is uitsluitend een <strong>lokale voorbereiding</strong>.
Plak het pas na eigen controle in een geautoriseerde, privé Linux-terminal
in de root van de geïnstalleerde offline suite.
Nieuwe outputpaden mogen nog niet bestaan; de bovenliggende directory moet
van de operator zijn en uitsluitend voor die operator toegankelijk.</p>
<textarea id="command" aria-label="Opdracht voor privéterminal" rows="5"
readonly spellcheck="false" placeholder="Vul eerst de benodigde absolute paden in."></textarea>
<div class="tools">
<button type="button" id="copy" disabled>Kopieer terminalcommando</button>
<button type="button" id="prepare-receive" class="secondary" hidden disabled>Vul ontvangstcommando in</button>
<button type="button" id="prepare-checksum" class="secondary" hidden disabled>Vul checksumopdracht in</button>
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
