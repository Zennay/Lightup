#!/usr/bin/env python3
"""Source-bound, non-authorizing PRIVATE HUMAN retention-plan comparison.

Reads only locally exported browser HUMAN plans, never original assessment assets.
No network, subprocess, delete, authorization or test functionality.
"""
from __future__ import annotations

import argparse
from datetime import date
from html import escape
import json
import os
from pathlib import Path
import re
import stat
import tempfile

MAX_FILES = 12
MAX_RECEIPT_BYTES = 131072
SHA = re.compile(r"^[0-9a-f]{64}$")
UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f]")
STAGES = {
    "needs_review": "Nog beoordelen",
    "retain": "Behouden (voorstel)",
    "quarantine": "Afzonderen (voorstel)",
    "propose_delete": "Verwijdering voorstellen, nooit automatisch",
}
CLASSIFICATIONS = {"unknown":"Onbekend HUMAN", "internal":"Intern HUMAN",
                   "confidential":"Vertrouwelijk HUMAN", "restricted":"Beperkt gevoelig HUMAN"}
HOLD_FLAGS = {"unknown":"Niet beoordeeld HUMAN",
              "human_claim_active":"HUMAN meldt actieve bewaarbeperking",
              "human_declared_clear":"HUMAN meldt geen bekende beperking (NIET onafhankelijk geverifieerd)"}
HUMAN_FIELDS = ("alias","status","review_date","action","custodian","classification","hold_flag")
V2_FIELDS = ("sha256","bytes","alias","status","review_date","action",
             "custodian","classification","hold_flag")
AUTHORITY = {
    "authorizes_scan": False,
    "authorizes_delete": False,
    "verifies_finding": False,
    "verifies_remediation": False,
    "proves_consent": False,
    "authenticates_source": False,
}


class Hold(Exception):
    """Fail-closed acceptance failure; no output is published."""


def no_duplicates(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Hold("duplicate JSON member")
        result[key] = value
    return result


def no_constant(value):
    raise Hold("non-finite JSON number")


def exact_dict(value, keys):
    return type(value) is dict and set(value) == set(keys)


def human(value, length):
    return type(value) is str and len(value) <= length and not UNSAFE.search(value)


def review_date(value):
    if value == "":
        return True
    if type(value) is not str or not re.fullmatch(r"20\d\d-\d\d-\d\d", value):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def read_receipt(path):
    source = Path(path)
    try:
        if not stat.S_ISREG(source.lstat().st_mode):
            raise Hold("receipt is not a regular file (links rejected)")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(source, flags)
        try:
            descriptor = os.fstat(fd)
            if not stat.S_ISREG(descriptor.st_mode) or descriptor.st_size > MAX_RECEIPT_BYTES:
                raise Hold("receipt is not regular or exceeds 128 KiB")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_RECEIPT_BYTES + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise Hold("could not securely read a private receipt") from exc
    return parse_receipt_bytes(raw)


def parse_receipt_bytes(raw):
    """Validate the unchanged original browser source-bound HUMAN receipt in memory.

    Also used when original canonical plaintext comes from authenticated local
    AES-GCM decryption. No plaintext is written by this function.
    """
    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise Hold("empty or oversized private receipt")
    try:
        document = json.loads(raw.decode("utf-8", "strict"),
                              object_pairs_hook=no_duplicates,
                              parse_constant=no_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise Hold("invalid UTF-8 or JSON") from exc
    if (
        not exact_dict(document, ("kind", "version", "authority", "rows"))
        or document["kind"] != "lightup.private.assessment.retention.plan"
        or type(document["version"]) is not int or document["version"] not in (1, 2)
        or not exact_dict(document["authority"], AUTHORITY)
        or any(document["authority"][field] is not False for field in AUTHORITY)
    ):
        raise Hold("unknown receipt or false-authority contract")
    rows = document["rows"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_FILES:
        raise Hold("invalid receipt row cardinality")
    result = {}
    for item in rows:
        if (
            not exact_dict(item, V2_FIELDS if document["version"] == 2
                           else ("sha256", "bytes", "alias", "status", "review_date", "action"))
            or type(item["sha256"]) is not str or not SHA.fullmatch(item["sha256"])
            or type(item["bytes"]) is not int or not 1 <= item["bytes"] <= 8 * 1024 * 1024
            or not human(item["alias"], 80)
            or type(item["status"]) is not str or item["status"] not in STAGES
            or not review_date(item["review_date"])
            or not human(item["action"], 400)
            or (item["status"] == "propose_delete" and not item["action"].strip())
            or item["sha256"] in result
        ):
            raise Hold("invalid, ambiguous or repeated source/HUMAN row")
        if document["version"] == 2:
            if (
                not human(item["custodian"], 80)
                or type(item["classification"]) is not str
                or item["classification"] not in CLASSIFICATIONS
                or type(item["hold_flag"]) is not str
                or item["hold_flag"] not in HOLD_FLAGS
                or (item["status"] == "propose_delete" and (
                    not item["custodian"].strip()
                    or item["hold_flag"] != "human_declared_clear"))
            ):
                raise Hold("missing HUMAN custodian, classification or hold declaration")
            result[item["sha256"]] = item
        else:
            # v1 had no field for custody; unknown can never mean cleared.
            result[item["sha256"]] = {**item,"custodian":"",
                                     "classification":"unknown","hold_flag":"unknown"}
    if sum(row["bytes"] for row in result.values()) > 64 * 1024 * 1024:
        raise Hold("receipt total exceeds original 64 MiB admission cap")
    return result


def private_html(sequence):
    baseline = {(key, row["bytes"]) for key, row in sequence[0].items()}
    for plan in sequence[1:]:
        if {(key, row["bytes"]) for key, row in plan.items()} != baseline:
            raise Hold("original source SHA/size membership drift across plans")
    ids = sorted(sequence[0])
    heads = "".join("<th>HUMAN plan " + str(i + 1) + "</th>"
                    for i in range(len(sequence)))
    bodies = []
    changed_by_pair = [0] * (len(sequence) - 1)
    for key in ids:
        start = sequence[0][key]
        cols = [
            "<td><strong>" + escape(start["alias"]) + "</strong><small>"
            + escape(key[:16]) + "… · " + str(start["bytes"]) + " bytes</small></td>"
        ]
        for index, plan in enumerate(sequence):
            row = plan[key]
            if index:
                prior = sequence[index - 1][key]
                changed = any(row[field] != prior[field]
                              for field in HUMAN_FIELDS)
                if changed:
                    changed_by_pair[index - 1] += 1
            else:
                changed = False
            shown = "<strong>" + escape(STAGES[row["status"]]) + "</strong>"
            if row["review_date"]:
                shown += "<small>Voorlopige review: " + escape(row["review_date"]) + "</small>"
            if row["action"]:
                shown += "<span class='note'>" + escape(row["action"]) + "</span>"
            if row["alias"] != start["alias"]:
                shown += "<small>HUMAN alias: " + escape(row["alias"]) + "</small>"
            shown += "<small>Dossierhouder HUMAN: " + escape(row["custodian"] or "NIET TOEGEWEZEN") + "</small>"
            shown += "<small>Gevoeligheid HUMAN: " + escape(CLASSIFICATIONS[row["classification"]]) + "</small>"
            shown += "<small>Bewaarbeperking HUMAN: " + escape(HOLD_FLAGS[row["hold_flag"]]) + "</small>"
            cols.append("<td class='" + ("changed" if changed else "") + "'>" + shown + "</td>")
        bodies.append("<tr>" + "".join(cols) + "</tr>")
    diffs = "".join("<li>Plan " + str(i + 1) + " → " + str(i + 2)
                    + ": " + str(count) + " van " + str(len(ids))
                    + " bronrijen met gewijzigde HUMAN-velden</li>"
                    for i, count in enumerate(changed_by_pair))
    steps = []
    for i, plan in enumerate(sequence):
        numbers = ", ".join(escape(STAGES[state]) + ": "
                            + str(sum(row["status"] == state for row in plan.values()))
                            for state in STAGES)
        steps.append("<li><strong>HUMAN plan " + str(i + 1) + "</strong> — " + numbers + "</li>")
    return """<!doctype html><html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN retentiehistorie</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1250px;margin:30px auto;padding:0 15px;color:#172130}h1{font-size:2.1rem}
.banner{border:2px solid #82461b;background:#fff4dd;padding:16px;border-radius:9px}table{border-collapse:collapse;width:100%;min-width:750px}
td,th{border:1px solid #b5bec9;text-align:left;padding:9px;vertical-align:top}th{background:#e8edf2}
.changed{background:#fff3dc}small,.note{display:block;font-size:.82rem;color:#445367}
.note{white-space:pre-wrap;overflow-wrap:anywhere;margin-top:8px}div.scroll{overflow-x:auto}
@media print{body{max-width:none;margin:0;font-size:10px}table{min-width:0}td,th{padding:4px}.banner{background:white}}
</style></head><body>
<h1>PRIVATE · oorspronkelijke bestandsgebonden HUMAN retentiehistorie</h1>
<p class="banner"><strong>INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</strong>
Dit ongetekende rapport beschrijft uitsluitend <em>HUMAN voorstellen</em> uit lokaal aangeleverde plannen.
Geen toestemming voor scan of wissen, geen geauthenticeerde producent/klant, geen werkelijke retentie- of herstelbeslissing.
De planvolgorde is door de operator gekozen; dit is <strong>geen bewezen chronologie</strong>.
Alle gegevens hieronder zijn PRIVATE. Geen bronbestand is geopend, geüpload, veranderd of gewist.</p>
<h2>Identieke oorspronkelijke byte-identiteiten</h2>
<p>""" + str(len(ids)) + " originele SHA-256 + bestandsgrootte combinaties in elk van " + str(len(sequence)) + """ HUMAN plannen;
ontbrekende, extra of gewijzigde bronnen zouden vóór rapportproductie zijn geweigerd.</p>
<h2>Overzicht per aangeleverd plan</h2><ul>""" + "".join(steps) + """</ul>
<h2>Veranderingen tussen opeenvolgende plannen</h2><ul>""" + diffs + """</ul>
<h2>Brongebonden HUMAN-matrix</h2><div class="scroll"><table><thead><tr><th>Oorspronkelijke bron (PRIVATE prefix)</th>""" + heads + """</tr></thead><tbody>""" + "".join(bodies) + """</tbody></table></div>
<p><strong>Geen broninhoud, echte bevinding, scanresultaat, grant, consensus, consent of automatische verwijdering.</strong>
Een SHA vergelijkt uitsluitend bytes. Volg aparte originele autorisatie-, consent-, privacy- en bewaartermijnbesluiten.</p>
</body></html>"""


def publish_private(output, contents):
    path = Path(output)
    parent = path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as exc:
        raise Hold("output parent is not available") from exc
    if (not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700):
        raise Hold("output must use an existing owner-owned exact mode-0700 private directory")
    if path.exists() or path.is_symlink():
        raise Hold("output exists; exclusive non-overwriting destination required")
    if isinstance(contents, str):
        try:
            raw_contents = contents.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise Hold("private output contains invalid UTF-8") from exc
    elif isinstance(contents, bytes):
        raw_contents = contents
    else:
        raise Hold("private output must be UTF-8 text or already-built bytes")
    if not raw_contents:
        raise Hold("empty private output refused")
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".lightup-private-", suffix=".pending", dir=parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw_contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # hard-link publishes complete 0600 bytes only, O_EXCL by pathname
    except OSError as exc:
        raise Hold("private output creation refused; no report published") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Read-only PRIVATE HUMAN retention timeline; no scan, deletion, consent or grant."
    )
    parser.add_argument("--output", required=True, help="New report HTML path in an existing private 0700 folder")
    parser.add_argument("plans", nargs="+", help="2–12 intentionally ordered original PRIVATE browser plan JSON files")
    args = parser.parse_args()
    if not 2 <= len(args.plans) <= MAX_FILES:
        parser.error("two to twelve existing original plans required")
    try:
        history = [read_receipt(file) for file in args.plans]
        report = private_html(history)
        publish_private(args.output, report)
    except Hold as exc:
        parser.exit(2, "HOLD: " + str(exc) + "\n")
    print("PRIVATE HUMAN timeline created (unsigned, non-authorizing, no source contents).")


if __name__ == "__main__":
    main()
