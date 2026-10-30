"""Source-free, original-position HUMAN print agenda: HOLD, not authority."""
import csv
from html import escape
from io import StringIO

NAME = "PRINT-PRIVATE-HAR-HUMAN-AGENDA.html"


def build(source_queue: bytes, rounds: int) -> bytes:
    if type(rounds) is not int or not 1 <= rounds <= 8:
        raise ValueError("HOLD: invalid operator-supplied round count")
    rows = list(csv.DictReader(StringIO(source_queue.decode("utf-8", "strict"))))
    if not 1 <= len(rows) <= 12:
        raise ValueError("HOLD: invalid bounded original roster")
    seen = set()
    sections = []
    for row in rows:
        position = int(row["original_ordinal"])
        total = int(row["action_count"])
        fields = ("withheld", "source_owner_needed", "in_progress", "pending_human")
        unfinished = sum(int(row[key]) for key in fields)
        if position in seen or not 1 <= position <= 12 or not 1 <= total <= 40 or not 0 <= unfinished <= total:
            raise ValueError("HOLD: invalid original action counts")
        seen.add(position)
        action = escape(row["manual_work_sequence"].replace("_", " "))
        sections.append(f"<section><h2>Original #{position}</h2><p><b>Manual next action:</b> {action}</p>"
                        f"<p>{total} source-minimal tasks, {unfinished} not HUMAN-marked reviewed.</p>"
                        "<p>□ Ask original source owner privately</p>"
                        "<p>□ Inspect original evidence in owner-only workroom</p>"
                        "<p>□ Record NEW manual source-bound CSV status round</p>"
                        "<p>□ Refer to independent security/privacy reviewers</p>"
                        "<p><em>Any paper checks are unsigned reminders, never approval.</em></p></section>")
    template = """<!doctype html><html lang='en'><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<meta http-equiv='Content-Security-Policy' content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';object-src 'none';base-uri 'none'">
<title>LightUp PRIVATE HUMAN HAR print agenda</title>
<style>body{font:16px/1.5 system-ui;max-width:850px;margin:auto;padding:1rem;color:#173048}
section{border:1px solid #9ba9b8;border-radius:8px;padding:1rem;margin:1rem 0;break-inside:avoid}
aside{padding:1rem;background:#fff0e5;border-left:5px solid #ad582b}
@media print{body{margin:0}section{border-color:#444}}</style>
<h1>PRIVATE HAR HUMAN original-position agenda</h1>
<aside><b>INCUBATE M3/M7 — PLAN/LAB ONLY — HOLD.</b>
Self-reported HUMAN labels and operator-supplied order are not attested.
No privacy PASS, verified finding, scan, disclosure, active consent, grant, release,
reviewer identity or security approval. This printout contains no source names,
source content, URLs, paths, hashes, client identifiers, credentials or HUMAN notes.
Do not distribute without independent human privacy review.</aside>
<p>Operator-ordered manual rounds: {rounds}. These are not risk rankings.</p>
<main>{sections}</main><footer>Re-admit original immutable source-bound packet
before using this human-only agenda. At-use consent and explicit HUMAN GO
are separately required for any eventual real operation.</footer></html>"""
    return template.replace("{rounds}", str(rounds)).replace("{sections}", "".join(sections)).encode("utf-8")
