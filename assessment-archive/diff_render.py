"""Static no-script source delta dashboard over already-validated private manifests."""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
from html import escape
from archive import STYLE


def render(delta, aggregate_only):
    policy = b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    rows = "".join(
        f"<tr><th scope='row'>{escape(item['source_class'])}</th>"
        f"<td>{item['previous']}</td><td>{item['current']}</td>"
        f"<td>{item['delta']:+}</td></tr>"
        for item in delta["source_class_shifts"]
    )
    private = ""
    if not aggregate_only:
        private = (
            "<section><h2>Private source byte fingerprints</h2>"
            "<p>Source membership, NOT a verdict or verification.</p>"
            "<h3>New bytes</h3><ol>"
            + "".join(f"<li><code>{digest}</code></li>" for digest in delta["new_private_sha256"])
            + "</ol><h3>Not in current selection</h3><ol>"
            + "".join(f"<li><code>{digest}</code></li>" for digest in delta["absent_private_sha256"])
            + "</ol></section>"
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'; style-src 'sha256-{policy}'">
<title>LightUp — Offline Archive Changes</title><style>{STYLE}</style></head><body>
<header class="hero"><div class="kicker">LIGHTUP / LAB SOURCE ARCHIVE / OFFLINE</div>
<h1>Archive changes</h1>
<p>Owner-selected archive snapshots. Files are not scanned and no vulnerability changes are inferred.</p>
<div class="state">INCUBATE M3/M7 · PLAN/LAB ONLY · {escape(delta['status'])} · NO GO</div></header>
<main><div class="card"><div class="kicker">Added</div><div class="big">{delta['added_count']}</div></div>
<div class="card"><div class="kicker">Absent</div><div class="big">{delta['absent_count']}</div></div>
<div class="card"><div class="kicker">Unchanged</div><div class="big">{delta['unchanged_count']}</div></div></main>
<section><h2>Source classes</h2><p>Previously {delta['previous_source_count']} selections;
now {delta['current_source_count']}. These are unsigned claims, not evidence of remediation.</p>
<table><thead><tr><th>Source class</th><th>Previous</th><th>Current</th><th>Change</th></tr></thead>
<tbody>{rows}</tbody></table></section>{private}
<section><aside><h2>Human review required</h2><p>Absent source does NOT mean fixed finding.
Matching fingerprints do NOT prove authenticity, consent or authorization.
Original security/privacy, source owner, CI and genuine operator/client gates are unchanged.</p></aside></section>
<footer><p>Fully local · printable · no network, JavaScript, telemetry or browser storage.</p></footer>
</body></html>""".encode("utf-8")
