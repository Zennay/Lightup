"""Generate a fully offline PRIVATE HUMAN decision editor without browser storage or network."""
from __future__ import annotations
import base64
import hashlib
import html

JS = r"""
"use strict";
(() => {
  const permitted = new Set([
    "NEEDS_HUMAN_REVIEW", "SOURCE_OWNER_REQUIRED", "WITHHOLD",
    "INTERNAL_REVIEW_ONLY"
  ]);
  const message = document.getElementById("message");
  const save = document.getElementById("save");
  const nodes = Array.from(document.querySelectorAll("article[data-ordinal]"));
  function csv(value) {
    return '"' + String(value).replaceAll('"', '""') + '"';
  }
  save.addEventListener("click", () => {
    const rows = [
      "source_ordinal,source_sha256_unsigned,human_stage,human_note"
    ];
    for (const node of nodes) {
      const ordinal = node.dataset.ordinal;
      const source = node.dataset.sha256;
      const stage = node.querySelector("select").value;
      let note = node.querySelector("textarea").value
          .replace(/[\r\n\x00-\x08\x0B\x0C\x0E-\x1F]/g, " ")
          .trim();
      if (!/^([0-9a-f]{64})$/.test(source) || !/^\d+$/.test(ordinal)
          || !permitted.has(stage) || note.length > 500
          || /^[\s]*[=+@-]/.test(note)) {
        message.textContent = "HOLD: invalid local HUMAN decision; nothing saved.";
        return;
      }
      rows.push([ordinal, source, stage, note].map(csv).join(","));
    }
    const data = rows.join("\r\n") + "\r\n";
    const blob = new Blob([data], {type:"text/csv;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "PRIVATE-HUMAN-decisions-completed.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    // Keep the object URL live until the browser has accepted the local save.
    setTimeout(() => URL.revokeObjectURL(url), 15000);
    message.textContent = "PRIVATE CSV prepared locally. No data was sent anywhere. " +
      "Supply this file to the explicit native finalize command. No release permission.";
  });
})();
"""


def render(sources: list[dict], decisions: list[dict] | None = None) -> bytes:
    integrity = base64.b64encode(hashlib.sha256(JS.encode("utf-8")).digest()).decode("ascii")
    cards = []
    for item in sources:
        ordinal = item["ordinal"]
        sha = item["source_sha256_unsigned"]
        assert type(ordinal) is int and 1 <= ordinal <= 12
        assert type(sha) is str and len(sha) == 64 and all(x in "0123456789abcdef" for x in sha)
        prior = decisions[ordinal - 1] if decisions else {}
        prior_stage = prior.get("human_stage", "NEEDS_HUMAN_REVIEW")
        prior_note = prior.get("human_note", "")
        assert prior_stage in {"NEEDS_HUMAN_REVIEW", "SOURCE_OWNER_REQUIRED",
                               "WITHHOLD", "INTERNAL_REVIEW_ONLY"}
        assert type(prior_note) is str and len(prior_note) <= 500
        options = (
            ("NEEDS_HUMAN_REVIEW", "Needs further HUMAN review"),
            ("SOURCE_OWNER_REQUIRED", "Ask original source owner"),
            ("WITHHOLD", "Withhold from all recipients"),
            ("INTERNAL_REVIEW_ONLY", "Internal PRIVATE review only"),
        )
        select_options = "".join(
            '<option value="' + value + '"' + (' selected' if value == prior_stage else '') +
            '>' + label + '</option>' for value, label in options
        )
        cards.append(
            f'<article data-ordinal="{ordinal}" data-sha256="{sha}">'
            f'<h2>PRIVATE original note #{ordinal}</h2>'
            f'<label for="stage-{ordinal}">HUMAN disposition (not authorization)</label>'
            f'<select id="stage-{ordinal}">' + select_options + '</select>'
            f'<label for="note-{ordinal}">PRIVATE optional HUMAN note (max 500 characters)</label>'
            f'<textarea id="note-{ordinal}" maxlength="500" rows="3" '
            'placeholder="Next HUMAN question; no secrets or personal details">'
            + html.escape(prior_note) + '</textarea></article>'
        )
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-""" + integrity + """'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'; img-src 'none'">
<title>LightUp PRIVATE HUMAN disposition studio</title>
<style>
:root{font:17px/1.5 system-ui;color:#102638;background:#eef4f7}
*{box-sizing:border-box}body{max-width:850px;margin:auto;padding:24px}
header,article,footer{background:white;border:1px solid #c8d9e8;border-radius:14px;padding:20px;margin:14px 0}
h1{font-size:clamp(1.7rem,4vw,2.6rem);margin:0 0 10px}
h2{font-size:1.13rem;margin:0 0 12px}
p{line-height:1.65}
.warning{border-left:4px solid #b3532a;padding:12px 16px;background:#fff1eb;color:#7d351b}
label{display:block;font-weight:650;margin:12px 0 5px}
select,textarea{width:100%;font:inherit;border:1px solid #8c9caa;border-radius:7px;padding:10px}
button{border:0;border-radius:10px;padding:15px 24px;font-weight:750;font:inherit;background:#125376;color:white;cursor:pointer}
button:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #d9982f;outline-offset:2px}
#message{min-height:3em;font-weight:650}
@media print{button{display:none}body{background:white;padding:0}article{break-inside:avoid}}
</style><header><p class="warning"><b>LightUp · PRIVATE HUMAN ONLY · REVIEW_ONLY/HOLD</b><br>
Local decisions are not approval, consent or permission to share.</p>
<h1>Assess credential-masked notes</h1>
<p>Use each source slot to record a strictly local HUMAN disposition.
This browser page does not contain the original raw credentials, but hashes,
notes and masked text remain confidential. The masking is pattern-based;
secret strings and personal data may remain elsewhere.</p>
<p>Nothing is uploaded or stored by the page. Save a new PRIVATE decision
CSV and provide it to the separate native finalize step. The native original
source identity and every row must match exactly or the handoff will HOLD.</p></header>
<main>""" + "".join(cards) + """</main>
<footer><button id="save" type="button">Save PRIVATE HUMAN decisions CSV</button>
<p role="status" id="message" aria-live="polite"></p>
<p class="warning">Even a completed HUMAN CSV never grants sharing authority.
All outputs remain owner-private. Original client/operator consent,
at-use revocation, source ownership, independent privacy/security
review, required CI and explicit HUMAN GO are external.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></footer>
<script>""" + JS + """</script></html>"""
    return page.encode("utf-8")
