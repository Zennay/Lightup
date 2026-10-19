"""Exact-source Ticket Desk auto-load bundle inside an encrypted authorized Casework handoff.

The original standalone product is SHA256-pinned and never edited. Its already
CSP-hashed JavaScript runs unchanged; this new one-file *output* gets an
additional literal-hash-pinned bootstrap script and inert base64 source bytes.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re

ORIGINAL = Path(__file__).resolve().parents[1] / "remediation-ticket-drafts" / "standalone.html"
PINNED_TICKET_DESK_SHA256 = "c5e8c7bd97ba4384fb63e443bd2f9bc155fe39f562633274af071e927122ac3d"
SCRIPT = """(function(){
'use strict';
var holder=document.getElementById('lightupApprovedSourceCSV');
var input=document.getElementById('source-file');
var status=document.getElementById('notice');
try {
 if(!holder || !input || !status)throw new Error('Original PRIVATE Ticket Desk import UI is missing.');
 var binary=atob(holder.textContent);
 var bytes=new Uint8Array(binary.length);
 for(var i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
 var file=new File([bytes], 'lightup-PRIVATE-original-summary.csv', {type:'text/csv'});
 var transfer=new DataTransfer();
 transfer.items.add(file);
 input.files=transfer.files;
 input.dispatchEvent(new Event('change',{bubbles:true}));
 // The existing original engine, not this bootstrap, performs all CSV validation.
 holder.textContent='';
 bytes.fill(0);
} catch(err) {
 if(status)status.textContent='PRIVATE source preload HOLD: file input unavailable. Original authenticated summary was not imported; do not assume any findings were loaded.';
}
})();"""


def build_ticketdesk(csv_text: str) -> str:
    if type(csv_text) is not str:
        raise ValueError("Original selected CSV must be a string.")
    raw_csv = csv_text.encode("utf-8", errors="strict")
    if not raw_csv or len(raw_csv) > 1_048_576:
        raise ValueError("Private original CSV outside source size boundary.")
    original = ORIGINAL.read_bytes()
    if hashlib.sha256(original).hexdigest() != PINNED_TICKET_DESK_SHA256:
        raise ValueError("Original Ticket Desk source owner changed: independent re-review required.")
    page = original.decode("utf-8", errors="strict")
    if page.count("</body>") != 1 or page.count('id="source-file"') != 1 or page.count("connect-src 'none'") != 1:
        raise ValueError("Original offline Ticket Desk markup or no-network policy changed.")
    # Validate the unchanged upstream standalone CSP against all its actual inline scripts.
    declared_match = re.search(r"script-src ([^;]+);", page)
    if declared_match is None:
        raise ValueError("Original Ticket Desk has no strict inline CSP.")
    declared = declared_match.group(1).split()
    inline = re.findall(r"<script>(.*?)</script>", page, flags=re.DOTALL)
    expected = [
        "'sha256-" + base64.b64encode(hashlib.sha256(x.encode("utf-8")).digest()).decode("ascii") + "'"
        for x in inline
    ]
    if len(expected) < 2 or declared != expected:
        raise ValueError("Original Ticket Desk CSP/source bytes mismatch; refusing private bundle.")
    script_hash = "'sha256-" + base64.b64encode(
        hashlib.sha256(("\n" + SCRIPT + "\n").encode("utf-8")).digest()
    ).decode("ascii") + "'"
    # Retain all original CSP script hashes; allow only this exact new preload script.
    new_policy = "script-src " + declared_match.group(1) + " " + script_hash + ";"
    page = page[:declared_match.start()] + new_policy + page[declared_match.end():]
    source_base64 = base64.b64encode(raw_csv).decode("ascii")
    inert = '<script id="lightupApprovedSourceCSV" type="application/json">' + source_base64 + '</script>'
    bridge = '<script>\n' + SCRIPT + '\n</script>'
    result = page.replace("</body>", inert + "\n" + bridge + "\n</body>", 1)
    if re.search(r"<script[^>]+src=", result, flags=re.IGNORECASE):
        raise ValueError("External scripts are forbidden in portable private Ticket Desk.")
    if len(result.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("Encrypted Ticket Desk HTML exceeds admitted size.")
    return result
