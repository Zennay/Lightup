#!/usr/bin/env python3
"""One real source-free Cockpit -> offline editable HUMAN-only single review.

No synthetic comparison, original evidence, external auth, scanner or API.
The original unchanged read_cockpit admission is always authoritative for
local packet consistency (never genuine source/authentication or consent).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
from pathlib import Path
import sys
import unicodedata

import install

sys.path.insert(0, str(install.ROOT / "remediation-evidence-bundle-integrity"))
import read_cockpit

review = read_cockpit.review
verify = read_cockpit.verify
workspace = read_cockpit.workspace
board = read_cockpit.board

KIND = "lightup.source_free_single_cockpit_human_review"
WARNING = ("HUMAN-only private local follow-up. Anonymous reason occurrences "
           "are NOT verified findings, distinct cases, remediation, retests, "
           "client/operator consent, grants, sender identity or security approval.")
STAGES = frozenset(("open_human", "ask_source_owner",
                    "in_discussion_human", "answered_human_only"))
VAULT_WARNING = ("PRIVATE encrypted self-declared HUMAN notes. No client/operator "
                 "identity, authenticated sender, consent, remediation, retest, "
                 "security finding, grant, scan or release approval. DRAFT/HOLD.")
STYLE = """
body{font:16px/1.5 system-ui,sans-serif;background:#f3f6fa;color:#142940;margin:0}
main{max-width:920px;margin:2rem auto;padding:1rem}
article,aside{background:white;border:1px solid #d5dfe8;border-radius:12px;padding:1.1rem;margin:1rem 0}
aside{border-left:6px solid #a96c18}
h1{font-size:1.8rem}h3{margin:.1rem 0}p{margin:.45rem 0}
label{display:block;font-weight:600;margin-top:.65rem}
select,textarea,input[type=search]{display:block;box-sizing:border-box;width:100%;max-width:720px;background:white;color:#17283e;border:1px solid #8092a7;border-radius:8px;padding:.6rem;font:inherit}
input[type=search]{max-width:450px}
button{padding:.75rem 1rem;font:inherit;margin:.3rem .6rem .5rem 0;background:white;color:#174269;border:1px solid #56718c;border-radius:8px;cursor:pointer}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #be8a35}
small{display:block;line-height:1.5;color:#495e72}
"""

def require(ok: bool, why: str) -> None:
    review.require(ok, why)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def original(cockpit: Path) -> tuple[list[dict], str, bytes, bytes]:
    read_cockpit.inspect(cockpit)
    mb = review.private_read(cockpit / "manifest.json")
    raw = review.private_read(cockpit / "portfolio.json")
    packet = verify.json_obj(raw)
    entries = []
    for slot in packet["source_slots"]:
        for reason in sorted(read_cockpit.triage.REASONS):
            count = slot["pending_human_reasons"][reason]
            if count:
                require(reason in board.ADVICE, "Unknown original human follow-up vocabulary")
                entries.append({"slot": slot["slot"], "reason": reason,
                                "count": count, "advice": board.ADVICE[reason],
                                "stage": "open_human", "note": ""})
    require(len(entries) <= 72, "Original anonymous HUMAN reason groups exceed limit")
    return entries, sha(mb + b"\x00" + raw), mb, raw

def valid_note(note: object) -> bool:
    return (type(note) is str and len(note) <= 240
            and len(note.encode("utf-8")) <= 960
            and all(ch == "\n" or unicodedata.category(ch)[0] != "C" for ch in note))

def journal_payload(entries: list[dict], source_key: str) -> dict:
    return {"kind": KIND, "version": 1,
            "disposition": "PRIVATE_HUMAN_ONLY_NO_AUTHORITY",
            "authority_granted": False, "consent_verified": False,
            "remediation_verified": False,
            "source_free_packet_sha256": source_key, "warning": WARNING,
            "items": [{key: row[key] for key in ("slot", "reason", "count", "stage", "note")}
                      for row in entries]}

def admit_journal(raw: bytes, base: list[dict], source_key: str) -> list[dict]:
    packet = verify.json_obj(raw)
    require(type(packet) is dict and
            set(packet) == set(journal_payload(base, source_key)),
            "Unknown PRIVATE single-source HUMAN journal shape")
    require(packet.get("kind") == KIND and type(packet.get("version")) is int
            and packet["version"] == 1 and
            packet.get("disposition") == "PRIVATE_HUMAN_ONLY_NO_AUTHORITY"
            and packet.get("warning") == WARNING
            and packet.get("source_free_packet_sha256") == source_key
            and packet.get("authority_granted") is False
            and packet.get("consent_verified") is False
            and packet.get("remediation_verified") is False,
            "Journal cannot claim authority or change the original source")
    rows = packet.get("items")
    require(type(rows) is list and len(rows) == len(base),
            "Incomplete PRIVATE HUMAN reason journal")
    complete = []
    for candidate, original_row in zip(rows, base):
        require(type(candidate) is dict and
                set(candidate) == {"slot", "reason", "count", "stage", "note"}
                and type(candidate.get("slot")) is int
                and candidate["slot"] == original_row["slot"]
                and type(candidate.get("count")) is int
                and candidate["count"] == original_row["count"]
                and candidate.get("reason") == original_row["reason"]
                and type(candidate.get("stage")) is str
                and candidate["stage"] in STAGES
                and valid_note(candidate.get("note")),
                "Saved HUMAN journal row does not match original source-free count")
        complete.append({**original_row, "stage": candidate["stage"],
                         "note": candidate["note"]})
    return complete

def hash_csp(b: bytes) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(b).digest()).decode("ascii") + "'"

def report(entries: list[dict], source_key: str) -> bytes:
    js = (Path(__file__).with_name("single_review.js")).read_bytes()
    cipher_js = (Path(__file__).with_name("journal_encrypt.js")).read_bytes()
    open_js = (Path(__file__).with_name("journal_open.js")).read_bytes()
    require(b"</script" not in open_js.lower() and len(open_js) <= 16000,
            "Local source-bound encrypted review opener unsafe")
    require(b"</script" not in cipher_js.lower() and len(cipher_js) <= 16000,
            "Local source-bound encrypted browser component unsafe")
    require(b"</script" not in js.lower() and len(js) <= 16000,
            "Local HUMAN reviewer script unsafe")
    css = STYLE.encode("utf-8")
    seed = journal_payload(entries, source_key)
    seed["vault_warning"] = VAULT_WARNING
    seed["items"] = entries
    json_body = json.dumps(seed, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":")).replace("<", chr(92) + "u003c")
    policy = ("default-src 'none'; script-src " + hash_csp(js) +
              " " + hash_csp(cipher_js) +
              " " + hash_csp(open_js) +
              "; style-src " + hash_csp(css) +
              "; img-src 'none'; connect-src 'none'; form-action 'none'; "
              "object-src 'none'; base-uri 'none'")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content='""" +
            html.escape(policy, quote=True) + """'>
<title>LightUp · PRIVATE single Cockpit HUMAN reviewer</title><style>""" +
            STYLE + """</style><main><h1>PRIVATE one-Cockpit HUMAN reviewer</h1>
<aside><strong>HUMAN ONLY · DRAFT/HOLD</strong><p>""" +
            html.escape(WARNING) +
            """</p><p>This is exactly ONE ORIGINAL source-free Cockpit packet,
not an invented comparison, authenticated moment or verified customer cohort.</p>
<p>Notes are private plaintext in browser memory and downloaded JSON.
No browser storage, network, account login, auto-handoff or irreversible deletion.</p></aside>
<p>Source-free HUMAN reason groups: """ + str(len(entries)) +
            """. Source identity and permission remain UNKNOWN.</p>
<section class="filters" aria-label="Filter HUMAN cases">
<label>Find original source-free slot or HUMAN reason
<input id="query" type="search" maxlength="120" placeholder="e.g. slot 1, changed local metadata" autocomplete="off"></label>
<label>Show by HUMAN state
<select id="stage-filter"><option value="all">All HUMAN statuses</option>
<option value="open_human">Open for HUMAN review</option>
<option value="ask_source_owner">Ask original source owner</option>
<option value="in_discussion_human">In local HUMAN discussion</option>
<option value="answered_human_only">Answered HUMAN (NOT verified fix)</option></select></label>
<p id="overview" aria-live="polite">Original HUMAN group totals loading offline.</p></section>
<section id="reasons"></section>
<section class="filters" aria-label="Encrypted HUMAN journal">
<h2>Prefer encrypted PRIVATE journal</h2>
<p>The optional browser Web Crypto action downloads a password-protected <code>.luhj</code>
without first writing a plaintext JSON journal. Enter a unique passphrase
(14–256 NFC characters) twice. This is NOT authenticated source identity,
client consent, or permission to share any private data. Store the passphrase
separately and securely; it cannot be recovered.</p>
<label>New private journal passphrase <input id="journal-password" type="password"
minlength="14" maxlength="256" autocomplete="new-password"></label>
<label>Confirm new passphrase <input id="journal-confirm" type="password"
minlength="14" maxlength="256" autocomplete="new-password"></label>
<button type="button" id="encrypt-journal">Download encrypted PRIVATE journal (.luhj)</button>
<h3>Open an existing encrypted PRIVATE HUMAN journal in memory</h3>
<label>Local source-bound .luhj file <input id="vault-file" type="file" accept=".luhj,application/json"></label>
<label>Passphrase for existing journal <input id="vault-password" type="password" autocomplete="off"></label>
<button type="button" id="open-vault">Open existing encrypted journal (no plaintext file)</button>
</section>
<button type="button" id="save">Download unencrypted PRIVATE JSON (less safe)</button>
<button type="button" id="clear">Clear current in-memory HUMAN edits</button>
<p id="status" role="status" aria-live="polite">No browser edits sent anywhere.</p>
<small>Use the native single_review.py resume command with the SAME complete
original Cockpit plus the downloaded 0600 journal to continue in a fresh 0700
private folder. Answered HUMAN does NOT mean fixed, retested or approved.</small>
<script type="application/json" id="seed">""" + json_body +
            """</script><script>""" + js.decode("utf-8") +
            """</script><script>""" + cipher_js.decode("utf-8") +
            """</script><script>""" + open_js.decode("utf-8") +
            """</script></main></html>\n""").encode("utf-8")

def publish(cockpit: Path, dest: Path, journal: Path | None,
            journal_bytes: bytes | None = None) -> None:
    require(dest.is_absolute() and dest.parent == dest.parent.resolve(strict=True)
            and not dest.exists() and not dest.is_symlink()
            and cockpit != dest and cockpit != dest.parent
            and cockpit not in dest.parents and dest not in cockpit.parents,
            "HUMAN reviewer must not alter its native received Cockpit")
    install.owner_dir(dest.parent)
    require(journal is None or journal_bytes is None,
            "Do not mix original file and unlocked private journal inputs")
    if journal is not None:
        require(journal.is_absolute() and journal.parent == journal.parent.resolve(strict=True)
                and journal != dest and journal.parent != dest,
                "HUMAN journal must be a separate original private input")
    entries, key, manifest, original_raw = original(cockpit)
    if journal is not None or journal_bytes is not None:
        raw = review.private_read(journal) if journal is not None else journal_bytes
        require(type(raw) is bytes and len(raw) <= 262144,
                "Unsealed PRIVATE HUMAN journal exceeds bounded native admission")
        entries = admit_journal(raw, entries, key)
    rendered = report(entries, key)
    data = journal_payload(entries, key)
    payloads = {"index.html": rendered,
                "human-review.json": workspace.pretty(data)}
    descriptor = {
        "kind": KIND + ".local_private_receipt", "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_NO_AUTHORITY",
        "authority_granted": False, "consent_verified": False,
        "remediation_verified": False, "warning": WARNING,
        "files": {name: {"bytes": len(raw), "sha256": sha(raw)}
                  for name, raw in sorted(payloads.items())}
    }
    # Native admission immediately before publishing; no source owner edits.
    read_cockpit.inspect(cockpit)
    require(review.private_read(cockpit / "manifest.json") == manifest and
            review.private_read(cockpit / "portfolio.json") == original_raw,
            "Original source-free Cockpit changed while staging HUMAN workroom")
    workspace.publish_bundle(dest, payloads, workspace.pretty(descriptor))
    print("REVIEW_ONLY: one original source-free Cockpit HUMAN review:", dest)
    print("Open local editable browser:", dest / "index.html")
    print("Human journal is not authenticated consent, approval, retest or fix.")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="One original complete source-free PRIVATE Cockpit -> editable HUMAN journal")
    p = parser.add_subparsers(dest="action", required=True)
    for name in ("start", "resume"):
        cmd = p.add_parser(name)
        cmd.add_argument("--cockpit", type=Path, required=True)
        cmd.add_argument("--output-dir", type=Path, required=True)
        if name == "resume":
            cmd.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args()
    try:
        publish(args.cockpit, args.output_dir,
                args.journal if args.action == "resume" else None)
        return 2
    except (review.Hold, ValueError, UnicodeError, OSError, KeyError, TypeError) as exc:
        print("HOLD: original PRIVATE HUMAN source or journal rejected: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
