#!/usr/bin/env python3
"""Build the PRIVATE offline AES-GCM courier UI for human review handoffs.

Does not decrypt sources on the server. All encryption remains memory-only in
a modern browser WebCrypto implementation and provides confidentiality of an
offline packet, NEVER authenticated actor/source identity or permission.
"""
from __future__ import annotations

import base64
import hashlib
import html
from pathlib import Path

MAX_JS = 18_000
CSS = """*{box-sizing:border-box}:root{color-scheme:dark}body{font:16px/1.55 system-ui,sans-serif;max-width:940px;margin:0 auto;padding:28px;background:#0f192a;color:#eff6ff}h1{font-size:clamp(1.7rem,4vw,2.5rem)}section{background:#1b3049;border-radius:12px;padding:20px;margin:20px 0}p{line-height:1.6}.hold{border:1px solid #ab8652;background:#342817;padding:16px;border-radius:9px;color:#ffdfae}label{display:block;margin:12px 0}label span{display:block;margin:4px 0}input,button{font:inherit;background:#2a4869;color:#fff;border:1px solid #8295b5;border-radius:7px;padding:10px;max-width:100%}input[type=password]{width:100%;max-width:480px}button{cursor:pointer;background:#376999;font-weight:700;margin:10px 0}button:hover{background:#4981b3}button:disabled{opacity:.55;cursor:not-allowed}button:focus-visible,input:focus-visible{outline:3px solid #85d4ff}output{display:block;margin:18px 0;padding:12px;border:1px solid #55708f;border-radius:8px;white-space:pre-wrap}small{color:#c0d3ea}"""

def render_courier() -> bytes:
    path = Path(__file__).with_name("private_courier.js")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JS:
        raise ValueError("Unsafe PRIVATE courier offline source")
    js = path.read_bytes().decode("utf-8","strict")
    if "</script" in js.lower():
        raise ValueError("Invalid inline JavaScript boundary")
    csp = (
        "default-src 'none'; script-src 'sha256-" +
        base64.b64encode(hashlib.sha256(js.encode("utf-8")).digest()).decode("ascii") +
        "'; style-src 'sha256-" +
        base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii") +
        "'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"" + html.escape(csp,quote=True) + "\">"
        "<title>LightUp PRIVATE encrypted HUMAN courier · DRAFT/HOLD</title>"
        "<style>" + CSS + "</style></head><body><main>"
        "<h1>LightUp · PRIVATE encrypted HUMAN courier</h1>"
        "<p class='hold'><strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</strong> "
        "This local utility encrypts/decrypts one PRIVATE review HTML/CSV/JSON or pinned offline ZIP file only. "
        "It does not sign the original record, authenticate an actor, authorize an assessment, "
        "grant permission, revoke authority, contact a target or launch an active scan. "
        "Encrypted content is not automatically displayed or executed.</p>"
        "<p>Use a locally trusted modern browser with offline WebCrypto. "
        "Transfer the recipient's own encrypted packet through an authorized channel; "
        "give its unique strong passphrase separately to the authenticated intended recipient. "
        "Do not share the private owner receipt or files belonging to another team. "
        "The password is not stored on disk or in browser localStorage by this tool.</p>"
        "<section><h2>1. Lock a local HUMAN file</h2>"
        "<label><span>One original PRIVATE .html / .csv / .json / .zip (max 2 MiB)</span>"
        "<input id='plainInput' type='file' accept='.html,.csv,.json,.zip'></label>"
        "<label><span>Unique strong private passphrase, at least 12 UTF-8 bytes</span>"
        "<input id='entryA' type='password' autocomplete='off' maxlength='1024'></label>"
        "<label><span>Confirm passphrase</span>"
        "<input id='entryB' type='password' autocomplete='off' maxlength='1024'></label>"
        "<button type='button' id='seal'>Encrypt as PRIVATE .luhr</button>"
        "<small>Uses PBKDF2-SHA-256 (310,000 iterations) and AES-256-GCM "
        "with a new random 16-byte salt and 12-byte nonce for each envelope. "
        "The exact binary envelope header is authenticated. Original file bytes are not changed.</small>"
        "</section><section><h2>2. Unlock an encrypted PRIVATE handoff</h2>"
        "<label><span>One encrypted .luhr file</span>"
        "<input id='vaultInput' type='file' accept='.luhr'></label>"
        "<label><span>Optional independently obtained original encrypted file SHA-256 (64 hex characters)</span>"
        "<input id='expectedDigest' type='text' maxlength='64' autocapitalize='off' autocomplete='off' spellcheck='false'></label>"
        "<p>The SHA-256 fingerprint is shown after encrypting and after opening a packet. "
        "The recipient may enter the independently communicated ciphertext fingerprint; "
        "a mismatch refuses decryption. A hash alone is only byte matching, not sender identity or authorization.</p>"
        "<p>Enter the matching passphrase above and click decrypt. "
        "The original contained filename and bytes are recovered locally without auto-opening them. "
        "Do not trust or execute unknown HTML, even if decryption succeeds.</p>"
        "<button type='button' id='open'>Decrypt to local original file</button>"
        "</section><output id='message' role='status' aria-live='polite'>"
        "No files have been selected or transmitted. PRIVATE bytes stay in this browser."
        "</output><p>Confidentiality does NOT establish sender trust, source provenance, "
        "tenant membership, client consent, operator consent, grant, revocation or security clearance. "
        "All original LightUp authorization/release gates remain mandatory.</p>"
        "</main><script>" + js + "</script></body></html>"
    ).encode("utf-8")
