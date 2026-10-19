#!/usr/bin/env python3
"""Authenticated, encrypted ORIGINAL Evidence Artifact Ledger (HUMAN review only).

Reuses original live read controls from remediation-secure-export and the byte-pinned
original Artifact Ledger package. All target, grant, scan and retest paths are absent.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys
from getpass import GetPassWarning

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "remediation-secure-export"))

import secure_export as original  # unchanged original authenticated tenant path

KIND = "lightup.authenticated_encrypted_evidence_ledger"
CONTRACT = "lightup.finding_export._COLUMNS_v1"
EXPECTED_ORIGINAL_LEDGER_SHA = "4707fa609387dd8b50050bf746485feee648704886da729f5d072c467f753aa7"
MAX_ENVELOPE = 3 * 1024 * 1024
MAX_RENDERED = 3 * 1024 * 1024
LABEL_LIMIT = 120
EXPECTED_FIELDS = frozenset({
    "kind", "schema_version", "disposition", "source_contract",
    "client_reference", "engagement_reference", "original_csv_sha256",
    "original_finding_count", "source_csv_base64", "original_ledger_sha256",
    "rendered_html_sha256", "warning", *original.FALSE
})


def _pinned_original() -> bytes:
    path = ROOT / "remediation-artifact-ledger" / "package.py"
    spec = importlib.util.spec_from_file_location("_original_evidence_ledger_package", path)
    if spec is None or spec.loader is None:
        raise ValueError("Original Evidence Ledger build is unavailable.")
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    content = package.build()
    if hashlib.sha256(content).hexdigest() != EXPECTED_ORIGINAL_LEDGER_SHA:
        raise ValueError("Original Evidence Ledger source drift: HUMAN HOLD.")
    if content != path.with_name("standalone.html").read_bytes():
        raise ValueError("Original portable app differs from its source build: HUMAN HOLD.")
    return content


def _text_label(value: str, name: str) -> str:
    original._literal(value, name)
    if len(value) > LABEL_LIMIT or any(ch in value for ch in ("<", ">", "&")):
        raise ValueError("Invalid original " + name + " label.")
    return value


def _safe_js_string(value: str) -> str:
    # Avoid HTML parser delimiters even in an inline script protected by CSP.
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _script(csv_raw: bytes, client: str, engagement: str) -> bytes:
    if len(csv_raw) > original.MAX_CSV_BYTES:
        raise ValueError("Original CSV exceeds the source limit.")
    source = base64.b64encode(csv_raw).decode("ascii")
    js = """(function() {
"use strict";
try {
 const encoded = __CSV__;
 const client = __CLIENT__;
 const engagement = __ENGAGEMENT__;
 const input = document.getElementById("original");
 const clientField = document.getElementById("client");
 const engagementField = document.getElementById("engagement");
 if (!input || !clientField || !engagementField || !document.getElementById("load")) {
   throw new Error("Original offline Evidence Ledger input is unavailable.");
 }
 if (typeof DataTransfer === "undefined" || typeof File === "undefined") {
   throw new Error("This local browser cannot preload a source file; HUMAN HOLD.");
 }
 const decoded = atob(encoded);
 const bytes = Uint8Array.from(decoded, ch => ch.charCodeAt(0));
 const file = new File([bytes], "original-current-findings.csv", {type:"text/csv"});
 const transfer = new DataTransfer();
 transfer.items.add(file);
 input.files = transfer.files;
 clientField.value = client;
 engagementField.value = engagement;
 document.getElementById("load").click();
 const heading = document.querySelector("header .eyebrow");
 if (heading) heading.textContent = "LIGHTUP / AUTHENTICATED AT EXPORT / PRIVATE OFFLINE HUMAN REVIEW";
} catch(e) {
 const notice = document.getElementById("notice");
 if (notice) {
   notice.textContent = "HUMAN HOLD: Original offline source preload unavailable; no review initiated.";
   notice.className = "alert";
 }
}
})();"""
    js = (js.replace("__CSV__", _safe_js_string(source))
            .replace("__CLIENT__", _safe_js_string(client))
            .replace("__ENGAGEMENT__", _safe_js_string(engagement)))
    if "</script" in js.lower() or "<!--" in js:
        raise ValueError("Untrusted script delimiter in original source.")
    return js.encode("utf-8", "strict")


def _render(csv_raw: bytes, client: str, engagement: str) -> bytes:
    original._strict_summary(csv_raw.decode("utf-8", "strict"))
    _text_label(client, "client")
    _text_label(engagement, "engagement")
    page = _pinned_original().decode("utf-8", "strict")
    js = _script(csv_raw, client, engagement)
    csp = "'sha256-" + base64.b64encode(hashlib.sha256(js).digest()).decode("ascii") + "'"
    def add_hash(match):
        return match.group(1) + " " + csp + match.group(2)
    page, count = re.subn(r"(script-src [^;]+)(; style-src )", add_hash, page)
    if count != 1 or page.count("</body>") != 1:
        raise ValueError("Original offline Evidence Ledger CSP/body has changed.")
    page = page.replace("</body>", "<script>" + js.decode("utf-8") + "</script></body>")
    rendered = page.encode("utf-8", "strict")
    if len(rendered) > MAX_RENDERED or b"connect-src 'none'" not in rendered:
        raise ValueError("PRIVATE Evidence Ledger offline policy/size HOLD.")
    return rendered


def _make_envelope(csv_text: str, client: str, engagement: str) -> bytes:
    _text_label(client, "client")
    _text_label(engagement, "engagement")
    sha, count = original._strict_summary(csv_text)
    raw = csv_text.encode("utf-8", "strict")
    rendered = _render(raw, client, engagement)
    manifest = {
        "kind": KIND, "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_EVIDENCE_LEDGER_ONLY",
        "source_contract": CONTRACT,
        "client_reference": client,
        "engagement_reference": engagement,
        "original_csv_sha256": sha,
        "original_finding_count": count,
        "source_csv_base64": base64.b64encode(raw).decode("ascii"),
        "original_ledger_sha256": EXPECTED_ORIGINAL_LEDGER_SHA,
        "rendered_html_sha256": hashlib.sha256(rendered).hexdigest(),
        "warning": (
            "Authenticated original read at export time only. No durable/current "
            "client consent, scan, grant, retest, remediation verification or release. "
            "PRIVATE HTML will contain original source findings after explicit opening."
        ),
        **{flag: False for flag in original.FALSE},
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > MAX_ENVELOPE:
        raise ValueError("Encrypted original Evidence Ledger envelope exceeds limit.")
    return encoded


def _read_envelope(encoded: bytes) -> tuple[dict, bytes]:
    if not encoded or len(encoded) > MAX_ENVELOPE:
        raise ValueError("Invalid private Evidence Ledger envelope size.")
    data = json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=original._unique_pairs)
    if type(data) is not dict or set(data) != EXPECTED_FIELDS:
        raise ValueError("Unsupported private Evidence Ledger envelope.")
    if json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") != encoded:
        raise ValueError("Noncanonical private Evidence Ledger envelope.")
    if (data["kind"] != KIND or type(data["schema_version"]) is not int
            or data["schema_version"] != 1 or
            data["disposition"] != "PRIVATE_HUMAN_EVIDENCE_LEDGER_ONLY" or
            data["source_contract"] != CONTRACT or
            any(data[flag] is not False for flag in original.FALSE)):
        raise ValueError("Envelope makes unsupported authorization claims.")
    client = _text_label(data["client_reference"], "client")
    engagement = _text_label(data["engagement_reference"], "engagement")
    if data["original_ledger_sha256"] != EXPECTED_ORIGINAL_LEDGER_SHA or type(data["warning"]) is not str:
        raise ValueError("Original Evidence Ledger identity HOLD.")
    if type(data["source_csv_base64"]) is not str:
        raise ValueError("Invalid original CSV body.")
    raw = base64.b64decode(data["source_csv_base64"], validate=True)
    if base64.b64encode(raw).decode("ascii") != data["source_csv_base64"]:
        raise ValueError("Noncanonical original CSV bytes.")
    sha, count = original._strict_summary(raw.decode("utf-8", "strict"))
    if (data["original_csv_sha256"] != sha or
            type(data["original_finding_count"]) is not int or
            data["original_finding_count"] != count):
        raise ValueError("Original Evidence Ledger source integrity HOLD.")
    rendered = _render(raw, client, engagement)
    if data["rendered_html_sha256"] != hashlib.sha256(rendered).hexdigest():
        raise ValueError("Authenticated offline Evidence Ledger HTML identity HOLD.")
    return data, rendered


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="operation", required=True)
    export = sub.add_parser("export", help="Authenticated original tenant findings -> NEW encrypted .ltv (no plaintext disk)")
    for name in ("db", "email", "client-id", "engagement-id"):
        export.add_argument("--" + name, required=True)
    export.add_argument("--output", required=True, type=Path)
    for operation in ("open", "open-current", "inspect", "rotate"):
        p = sub.add_parser(operation, help={
            "open": "Decrypt to owner-private HTML, no current read authorization claim",
            "open-current": "Fresh original login and exact current source match before private HTML",
            "inspect": "Decrypt and show source count only, without original identifiers",
            "rotate": "Re-encrypt to a NEW .ltv with a NEW passphrase (no plaintext disk)",
        }[operation])
        p.add_argument("--input", type=Path, required=True)
        if operation in ("open", "open-current", "rotate"):
            p.add_argument("--output", type=Path, required=True)
        if operation in ("open", "open-current"):
            p.add_argument("--ack-private-html", action="store_true", required=True)
        if operation == "open-current":
            for name in ("db", "email", "client-id", "engagement-id"):
                p.add_argument("--" + name, required=True)
    args = ap.parse_args(argv)
    try:
        vault = original._vault()
        if args.operation == "export":
            if args.output.suffix.lower() != ".ltv":
                raise ValueError("Encrypted output must be a new .ltv.")
            csv_text = original._authorized_summary(
                db=args.db, email=args.email,
                client_id=args.client_id, engagement_id=args.engagement_id)
            encrypted = _make_envelope(csv_text, args.client_id, args.engagement_id)
            password = vault._password("New PRIVATE Evidence Ledger passphrase: ", fresh=True)
            ciphertext = vault._seal(vault._inner(encrypted, "application/json"), password)
            vault._exclusive_output(args.output.expanduser().absolute(), ciphertext)
            print("Original authenticated Evidence Ledger sealed as one new owner-only 0600 .ltv.")
            print("No plaintext intermediate or durable authority/consent/retest inferred.")
            return 0
        if args.input.suffix.lower() != ".ltv":
            raise ValueError("Encrypted input must be a .ltv.")
        if args.operation in ("open", "open-current") and args.output.suffix.lower() != ".html":
            raise ValueError("New PRIVATE HTML destination must use .html.")
        if args.operation == "rotate" and args.output.suffix.lower() != ".ltv":
            raise ValueError("Rotated PRIVATE destination must use .ltv.")
        if args.operation != "inspect" and args.input.expanduser().absolute() == args.output.expanduser().absolute():
            raise ValueError("Never overwrite the source vault.")
        current_source = None
        if args.operation == "open-current":
            current = original._authorized_summary(
                db=args.db, email=args.email,
                client_id=args.client_id, engagement_id=args.engagement_id)
            current_source = original._strict_summary(current)
        ciphertext = vault._private_input(args.input.expanduser().absolute(), vault.MAX_VAULT)
        password = vault._password("Existing PRIVATE Evidence Ledger passphrase: ", fresh=False)
        content, mime, inner = vault._open(ciphertext, password)
        if mime != "application/json":
            raise ValueError("Unsupported PRIVATE vault MIME.")
        data, rendered = _read_envelope(content)
        if args.operation == "inspect":
            print("Offline original Evidence Ledger; count:", data["original_finding_count"])
            print("Human-only source snapshot; no client, finding, file or owner identities displayed.")
            return 0
        if args.operation == "rotate":
            replacement = vault._password("New replacement private passphrase: ", fresh=True)
            if replacement == password:
                raise ValueError("Replacement passphrase must be different.")
            vault._exclusive_output(args.output.expanduser().absolute(), vault._seal(inner, replacement))
            print("Rotated to new 0600 encrypted source. Old encrypted vault unchanged.")
            return 0
        if current_source is not None:
            if (data["client_reference"] != args.client_id or
                    data["engagement_reference"] != args.engagement_id or
                    (data["original_csv_sha256"], data["original_finding_count"]) != current_source):
                raise ValueError("Current original authenticated engagement/source differs: HOLD.")
        vault._exclusive_output(args.output.expanduser().absolute(), rendered)
        print("New 0600 PRIVATE offline Evidence Ledger HTML created.")
        print("Browser auto-loads original exported CSV locally. No scanning, consent, verified fix or deployment.")
        return 0
    except (ValueError, TypeError, OSError, sqlite3.DatabaseError, UnicodeError,
            GetPassWarning, EOFError, KeyboardInterrupt, ImportError) as exc:
        # No confidential filenames, request identifiers, passwords or original text in errors.
        print("HOLD: No Evidence Ledger output. Check permitted original account, encrypted source and private directory.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
