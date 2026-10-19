"""Source-owner-authenticated PRIVATE Casework export directly to AES-GCM vault.

New-only integration of original authenticated LightUp Casework export and an
unaltered original human ticket vault snapshot. No plaintext intermediate files,
new grant path, scan, remote target, tenant bypass or verified remediation claim.
"""
from __future__ import annotations

import argparse
import base64
import csv
from getpass import getpass, GetPassWarning
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import unicodedata
import warnings

# Reuse exact original published source owners, do not alter their contracts.
from lightup.domain import AccountLockedError, DomainStore
from lightup.finding_export_service import render_client_findings_csv
from lightup.remediation_handoff_cli import _bundle_workspace, MAX_CSV_BYTES, MAX_FINDINGS

ROOT = Path(__file__).resolve().parents[1]
VAULT_PATH = ROOT / "remediation-ticket-vault" / "vault.py"
KIND = "lightup.encrypted_authenticated_casework_handoff"
MAX_ENVELOPE = 3 * 1024 * 1024
MAX_HTML = 2 * 1024 * 1024
COLUMNS = ("finding_id", "title", "severity", "retest_status", "remediation")
STATES = ("not_tested", "fix_pending", "fixed", "regression")
SEVERITIES = ("critical", "high", "medium", "low", "info")
FALSE = ("authenticated", "source_authorized", "assessment_authorized", "grant",
         "client_consent", "operator_consent", "execution", "scan",
         "retest_verified", "release")


def _vault():
    if not VAULT_PATH.is_file():
        raise ValueError("Original PRIVATE ticket vault source is unavailable.")
    spec = importlib.util.spec_from_file_location("_lightup_original_human_ticket_vault", VAULT_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("Original PRIVATE ticket vault cannot be loaded.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _strict_summary(csv_text: str) -> tuple[str, int]:
    """Entire original authorized/redacted summary admitted before HTML or vault output.

    This is an independent safety fence for *this new integration only*, not a
    modification or claim of closure of the original CSV issue #1182.
    """
    if type(csv_text) is not str:
        raise ValueError("Invalid original finding summary.")
    raw = csv_text.encode("utf-8", "strict")
    if len(raw) > MAX_CSV_BYTES:
        raise ValueError("Original summary exceeds 1 MiB.")
    stream = csv.reader(io.StringIO(csv_text, newline=""), strict=True)
    header = next(stream, None)
    if header != list(COLUMNS):
        raise ValueError("Unexpected original finding export columns.")
    seen: set[str] = set()
    count = 0
    for row in stream:
        count += 1
        if count > MAX_FINDINGS or len(row) != len(COLUMNS):
            raise ValueError("Invalid or oversized original finding export.")
        for key, cell in zip(COLUMNS, row):
            if not cell or len(cell.encode("utf-8")) > 6000:
                raise ValueError("Empty or oversized original summary field.")
            # Unicode default controls, invisible bidi/format, surrogates, private
            # use and dangerous line/paragraph separators are rejected, not cleaned.
            if any(unicodedata.category(c).startswith("C") or
                   unicodedata.category(c) in ("Zl", "Zp") for c in cell):
                raise ValueError("Ambiguous Unicode in original finding summary.")
            probe = unicodedata.normalize("NFKC", cell).lstrip()
            if probe.startswith(("=", "+", "-", "@")):
                raise ValueError("Unicode-compatible spreadsheet formula prefix in original export.")
        finding_id, _, severity, retest, _ = row
        if finding_id in seen or len(finding_id) > 160 or not finding_id.strip():
            raise ValueError("Invalid or duplicated original finding ID.")
        if severity not in SEVERITIES or retest not in STATES:
            raise ValueError("Invalid original finding severity or retest label.")
        seen.add(finding_id)
    if count == 0:
        raise ValueError("No findings in exact authorized engagement.")
    return hashlib.sha256(raw).hexdigest(), count


def _literal(value: str, field: str) -> str:
    if type(value) is not str or not value or len(value) > 160 or value != value.strip() or any(
        unicodedata.category(char).startswith("C") for char in value
    ):
        raise ValueError("Noncanonical " + field + ".")
    return value


def _make_envelope(csv_text: str, client_id: str, engagement_id: str) -> bytes:
    csv_sha, count = _strict_summary(csv_text)
    html = _bundle_workspace(csv_text, root=ROOT).encode("utf-8", "strict")
    if not html or len(html) > MAX_HTML:
        raise ValueError("Casework HTML exceeds PRIVATE vault source size bound.")
    metadata = {
        "kind": KIND,
        "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_SOURCE_SNAPSHOT",
        "client_id_self_declared": _literal(client_id, "client ID"),
        "engagement_id_self_declared": _literal(engagement_id, "engagement ID"),
        "original_csv_sha256": csv_sha,
        "original_finding_count": count,
        "original_source_contract": "lightup.finding_export._COLUMNS_v1",
        "html_sha256": hashlib.sha256(html).hexdigest(),
        "html_bytes": len(html),
        "html_base64": base64.b64encode(html).decode("ascii"),
        **{flag: False for flag in FALSE},
        "instructions": (
            "Private export-time snapshot; not a current authentication, consent, "
            "grant, verified finding/fix/retest or permission to contact any target."
        ),
    }
    serialized = json.dumps(metadata, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(serialized) > MAX_ENVELOPE:
        raise ValueError("PRIVATE Casework handoff too large.")
    return serialized


def _read_envelope(payload: bytes, *, include_manifest: bool = False) -> bytes | tuple[bytes, dict]:
    if not payload or len(payload) > MAX_ENVELOPE:
        raise ValueError("PRIVATE handoff JSON is empty or oversized.")
    pairs = lambda vals: _unique_pairs(vals)
    data = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=pairs)
    expected = {
        "kind", "schema_version", "disposition", "client_id_self_declared",
        "engagement_id_self_declared", "original_csv_sha256", "original_finding_count",
        "original_source_contract", "html_sha256", "html_bytes", "html_base64",
        "instructions", *FALSE
    }
    if type(data) is not dict or set(data) != expected or data["kind"] != KIND or (
        type(data["schema_version"]) is not int or data["schema_version"] != 1
    ) or data["disposition"] != "PRIVATE_HUMAN_SOURCE_SNAPSHOT" or any(data[k] is not False for k in FALSE):
        raise ValueError("Unsupported or authority-claiming PRIVATE Casework envelope.")
    if json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") != payload:
        raise ValueError("Noncanonical PRIVATE Casework envelope.")
    for k in ("client_id_self_declared", "engagement_id_self_declared"):
        _literal(data[k], k)
    if data["original_source_contract"] != "lightup.finding_export._COLUMNS_v1" or (
        type(data["original_finding_count"]) is not int or
        not 1 <= data["original_finding_count"] <= MAX_FINDINGS
    ):
        raise ValueError("Invalid PRIVATE Casework source metadata.")
    if type(data["html_bytes"]) is not int or not 1 <= data["html_bytes"] <= MAX_HTML:
        raise ValueError("Invalid PRIVATE Casework HTML size.")
    for key in ("original_csv_sha256", "html_sha256"):
        if type(data[key]) is not str or len(data[key]) != 64 or any(ch not in "0123456789abcdef" for ch in data[key]):
            raise ValueError("Invalid encrypted Casework digest.")
    if type(data["html_base64"]) is not str or type(data["instructions"]) is not str:
        raise ValueError("Invalid PRIVATE Casework content.")
    html = base64.b64decode(data["html_base64"], validate=True)
    if base64.b64encode(html).decode("ascii") != data["html_base64"] or (
        len(html) != data["html_bytes"] or hashlib.sha256(html).hexdigest() != data["html_sha256"]
    ):
        raise ValueError("Decrypted PRIVATE Casework HTML integrity HOLD.")
    html.decode("utf-8", "strict")
    # Built from exact original Casework page; never substitute an external page.
    if b"<html" not in html[:512].lower() or b"lightup.authenticated_findings_handoff_v1" not in html:
        raise ValueError("Decrypted document is not an original Casework handoff.")
    return (html, data) if include_manifest else html


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in items:
        if key in result or key in ("__proto__", "constructor", "prototype"):
            raise ValueError("Duplicate or dangerous PRIVATE Casework JSON key.")
        result[key] = value
    return result


def _authorized_summary(*, db: str, email: str, client_id: str, engagement_id: str) -> str:
    """Use only the unchanged original authenticated tenant and engagement selector."""
    if not sys.stdin.isatty():
        raise ValueError("Interactive private TTY required for the original account login.")
    path = Path(db)
    if not path.is_file():
        raise ValueError("Existing LightUp domain database required.")
    _literal(client_id, "client ID")
    _literal(engagement_id, "engagement ID")
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        password = getpass("Current LightUp account password (private TTY): ")
    try:
        store = DomainStore(str(path))
        user = store.authenticate(email, password)
    finally:
        del password
    if user is None:
        raise ValueError("Original LightUp authentication denied.")
    ctx = store.context_for_user(user.user_id)
    return render_client_findings_csv(store, ctx, client_id, engagement_id=engagement_id)


def _authenticated_export(args) -> bytes:
    csv_text = _authorized_summary(
        db=args.db, email=args.email, client_id=args.client_id, engagement_id=args.engagement_id
    )
    return _make_envelope(csv_text, args.client_id, args.engagement_id)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    p = ap.add_subparsers(dest="operation", required=True)
    seal = p.add_parser("export", help="Original authenticated and tenant-checked Casework -> NEW encrypted .ltv, with no plaintext disk")
    seal.add_argument("--db", required=True)
    seal.add_argument("--email", required=True)
    seal.add_argument("--client-id", required=True)
    seal.add_argument("--engagement-id", required=True)
    seal.add_argument("--output", required=True, type=Path)
    op = p.add_parser("open", help="Decrypt original snapshot into a NEW private offline .html")
    op.add_argument("--input", required=True, type=Path)
    op.add_argument("--output", required=True, type=Path)
    op.add_argument("--ack-private-html", required=True, action="store_true")
    checked = p.add_parser(
        "open-current",
        help="Re-authenticate original client/engagement, require EXACT current authorized CSV bytes, then release new PRIVATE HTML",
    )
    checked.add_argument("--db", required=True)
    checked.add_argument("--email", required=True)
    checked.add_argument("--client-id", required=True)
    checked.add_argument("--engagement-id", required=True)
    checked.add_argument("--input", required=True, type=Path)
    checked.add_argument("--output", required=True, type=Path)
    checked.add_argument("--ack-private-html", required=True, action="store_true")
    inspect = p.add_parser("inspect", help="Authenticate an encrypted source snapshot and show ID-free aggregates in the terminal")
    inspect.add_argument("--input", required=True, type=Path)
    rotate = p.add_parser("rotate", help="Rotate source-bound Casework into a NEW encrypted vault without plaintext file")
    rotate.add_argument("--input", required=True, type=Path)
    rotate.add_argument("--output", required=True, type=Path)
    args = ap.parse_args(argv)
    try:
        vault = _vault()
        if args.operation == "export":
            if args.output.suffix.lower() != ".ltv":
                raise ValueError("Encrypted output must be a new .ltv file.")
            for key in ("client_id", "engagement_id"):
                _literal(getattr(args, key), key)
            envelope = _authenticated_export(args)
            fresh_passphrase = vault._password("New PRIVATE Casework vault passphrase: ", fresh=True)
            ciphertext = vault._seal(vault._inner(envelope, "application/json"), fresh_passphrase)
            vault._exclusive_output(args.output.expanduser().absolute(), ciphertext)
            print("New 0600 PRIVATE AES-GCM Casework vault created directly from authenticated export.")
            print("No plaintext file created. No ongoing authorization, current consent or fix/retest inferred.")
        else:
            if args.input.suffix.lower() != ".ltv":
                raise ValueError("PRIVATE Casework input must use .ltv.")
            if args.operation in ("open", "open-current"):
                if not args.ack_private_html or args.output.suffix.lower() != ".html":
                    raise ValueError("PRIVATE HTML requires --ack-private-html and a new .html destination.")
            if args.operation == "rotate":
                if args.output.suffix.lower() != ".ltv":
                    raise ValueError("Rotated PRIVATE Casework output must use .ltv.")
            if args.operation in ("open", "open-current", "rotate") and (
                args.input.expanduser().absolute() == args.output.expanduser().absolute()
            ):
                raise ValueError("Original and new PRIVATE source paths must differ.")
            current_sha = None
            current_count = None
            if args.operation == "open-current":
                # Reevaluate original stored account/tenant/engagement before any
                # decrypted casework HTML can be published. Not signed client consent.
                current_csv = _authorized_summary(
                    db=args.db, email=args.email, client_id=args.client_id, engagement_id=args.engagement_id
                )
                current_sha, current_count = _strict_summary(current_csv)
            vault_path = args.input.expanduser().absolute()
            ciphertext = vault._private_input(vault_path, vault.MAX_VAULT)
            old_passphrase = vault._password("Existing PRIVATE Casework vault passphrase: ", fresh=False)
            content, content_type, inner = vault._open(ciphertext, old_passphrase)
            if content_type != "application/json":
                raise ValueError("Vault does not contain original Casework handoff JSON.")
            html, manifest = _read_envelope(content, include_manifest=True)
            if args.operation == "inspect":
                # No names/IDs/titles/digests/notes/paths are exposed in stdout.
                print("Authenticated private Casework snapshot (local copy; not current consent or permission).")
                print("Original source findings:", manifest["original_finding_count"])
                print("Original HTML size:", manifest["html_bytes"], "bytes")
                print("No case/finding/owner identifiers or security verdicts disclosed.")
            elif args.operation == "rotate":
                replacement = vault._password("Replacement PRIVATE Casework passphrase: ", fresh=True)
                if replacement == old_passphrase:
                    raise ValueError("Replacement passphrase must differ from previous.")
                vault._exclusive_output(args.output.expanduser().absolute(), vault._seal(inner, replacement))
                print("New owner-private encrypted Casework vault created, original encrypted source preserved.")
                print("No plaintext file created; no authority/consent/retest state inferred.")
            else:
                if args.operation == "open-current":
                    if (manifest["client_id_self_declared"] != args.client_id or
                        manifest["engagement_id_self_declared"] != args.engagement_id or
                        manifest["original_csv_sha256"] != current_sha or
                        manifest["original_finding_count"] != current_count):
                        raise ValueError("Current original authorized source does not match encrypted Casework snapshot.")
                vault._exclusive_output(args.output.expanduser().absolute(), html)
                if args.operation == "open-current":
                    print("New 0600 PRIVATE Casework HTML restored from exact currently authenticated original source.")
                    print("This checked only current account/tenant/source; not client consent, grant, retest or release.")
                else:
                    print("New 0600 offline HUMAN Casework HTML restored; sensitive plaintext, never a grant or verified finding.")
        return 0
    except (AccountLockedError, GetPassWarning, PermissionError, ValueError, KeyError, OSError,
            UnicodeError, sqlite3.DatabaseError, EOFError, KeyboardInterrupt) as exc:
        # Opaque handling avoids logging client/tenant IDs, paths, passwords and evidence.
        print("HOLD: Secure Casework handoff unavailable; confirm local private storage and original authorized access.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
