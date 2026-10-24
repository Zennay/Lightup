#!/usr/bin/env python3
"""Offline revocation-impact desk for previously received source-only packages.

Unlike normal inbox reopen, this can REVIEW packages signed by a locally
REVOKED public key (only to inventory their custody impact). It NEVER marks
such packages trusted, release-ready, client-authorized or safe to execute.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from inbox import KIND as INBOX_KIND, _html as original_html, _import_original_install
from offline_signatures import (
    Hold, MAX_ARCHIVE_BYTES, _fingerprint, _pairs_no_duplicates,
    _regular_file_bytes, _write_new_private, verify, _canonical,
)
from portable_handoff import (
    ARCHIVE_NAME, PUBLIC_NAME, RECEIPT_NAME, SECOND_PUBLIC_NAME,
    SECOND_RECEIPT_NAME, _unpack_bytes,
)
from trust_registry import _json_file, _owner_private, _record, _subdirs, minimum_signers

KIND = "lightup.software.offline_revocation_impact.v1"
MAX_INBOXES = 12
MAX_ROWS = 24  # Prevent runaway previously bundled software population.


def _signers(members: dict[str, bytes], record: dict) -> list[dict]:
    names = [(PUBLIC_NAME, RECEIPT_NAME)]
    if SECOND_PUBLIC_NAME in members:
        names.append((SECOND_PUBLIC_NAME, SECOND_RECEIPT_NAME))
    stored = record["signers"]
    if type(stored) is not list or len(stored) != len(names):
        raise Hold("original stored signer membership no longer matches ZIP")
    # These are cryptographically verified bytes, NOT current trust grants.
    result = []
    for index, (public_name, receipt_name) in enumerate(names):
        raw_pub = members[public_name]
        if len(raw_pub) > 16384:
            raise Hold("embedded signed public key over limit")
        try:
            candidate = serialization.load_pem_public_key(raw_pub)
        except (ValueError, TypeError) as exc:
            raise Hold("embedded public key malformed") from exc
        if not isinstance(candidate, Ed25519PublicKey):
            raise Hold("original stored signer not Ed25519")
        fp = _fingerprint(candidate)
        saved = stored[index]
        if (
            type(saved) is not dict or set(saved) != {"label", "fingerprint"}
            or type(saved["label"]) is not str
            or saved["fingerprint"] != fp
        ):
            raise Hold("original original-source signer fingerprint or schema changed")
        result.append({
            "fingerprint": fp, "original_local_label": saved["label"],
            "receipt_name": receipt_name, "key_name": public_name,
        })
    if len(set(x["fingerprint"] for x in result)) != len(result):
        raise Hold("the original ZIP contains a repeated signing key")
    return result


def _review_inbox(registry: Path, folder: Path, selected_position: int, install: object) -> list[dict]:
    _owner_private(folder)
    manifest = _json_file(folder / "inbox.json")
    if manifest.get("format") != INBOX_KIND or manifest.get("disposition") != "PRIVATE_HUMAN_REVIEW_ONLY":
        raise Hold("not an original private source-only custody inbox")
    for flag in ("source_owner_authenticated", "client_consent", "remediation_verified", "scan_authorized", "deployment_authorized", "human_go"):
        if manifest.get(flag) is not False:
            raise Hold("inbox contains forbidden authority claim")
    entries = manifest.get("entries")
    if type(entries) is not list or not 1 <= len(entries) <= 12:
        raise Hold("original inbox records are absent or unbounded")
    if _regular_file_bytes(folder / "index.html", 32768) != original_html(entries):
        raise Hold("original scriptless source-only dashboard bytes changed")
    observed = set()
    rows: list[dict] = []
    for entry_index, rec in enumerate(entries, 1):
        if (
            type(rec) is not dict or rec.get("ordinal") != entry_index
            or rec.get("slot") != f"slot-{entry_index:02d}"
            or type(rec.get("original_zip_sha256")) is not str
            or type(rec.get("original_zip_bytes")) is not int
        ):
            raise Hold("noncanonical original software custody record")
        members = _unpack_bytes(folder / f"bundle-{entry_index:02d}.portable.zip")
        software = members[ARCHIVE_NAME]
        identity = hashlib.sha256(software).hexdigest()
        if identity != rec["original_zip_sha256"] or len(software) != rec["original_zip_bytes"]:
            raise Hold("signed software SHA/byte identity changed since original receipt")
        if identity in observed:
            raise Hold("ambiguous repeated software ZIP in one original inbox")
        observed.add(identity)
        signers = _signers(members, rec)
        # True signed ZIP verification independent of CURRENT trust state.
        # Publication of a revoked package is NOT permitted by this inspector.
        with tempfile.TemporaryDirectory(prefix=".lightup-revocation-byte-review-", dir=str(folder)) as tmp:
            local = Path(tmp)
            _write_new_private(local / ARCHIVE_NAME, software)
            for signer in signers:
                _write_new_private(local / signer["key_name"], members[signer["key_name"]])
                _write_new_private(local / signer["receipt_name"], members[signer["receipt_name"]])
                verified = verify(
                    local / ARCHIVE_NAME, local / signer["receipt_name"],
                    local / signer["key_name"], signer["fingerprint"]
                )
                if verified != software:
                    raise Hold("cryptographically stored signed software changed")
        installed = folder / rec["slot"]
        if installed.is_symlink() or not installed.is_dir():
            raise Hold("original native offline installed suite is absent")
        install.verify(installed)
        if _regular_file_bytes(installed / ARCHIVE_NAME, MAX_ARCHIVE_BYTES) != software:
            raise Hold("original native installed software differs from signed bytes")
        annotated = []
        for signer in signers:
            fp = signer["fingerprint"]
            trusted_record = _record(registry, fp)
            # Original and present HUMAN labels may differ between separate
            # private operators. Only cryptographic key bytes/fingerprint can
            # identify the same custody key; a label is never authentication.
            # The existence of a local revocation record is the LOCAL HOLD.
            revoked = registry / "revocations" / (fp + ".json")
            local_status = "LOCAL_REVOKED_HOLD" if revoked.exists() or revoked.is_symlink() else "CURRENTLY_REGISTERED_NOT_REAL_WORLD_AUTHENTICATION"
            annotated.append({
                "fingerprint": fp,
                "original_local_label": signer["original_local_label"],
                "current_local_label": trusted_record["label"],
                "local_trust_state": local_status,
            })
        rows.append({
            "selected_inbox": selected_position,
            "original_inbox_ordinal": entry_index,
            "software_sha256": identity,
            "software_bytes": len(software),
            "signers": annotated,
            "local_revocation_affects_this_package": any(
                s["local_trust_state"] == "LOCAL_REVOKED_HOLD" for s in annotated
            ),
        })
    return rows


def _html(records: list[dict], floor: int) -> bytes:
    items = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';",
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        "<title>LightUp | PRIVATE local key revocation impact</title>",
        "<style>body{background:#111a29;color:#eef4ff;font:16px system-ui;",
        "max-width:1024px;margin:2rem auto;padding:0 1rem}h1,h2{color:#fff}",
        ".warn{padding:1rem;border:1px solid #e4b772;border-radius:8px}",
        "table{width:100%;border-collapse:collapse}th,td{border:1px solid #566477;",
        "padding:.7rem;vertical-align:top;word-break:break-word}th{background:#233447}",
        "code{color:#a9dcff;font-size:.82rem}</style></head><body>",
        "<h1>PRIVATE LightUp signer revocation impact</h1>",
        "<p class='warn'><strong>DRAFT/HOLD · REVIEW_ONLY.</strong> This is a",
        " historical local-custody impact desk, NOT permission to reopen revoked",
        " software as trusted. Local revocation cannot retract previously shared",
        " files or authenticate clients, source authors or operators.</p>",
        f"<p>Local policy minimum: {floor} registered signer(s).",
        " Each original native software ZIP and signed receipt was checked",
        " for exact bytes despite any CURRENT revoked status. Human selected input",
        " order is not verified chronology.</p>",
        "<table><thead><tr><th>Selected inbox / row</th><th>Signed software identity</th>",
        "<th>Original local signing key state</th><th>Human follow-up</th></tr></thead><tbody>",
    ]
    for rec in records:
        identities = "<br>".join(
            "<strong>"+html.escape(s["local_trust_state"])+"</strong>"
            +"<br>Original: "+html.escape(s["original_local_label"])
            +"<br>Current: "+html.escape(s["current_local_label"])
            +" · <code>"+s["fingerprint"]+"</code>"
            for s in rec["signers"]
        )
        followup = ("LOCAL KEY REVOKED: withhold re-use and request fresh independent key and original source review"
                    if rec["local_revocation_affects_this_package"]
                    else "No known local key revocation; original security/consent/release HOLD still applies")
        items.extend([
            "<tr>",
            f"<td>#{rec['selected_inbox']:02d} / {rec['original_inbox_ordinal']:02d}</td>",
            f"<td><code>{rec['software_sha256']}</code><br>{rec['software_bytes']} bytes</td>",
            f"<td>{identities}</td>",
            f"<td>{html.escape(followup)}</td>",
            "</tr>",
        ])
    items.extend([
        "</tbody></table><h2>Review contract</h2><p>Current key policy and",
        " past receipt bytes are local claims, not an authentic client approval",
        " or independent source certification. In case of a revoked key, do not",
        " infer earlier receipts are safe; they must undergo separate HUMAN review.",
        " Recreate this PRIVATE report after any relevant change. Never use these",
        " files to issue grants, activate targets, scan, remediate or deploy.",
        " No browser scripts, persistence or network resources.</p></body></html>",
    ])
    return "".join(items).encode("utf-8")


def impact(registry: Path, inboxes: list[Path], output: Path) -> None:
    _subdirs(registry)
    if not 1 <= len(inboxes) <= MAX_INBOXES or len({str(p) for p in inboxes}) != len(inboxes):
        raise Hold("choose 1–12 distinct original private inbox directories")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise Hold("choose a fresh, private absolute output directory")
    install = _import_original_install()
    install.owner_dir(output.parent)
    records = []
    for index, path in enumerate(inboxes, 1):
        records.extend(_review_inbox(registry, path, index, install))
        if len(records) > MAX_ROWS:
            raise Hold("local revocation review exceeds 24 signed packages")
    floor = minimum_signers(registry)
    if any(
        signer["local_trust_state"] == "LOCAL_REVOKED_HOLD"
        for rec in records for signer in rec["signers"]
    ):
        disposition = "PRIVATE_HUMAN_REVIEW_WITH_REVOKED_SIGNER_HOLD"
    else:
        disposition = "PRIVATE_HUMAN_REVIEW_NO_KNOWN_LOCAL_REVOCATION"
    receipt = {
        "format": KIND, "disposition": disposition,
        "current_local_minimum_signers": floor,
        "source_owner_authenticated": False,
        "current_client_consent": False, "security_remediation_verified": False,
        "active_scan_authorized": False, "deployment_authorized": False,
        "human_go": False,
        "records": records,
    }
    stage = output.parent / (".lightup-revocation-desk-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        _write_new_private(stage / "index.html", _html(records, floor))
        _write_new_private(stage / "revocation-impact.json", _canonical(receipt) + b"\n")
        # Only tighten last-moment reads: never invent a trusted state.
        for rec in records:
            for signer in rec["signers"]:
                revoked = registry / "revocations" / (signer["fingerprint"] + ".json")
                was_revoked = signer["local_trust_state"] == "LOCAL_REVOKED_HOLD"
                if (revoked.exists() or revoked.is_symlink()) != was_revoked:
                    raise Hold("local revocation state changed during impact publication")
        install.exclusive_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("PRIVATE REVIEW_ONLY local signer impact:", output / "index.html")
    print("Source-locked software and LOCAL revocation are not consent or release approval.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--inbox", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        impact(args.keyring, args.inbox, args.output_dir)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
