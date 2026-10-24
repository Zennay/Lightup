#!/usr/bin/env python3
"""Atomic offline custody inbox for 1–12 original LightUp software-only packages.

Admit only locally registered, non-revoked Ed25519 signer fingerprints.
Every original source-locked package is received by the ORIGINAL native
receiver. The batch is private, atomic, networkless and HUMAN REVIEW ONLY.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

from offline_signatures import (
    Hold, _canonical, _fingerprint,
    _regular_file_bytes, _write_new_private,
)
from portable_handoff import (
    ARCHIVE_NAME, PUBLIC_NAME, SECOND_PUBLIC_NAME,
    MAX_PORTABLE_BYTES, _unpack_bytes, receive,
)
from trust_registry import minimum_signers, trusted

MAX_PACKAGES = 12
KIND = "lightup.software.offline_custody_inbox.v1"


def _import_original_install() -> object:
    original = Path(__file__).resolve().parent.parent / "remediation-integrated-workspace"
    if not (original / "install.py").is_file():
        raise Hold("the pinned original offline source owner is absent")
    sys.path.insert(0, str(original))
    import install
    return install


def _html(records: list[dict]) -> bytes:
    lines = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' ",
        "content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        "<title>LightUp | LOCAL software custody inbox — REVIEW ONLY</title>",
        "<style>body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;",
        "background:#111925;color:#eef4ff}h1,h2{color:#ecf3ff}a{color:#9bdcff}",
        ".warning{border:1px solid #dfb77c;padding:1rem;border-radius:.6rem}",
        "table{border-collapse:collapse;width:100%;margin-top:1rem}th,td{border:1px solid #526073;",
        "padding:.6rem;vertical-align:top;word-break:break-word}th{text-align:left;background:#26384a}",
        "small{color:#c9d5e2}code{font-size:.8rem}</style></head><body>",
        "<h1>PRIVATE offline software custody inbox</h1>",
        "<p class='warning'><strong>REVIEW_ONLY · DRAFT/HOLD.</strong> These packages are not ",
        "released, authorized, source-owner-approved or client consent. Local cryptographic ",
        "custody does not establish actual source identity or permit scans, remediation, ",
        "client access or deployment. All original security/release gates remain required.</p>",
        f"<p>{len(records)} separately provided software-only packages; no customer evidence, ",
        "credentials or HUMAN notes imported. Ordinal position is user input, ",
        "<strong>not</strong> a timestamp or a verified update sequence.</p>",
        "<table><thead><tr><th>Package</th><th>Signed ZIP identity</th>",
        "<th>Registered local custody keys</th><th>Open original offline suite</th></tr></thead><tbody>",
    ]
    for r in records:
        link = f"{r['slot']}/index.html"
        signer_text = "<br>".join(
            f"{html.escape(s['label'])} · <code>{s['fingerprint'][:16]}…</code>"
            for s in r["signers"]
        )
        lines.extend([
            "<tr>",
            f"<td>#{r['ordinal']:02d} — <strong>ORIGINAL SOURCE-LOCK ADMITTED</strong></td>",
            f"<td><small>SHA-256:</small><br><code>{r['original_zip_sha256']}</code><br>",
            f"<small>{r['original_zip_bytes']} bytes</small></td>",
            f"<td>{signer_text}</td>",
            f"<td><a href='{link}'>Open PRIVATE original local workroom #{r['ordinal']:02d}</a></td>",
            "</tr>",
        ])
    lines.extend([
        "</tbody></table><h2>Important limitations</h2><p>Even a valid signature only ",
        "binds exact ZIP bytes to a key you independently registered. Local key revocation ",
        "cannot retract previously exported files or prove external source identity.</p>",
        "<p>Each received app remains governed by the original source inventory, offline ",
        "security posture and separate human/CI/release gates. No browser storage, ",
        "scripts, external resources or network calls are used on this page.</p></body></html>",
    ])
    return "".join(lines).encode("utf-8")


def _admit_signers(keyring: Path, members: dict[str, bytes], two_required: bool) -> list[dict]:
    has_second = SECOND_PUBLIC_NAME in members
    if two_required and not has_second:
        raise Hold("two independently registered custody keys required; no downgrade to one")
    keys = [PUBLIC_NAME] + ([SECOND_PUBLIC_NAME] if has_second else [])
    result = []
    for name in keys:
        # Decode the embedded key only in memory. It is never a trust anchor.
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if len(members[name]) > 16384:
            raise Hold("untrusted embedded public key too large")
        try:
            key = load_pem_public_key(members[name])
        except (TypeError, ValueError) as exc:
            raise Hold("untrusted embedded public key is malformed") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise Hold("embedded signer must be Ed25519")
        fp = _fingerprint(key)
        rec = trusted(keyring, fp)
        registry_pem = base64.b64decode(rec["public_pem_b64"], validate=True)
        # Confirm the independently curated trust entry refers to same public key.
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        canonical_pub = load_pem_public_key(registry_pem)
        if _fingerprint(canonical_pub) != fp:
            raise Hold("keyring provenance differs from portable public key")
        result.append({"fingerprint": fp, "label": rec["label"]})
    if len({r["fingerprint"] for r in result}) != len(result):
        raise Hold("two portable signers must be independently trusted distinct keys")
    return result


def inbox(keyring: Path, paths: list[Path], output: Path, require_two: bool) -> None:
    require_two = require_two or minimum_signers(keyring) == 2
    if not 1 <= len(paths) <= MAX_PACKAGES:
        raise Hold("choose 1–12 source-only portable packages")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise Hold("output must be new and absolute, not an existing/symlink directory")
    install = _import_original_install()
    install.owner_dir(output.parent)
    names = [str(p) for p in paths]
    if len(set(names)) != len(names):
        raise Hold("duplicate original bundle path is ambiguous")
    stage = output.parent / (".lightup-custody-inbox-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    records: list[dict] = []
    seen_hashes: set[str] = set()
    try:
        for ordinal, path in enumerate(paths, 1):
            # Capture original untrusted transport bytes once and do not re-open
            # the mutable caller-selected path after this snapshot.
            transport = _regular_file_bytes(path, MAX_PORTABLE_BYTES)
            raw_entry = stage / f"bundle-{ordinal:02d}.portable.zip"
            _write_new_private(raw_entry, transport)
            members = _unpack_bytes(raw_entry)
            archive_sha = hashlib.sha256(members[ARCHIVE_NAME]).hexdigest()
            if archive_sha in seen_hashes:
                raise Hold("duplicate signed original software archive in one inbox")
            seen_hashes.add(archive_sha)
            signers = _admit_signers(keyring, members, require_two)
            slot = f"slot-{ordinal:02d}"
            first = signers[0]["fingerprint"]
            second = signers[1]["fingerprint"] if len(signers) == 2 else None
            # Reuse existing two signature gates + original source owner receiver.
            receive(raw_entry, first, stage / slot, second_trusted_fingerprint=second)
            records.append({
                "ordinal": ordinal, "slot": slot,
                "original_zip_sha256": archive_sha,
                "original_zip_bytes": len(members[ARCHIVE_NAME]),
                "signers": signers,
            })
        # Snapshot local key revocations again just before atomic publication.
        for record in records:
            for signer in record["signers"]:
                trusted(keyring, signer["fingerprint"])
        receipt = {
            "format": KIND,
            "disposition": "PRIVATE_HUMAN_REVIEW_ONLY",
            "source_owner_authenticated": False,
            "client_consent": False,
            "remediation_verified": False,
            "scan_authorized": False,
            "deployment_authorized": False,
            "human_go": False,
            "local_minimum_signers": 2 if require_two else 1,
            "entries": records,
        }
        _write_new_private(stage / "index.html", _html(records))
        _write_new_private(stage / "inbox.json", _canonical(receipt) + b"\n")
        install.exclusive_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: original source-bound offline software custody inbox:", output)
    print("Open local scriptless dashboard:", output / "index.html")
    print("CUSTODY IS NOT RELEASE: client/operator authority, CI and HUMAN GO remain HOLD.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--bundle", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--require-two-signers", action="store_true")
    args = parser.parse_args()
    try:
        inbox(args.keyring, args.bundle, args.output_dir, args.require_two_signers)
    except (OSError, ValueError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
