#!/usr/bin/env python3
"""PRIVATE signed HUMAN reply inbox: exact source + 2–8 admitted original replies.

Every signed courier requires a separately provided trusted public fingerprint.
An original-source-native offline comparator is invoked only after ALL signed
encrypted inputs match exactly the same original selected .luhq bytes.
No automated consensus, client authority, remediation or grants.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

from signed_courier import (
    Hold, ROOT, MAX_COURIER, canonical, admit_courier, owner_dir,
    private_bytes, publish_new,
)
sys.path.insert(0, str(ROOT / "remediation-human-replies"))
import reconcile  # original author code, unchanged
sys.path.insert(0, str(ROOT / "remediation-integrated-workspace"))
import install  # original atomic exclusive publication

MAX_RECEIVED = 8
KIND = "lightup.private_encrypted_human_signed_reply_inbox.v1"


def _page(records: list[dict]) -> bytes:
    rows = []
    for row in records:
        rows.extend((
            "<tr><td>", str(row["ordinal"]), "</td><td><code>",
            html.escape(row["signer_fingerprint"]), "</code></td><td><code>",
            html.escape(row["response_sha256"]), "</code></td></tr>",
        ))
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
        "style-src 'unsafe-inline';base-uri 'none';form-action 'none'\">"
        "<title>PRIVATE source-bound HUMAN reply signatures · REVIEW_ONLY</title>"
        "<style>body{font:16px system-ui;background:#112036;color:#f1f5ff;"
        "max-width:1100px;margin:2rem auto;padding:1rem}a{color:#aadfff}"
        "aside{padding:1rem;border:1px solid #c8a66c;border-radius:9px}"
        "table{border-collapse:collapse;width:100%}td,th{padding:.7rem;"
        "border:1px solid #526481;text-align:left;word-break:break-all}"
        "code{font-size:.8rem}</style></head><body>"
        "<h1>LightUp · PRIVATE signed HUMAN reply inbox</h1>"
        "<aside><strong>INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD</strong>"
        "<p>Signatures only bind exact encrypted original files to possessors of "
        "independently pre-trusted public keys. They do NOT authenticate actual "
        "persons, original client/source, verified fixes, consent, security "
        "review, execution, scanner, grant, deployment or HUMAN GO.</p></aside>"
        "<p>Original selected HUMAN source: identical encrypted bytes in every "
        "signed courier. Each reply underwent the unchanged original source+"
        "password admission after cryptographic validation. File slots are NOT "
        "independent people, chronology, truth, agreement or authorization.</p>"
        "<p><a href='original-human-comparison/index.html'>"
        "Open original PRIVATE HUMAN reply comparison</a></p>"
        "<h2>Local encrypted-file custody (PRIVATE)</h2>"
        "<table><thead><tr><th>Input slot</th><th>Trusted key fingerprint</th>"
        "<th>Exact encrypted reply SHA-256</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table><p>Source SHA references and HUMAN replies may be "
        "sensitive. The entire private inbox is mode 0700/0600 and never "
        "auto-sent or published. No network or browser scripting.</p></body></html>"
    ).encode("utf-8")


def receive_many(selected: list[tuple[Path, str]], output: Path) -> None:
    if not 2 <= len(selected) <= MAX_RECEIVED:
        raise Hold("choose 2–8 original encrypted HUMAN signed couriers")
    if not sys.stdin.isatty():
        raise Hold("unchanged original encrypted HUMAN admission requires a private terminal")
    if not output.is_absolute() or output.exists() or output.is_symlink() or ROOT in output.parents:
        raise Hold("output must be fresh private path outside original source checkout")
    owner_dir(output.parent)
    original_handoff: bytes | None = None
    records: list[dict] = []
    exact_ciphertext: set[str] = set()
    exact_couriers: set[str] = set()
    packages: list[tuple[Path, bytes]] = []
    stage = output.parent / (".lightup-signed-human-inbox-" + secrets.token_hex(12))
    stage.mkdir(mode=0o700)
    try:
        paths: list[Path] = []
        for ordinal, (courier_file, verified_fingerprint) in enumerate(selected, 1):
            source_bytes, reply_bytes, fingerprint, courier_bytes = admit_courier(
                courier_file, verified_fingerprint,
            )
            if original_handoff is None:
                original_handoff = source_bytes
                publish_new(stage / "original-selected.luhq", original_handoff)
            elif source_bytes != original_handoff:
                raise Hold("different source-redacted HUMAN selection; no cross-source comparison")
            source_digest = hashlib.sha256(reply_bytes).hexdigest()
            if source_digest in exact_ciphertext:
                raise Hold("same exact encrypted HUMAN reply repeated in signed couriers")
            exact_ciphertext.add(source_digest)
            courier_digest = hashlib.sha256(courier_bytes).hexdigest()
            if courier_digest in exact_couriers:
                raise Hold("duplicate signed original courier")
            exact_couriers.add(courier_digest)
            target = stage / f"reply-{ordinal:02d}.luhr"
            publish_new(target, reply_bytes)
            paths.append(target)
            packages.append((courier_file, courier_bytes))
            records.append({
                "ordinal": ordinal,
                "signer_fingerprint": fingerprint,
                "response_sha256": source_digest,
            })
        if original_handoff is None:
            raise Hold("source-redacted HUMAN selection absent")
        # Delegates ALL semantic checks to original owner, including 2 separate
        # HUMAN passwords and exact ordinal/source-membership checks. Original
        # output is published locally inside our currently unpublished stage.
        reconcile.compare(stage / "original-selected.luhq", paths, stage / "original-human-comparison")
        for courier_file, old_bytes in packages:
            if private_bytes(courier_file, MAX_COURIER) != old_bytes:
                raise Hold("signed encrypted reply courier mutated during original admission")
        publish_new(stage / "index.html", _page(records))
        receipt = {
            "kind": KIND, "version": 1, "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
            "authority_granted": False, "consent_verified": False,
            "remediation_verified": False, "source_authenticated": False,
            "independent_humans_verified": False,
            "original_encrypted_handoff_sha256": hashlib.sha256(original_handoff).hexdigest(),
            "entries": records,
        }
        publish_new(stage / "private-custody.json", canonical(receipt) + b"\n")
        install.exclusive_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: complete PRIVATE signed HUMAN reply comparison:", output / "index.html")
    print("Signatures are byte custody only: NO verified unique humans, consent, fixes, scan or release.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signed-courier", action="append", required=True, type=Path)
    parser.add_argument("--trusted-fingerprint", action="append", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if len(args.signed_courier) != len(args.trusted_fingerprint):
            raise Hold("supply one independently trusted fingerprint PER signed private courier")
        receive_many(list(zip(args.signed_courier, args.trusted_fingerprint)), args.output_dir)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
