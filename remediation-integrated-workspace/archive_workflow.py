#!/usr/bin/env python3
"""One-command local source-free archive intake -> HUMAN recipient workroom.

Only canonical original source-free .luhz software handoffs, NOT original
client evidence; original native receivers and human products are reused.
No upload/network, target, scanner, grant, consent claim, auto-remediation or
source-owner writeback. This command never authorizes cross-tenant disclosure.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import sys
import zipfile

import install
import portable_cockpit
import encrypted_cockpit
import workflow

review = workflow.review
workspace = workflow.workspace

WARNING = (
    "Private source-free HUMAN counts only. No sender signature, original client "
    "identity, matched cohort, authenticated time, consent, verified finding, "
    "fix, retest, grant, scanner or HUMAN GO. INCUBATE M3/M7 DRAFT/HOLD."
)

def require(condition: bool, explanation: str) -> None:
    review.require(condition, explanation)

def build(archives: list[Path], dest: Path, encrypted: bool = False, unsigned_receipt: Path | None = None) -> None:
    require(1 <= len(archives) <= 12 and len(set(archives)) == len(archives),
            "Select 1 to 12 distinct original source-free archive files")
    require(dest.is_absolute() and dest.parent == dest.parent.resolve(strict=True)
            and not dest.exists() and not dest.is_symlink(),
            "New output must be a literal absolute PRIVATE directory")
    install.owner_dir(dest.parent)
    # Optional byte custody only: an UNSIGNED receipt is never consent.
    expected_slots = None
    receipt_raw = None
    if unsigned_receipt is not None:
        import packet_fingerprint
        require(unsigned_receipt not in archives and unsigned_receipt != dest,
                "Original PRIVATE unsigned receipt must be separate")
        receipt_raw = packet_fingerprint.receipt_bytes(unsigned_receipt)
        expected_slots = packet_fingerprint.load_receipt(unsigned_receipt)["files"]
        require(len(archives) == len(expected_slots),
                "Unsigned original receipt slot count mismatch")
    seen = set()
    original_bytes = []
    for archive in archives:
        require(archive.is_absolute()
                and archive.parent == archive.parent.resolve(strict=True)
                and archive != dest and dest not in archive.parents
                and archive.parent != dest,
                "Archive cannot be inside recipient folder or an alias")
        install.owner_dir(archive.parent)
        raw = (encrypted_cockpit.private_envelope(archive) if encrypted
               else install.read_owner_file(archive))
        require(0 < len(raw) <= (encrypted_cockpit.MAX_ENVELOPE if encrypted
                                else portable_cockpit.MAX_ZIP),
                "Private source-free archive exceeds original transport limit")
        if expected_slots is not None:
            slot = expected_slots[len(original_bytes)]
            require(slot["bytes"] == len(raw)
                    and slot["sha256"] == hashlib.sha256(raw).hexdigest(),
                    "Received source-free packet differs from UNSIGNED receipt")
        signature = hashlib.sha256(raw).digest()
        require(signature not in seen,
                "The same exact source-free archive cannot be two HUMAN revisions")
        seen.add(signature)
        original_bytes.append(raw)
    stage, stage_identity = install.create_private_stage(dest.parent, ".lightup-receiver-")
    try:
        received = []
        for ordinal, archive in enumerate(archives, 1):
            target = stage / f"received-{ordinal:02d}"
            if encrypted:
                encrypted_cockpit.decrypt(archive, target)
            else:
                portable_cockpit.unpack(archive, target)
            received.append(target)
        # Use the existing complete native original recipient product.
        # Its own privately staged publication occurs only inside our stage.
        workflow.recipient_start(received, stage / "human-review")
        for archive, old in zip(archives, original_bytes):
            require((encrypted_cockpit.private_envelope(archive) if encrypted
                     else install.read_owner_file(archive)) == old,
                    "Original transferred source-free package changed during intake")
        portal = workflow.page(
            "PRIVATE source-free HUMAN archive intake",
            [
                ("Open native source-free HUMAN reviewer",
                 "human-review/index.html",
                 "Exactly the admitted original anonymous packets; one => single HUMAN reviewer, "
                 "two => original comparison, three to twelve => source-free ordinal series."),
                ("Read the first received canonical Cockpit",
                 "received-01/index.html",
                 "Full original PRIVATE source-free native Cockpit. No original client records."),
            ],
            "PRIVATE operator-only transfer bundle. Its original source-free counts and "
            "local HUMAN notes can still be sensitive. Entire source folder MUST NOT "
            "be shared without independent recipient authorization. Unsigned ZIP "
            "checksums are not actual sender signatures or consent."
        )
        install.write_file(stage / "index.html", portal)
        stats = {
            "kind": "lightup.private_sourcefree_archive_human_intake",
            "schema_version": 1,
            "disposition": "HUMAN_REVIEW_ONLY_DRAFT_HOLD",
            "authority_granted": False,
            "consent_verified": False,
            "remediation_verified": False,
            "authenticated_sender": False,
            "selected_archives": len(received),
            "encrypted_transport_used": encrypted,
            "original_cohort_identity": "UNKNOWN_NOT_MATCHED",
            "archive_order": "OPERATOR_SELECTED_NOT_AUTHENTICATED_TIME",
            "warning": WARNING,
        }
        install.write_file(stage / "private-summary.json", install.canonical(stats))
        if receipt_raw is not None:
            import packet_fingerprint
            require(packet_fingerprint.receipt_bytes(unsigned_receipt) == receipt_raw
                    and packet_fingerprint.load_receipt(unsigned_receipt)["files"] == expected_slots,
                    "Original UNSIGNED receipt changed during recipient intake")
        require(not dest.exists(), "Recipient output appeared before final private publication")
        install.exclusive_publish(stage, dest, expected_identity=stage_identity)
    finally:
        # Never remove a substituted stage under the private handoff path.
        install.cleanup_private_stage(stage, stage_identity)
    print("REVIEW_ONLY: native PRIVATE source-free archive intake:", dest)
    print("Original source-free Cockpit packets:", len(archives))
    print("Open offline:", dest / "index.html")
    print("No actual sender authentication, client consent or remediation authority.")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Receive 1-12 original native private source-free Cockpit ZIPs into HUMAN reviewer"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", action="append", type=Path,
                        help="UNENCRYPTED .luhz 0600 source-free archive; repeat 1-12")
    source.add_argument("--encrypted-archive", action="append", type=Path,
                        help="PASSPHRASE encrypted .luhx archive; repeat 1-12; interactive prompt")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="NEW absolute original owner-private 0700 recipient folder")
    parser.add_argument("--receipt", type=Path, default=None,
                        help="Optional ORIGINAL private UNSIGNED source-free SHA-256 receipt, match before decrypt and final publication")
    args = parser.parse_args()
    try:
        build(args.encrypted_archive or args.archive, args.output_dir,
              encrypted=args.encrypted_archive is not None, unsigned_receipt=args.receipt)
        return 2
    except (review.Hold, install.Hold, OSError, ValueError, TypeError, KeyError,
            RuntimeError, EOFError, zipfile.BadZipFile) as exc:
        print("HOLD: PRIVATE source-free HUMAN intake refused: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
