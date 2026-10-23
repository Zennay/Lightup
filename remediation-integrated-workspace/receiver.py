#!/usr/bin/env python3
"""Fail-closed, software-only offline LightUp recipient. Never authenticates sender."""
from __future__ import annotations
import hmac
from pathlib import Path
import secrets

import install as suite

# One exact source of truth for builder and receiver file inventory.
TOOLS = frozenset(suite.INTEGRATED_TOOLS)

def admit_archive(archive: Path,
                  expected_sha256_file: Path | None = None
                  ) -> tuple[bytes, bytes, dict, dict[str, bytes]]:
    """Read and validate original software bytes without extracting or writing."""
    suite.owner_dir(archive.parent)
    raw = suite.read_owner_file(archive, ceiling=suite.MAX_TOTAL)
    suite.require(0 < len(raw) <= suite.MAX_TOTAL, "Oversized incoming software ZIP")
    if expected_sha256_file is not None:
        suite.require(expected_sha256_file != archive and
                      expected_sha256_file != suite.ROOT and
                      suite.ROOT not in expected_sha256_file.parents,
                      "Expected transfer fingerprint must be separate from source and ZIP")
        # The operator must obtain these original 65 bytes by a separately
        # trusted procedure. This comparison alone does not authenticate the
        # owner, channel, client or operator.
        fingerprint = suite.read_owner_file(expected_sha256_file, ceiling=65)
        suite.require(len(fingerprint) == 65
                      and fingerprint[-1:] == b"\n"
                      and all(x in b"0123456789abcdef" for x in fingerprint[:64]),
                      "Expected transfer checksum must be 64 lowercase hex digits and LF")
        suite.require(hmac.compare_digest(fingerprint[:64],
                                          suite.digest(raw).encode("ascii")),
                      "Software ZIP differs from separately supplied exact-byte checksum")
    lock_bytes, lock = suite.catalog()
    expected = set(lock["files"]) | set(TOOLS) | {"source-lock.json", "index.html", "operator.html"}
    # Source names, complete ZIP layout, original pinned files and all current
    # integration tools must match before any recipient side effects.
    files = suite.unpack_native_archive(raw, expected)
    import operator_console
    suite.require(files["source-lock.json"] == lock_bytes
                  and files["index.html"] == suite.home()
                  and files["operator.html"] == operator_console.render(),
                  "Incoming source/portal/operator studio mismatch")
    for name, desc in lock["files"].items():
        suite.require(len(files[name]) == desc["bytes"]
                      and suite.digest(files[name]) == desc["sha256"],
                      "Unpinned source content in offline software")
    for name in TOOLS:
        suite.require(files[name] == suite.read_checkout_source(suite.ROOT / name),
                      "Installer or receiver version differs from source release")
    suite.require(suite.read_checkout_source(suite.LOCK, 350_000) == lock_bytes,
                  "Pinned original source inventory changed during admission")
    suite.require(suite.read_owner_file(archive, ceiling=suite.MAX_TOTAL) == raw,
                  "Received software archive changed during admission")
    return raw, lock_bytes, lock, files



def fingerprint_archive(archive: Path, output_file: Path) -> None:
    """Publish a PRIVATE 0600 65-byte software checksum, not a sender proof.

    Reuse the original full software admission rather than hashing arbitrary
    bytes and giving them the appearance of a locally verified distribution.
    The operator alone controls whether and how this receipt is disclosed.
    """
    raw, _, _, _ = admit_archive(archive)
    suite.require(output_file.is_absolute() and
                  output_file.parent == output_file.parent.resolve(strict=True)
                  and not output_file.exists() and not output_file.is_symlink()
                  and output_file != archive
                  and archive.parent not in output_file.parents
                  and output_file != suite.ROOT
                  and suite.ROOT not in output_file.parents,
                  "Choose a fresh separate private checksum file outside software and source")
    suite.owner_dir(output_file.parent)
    payload = (suite.digest(raw) + "\n").encode("ascii")
    stage = output_file.parent / (".lightup-software-hash-" + secrets.token_hex(12))
    try:
        suite.write_file(stage, payload)
        suite.require(suite.read_owner_file(archive, ceiling=suite.MAX_TOTAL) == raw,
                      "Software ZIP changed before private checksum publication")
        suite.exclusive_publish(stage, output_file)
    finally:
        # Clean only this known temporary checksum name relative to the
        # verified private directory, not via a replaceable absolute path.
        suite.cleanup_private_file_stage(stage)
    print("REVIEW_ONLY: original software fingerprint saved to PRIVATE file:", output_file)
    print("UNSIGNED SOFTWARE SHA256:", suite.digest(raw))
    print("Output is not producer identity, release approval, or permission to disclose.")


def inspect_archive(archive: Path, expected_sha256_file: Path | None = None) -> None:
    """Operator's side-effect-free pre-admission for an original private ZIP."""
    raw, _, lock, files = admit_archive(archive, expected_sha256_file)
    print(f"REVIEW_ONLY: native software-only ZIP admitted: {len(files)} files, "
          f"{len(lock['files'])} original pinned assets and {len(TOOLS)} integrated tools.")
    print("UNSIGNED SOFTWARE SHA256:", suite.digest(raw))
    print("ARCHIVE BYTES:", len(raw))
    if expected_sha256_file is not None:
        print("TRANSFER CHECKSUM PARITY: exact original ZIP bytes match operator-provided fingerprint.")
    print("No extraction, report creation, authenticated producer identity or permissions.")


def receive(archive: Path, destination: Path,
            expected_sha256_file: Path | None = None) -> None:
    raw, lock_bytes, lock, files = admit_archive(archive, expected_sha256_file)
    suite.require(destination.is_absolute() and not destination.exists()
                  and not destination.is_symlink()
                  and destination.parent == destination.parent.resolve(strict=True),
                  "Recipient destination must be fresh, literal and absolute")
    suite.owner_dir(destination.parent)
    suite.require(destination != suite.ROOT and suite.ROOT not in destination.parents
                  and destination not in suite.ROOT.parents
                  and archive != destination and destination not in archive.parents
                  and destination != archive.parent
                  and archive.parent not in destination.parents,
                  "Recipient output must be entirely outside the original software ZIP directory")
    stage = suite.create_private_stage(destination.parent, ".lightup-receiver-")
    try:
        entries = {}
        for name, data in sorted(files.items()):
            target = stage / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            suite.write_file(target, data)
            entries[name] = {"sha256": suite.digest(data), "bytes": len(data)}
        suite.write_file(stage / "software-only.zip", raw)
        entries["software-only.zip"] = {"sha256": suite.digest(raw), "bytes": len(raw)}
        receipt = {"kind": suite.KIND, "version": 1, "disposition": "HUMAN_ONLY_DRAFT_HOLD",
                   "authority_granted": False, "scan_authorized": False,
                   "verified_remediation": False, "client_consent": False,
                   "source_heads": lock["source_heads"], "files": entries,
                   "warning": suite.WARNING}
        suite.write_file(stage / "manifest.json", suite.canonical(receipt))
        suite.require(suite.read_checkout_source(suite.LOCK, 350_000) == lock_bytes,
                      "Pinned original source inventory changed during receiving")
        suite.require(suite.read_owner_file(archive, ceiling=suite.MAX_TOTAL) == raw,
                      "Received ZIP changed before private publication")
        if expected_sha256_file is not None:
            require_again = suite.read_owner_file(expected_sha256_file, ceiling=65)
            suite.require(require_again == (suite.digest(raw) + "\n").encode("ascii"),
                          "Expected transfer checksum changed before publication")
        # Validate the complete original staged suite and the stable received
        # ZIP against the same local checkout before any publication.
        suite.verify(stage, compare_checkout=True)
        suite.require(not destination.exists(), "Recipient destination unexpectedly appeared")
        suite.exclusive_publish(stage, destination)
    finally:
        suite.cleanup_private_stage(stage)
    print("REVIEW_ONLY: received original software to PRIVATE directory:", destination)
    print("Open offline:", destination / "index.html")
    print("UNSIGNED SOFTWARE SHA256:", suite.digest(raw))
    if expected_sha256_file is not None:
        print("TRANSFER CHECKSUM PARITY: independently supplied file bytes matched at admission and publication.")
    print("Unsigned local digests NEVER establish authenticated source, consent or HUMAN GO.")
