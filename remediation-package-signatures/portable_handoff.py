#!/usr/bin/env python3
"""One-file portable offline software custody bundle; REVIEW_ONLY, never release.

Bundle contains only original software-only.zip, unsigned tiny receipt and
public verification key. The public key MUST be independently trusted by
its SHA-256 SPKI fingerprint; bundled public keys are never trust anchors.
"""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import sys
import tempfile
import zipfile

from offline_signatures import (
    Hold,
    MAX_ARCHIVE_BYTES,
    MAX_KEY_BYTES,
    MAX_RECEIPT_BYTES,
    _regular_file_bytes,
    _write_new_private,
    verify,
)
from verified_receive import receive as receive_original

ARCHIVE_NAME = "software-only.zip"
RECEIPT_NAME = "signature.lusig.json"
PUBLIC_NAME = "signer-public.pem"
REQUIRED = frozenset({ARCHIVE_NAME, RECEIPT_NAME, PUBLIC_NAME})
BOUNDS = {
    ARCHIVE_NAME: MAX_ARCHIVE_BYTES,
    RECEIPT_NAME: MAX_RECEIPT_BYTES,
    PUBLIC_NAME: MAX_KEY_BYTES,
}
MAX_PORTABLE_BYTES = MAX_ARCHIVE_BYTES + 1024 * 1024


def _zip_member(name: str, data: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = 0o100600 << 16
    info.compress_type = zipfile.ZIP_STORED
    return info, data


def pack(
    archive: Path,
    receipt: Path,
    trusted_public_key: Path,
    trusted_fingerprint: str,
    output_bundle: Path,
) -> None:
    # Verify first; carry EXACT signed ZIP bytes, not a later read of archive.
    signed_bytes = verify(archive, receipt, trusted_public_key, trusted_fingerprint)
    receipt_bytes = _regular_file_bytes(receipt, MAX_RECEIPT_BYTES)
    public_bytes = _regular_file_bytes(trusted_public_key, MAX_KEY_BYTES)
    payloads = {
        ARCHIVE_NAME: signed_bytes,
        RECEIPT_NAME: receipt_bytes,
        PUBLIC_NAME: public_bytes,
    }
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, mode="w", compression=zipfile.ZIP_STORED) as z:
        for name in sorted(REQUIRED):
            info, data = _zip_member(name, payloads[name])
            z.writestr(info, data)
    raw = payload.getvalue()
    if len(raw) > MAX_PORTABLE_BYTES:
        raise Hold("portable archive exceeds bounded software-only limit")
    _write_new_private(output_bundle, raw)
    print("REVIEW_ONLY: single-file software + signature + public-key bundle published.")
    print("The receiver MUST independently authenticate the public-key fingerprint.")
    print("This software-only artifact never contains client evidence, authorization or HUMAN GO.")


def _unpack_bytes(bundle: Path) -> dict[str, bytes]:
    raw = _regular_file_bytes(bundle, MAX_PORTABLE_BYTES)
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as zipped:
            entries = zipped.infolist()
            if (
                len(entries) != 3
                or frozenset(e.filename for e in entries) != REQUIRED
                or len({e.filename for e in entries}) != 3
                or zipped.comment
            ):
                raise Hold("portable inventory is missing, extra or duplicated")
            output: dict[str, bytes] = {}
            for entry in entries:
                allowed = BOUNDS[entry.filename]
                if (
                    entry.is_dir()
                    or entry.compress_type != zipfile.ZIP_STORED
                    or entry.flag_bits & 1
                    or entry.file_size < 1
                    or entry.file_size > allowed
                    or entry.compress_size != entry.file_size
                    or (entry.external_attr >> 16) not in (0, 0o100600)
                ):
                    raise Hold("portable member has unsafe mode, type, compression or size")
                with zipped.open(entry, "r") as stream:
                    data = stream.read(allowed + 1)
                    if len(data) != entry.file_size or stream.read(1):
                        raise Hold("portable member declared byte size differs")
                output[entry.filename] = data
            return output
    except (zipfile.BadZipFile, zipfile.LargeZipFile):
        raise Hold("not a valid bounded software bundle") from None


def receive(
    bundle: Path,
    independently_trusted_fingerprint: str,
    output_dir: Path,
) -> None:
    if not output_dir.is_absolute() or output_dir.exists() or output_dir.is_symlink():
        raise Hold("recipient output must be a fresh absolute directory")
    # Entire untrusted transport ZIP admitted to memory before private temp
    # stage creation. Original native recipient remains the final source gate.
    members = _unpack_bytes(bundle)
    from pathlib import Path as _Path
    # Check owner-private parent with ORIGINAL source gate before writing files.
    original_path = _Path(__file__).resolve().parent.parent / "remediation-integrated-workspace"
    sys.path.insert(0, str(original_path))
    import install  # source owner, unchanged

    install.owner_dir(output_dir.parent)
    with tempfile.TemporaryDirectory(
        prefix=".lightup-portable-custody-", dir=str(output_dir.parent)
    ) as staging:
        stage = Path(staging)
        _write_new_private(stage / ARCHIVE_NAME, members[ARCHIVE_NAME])
        _write_new_private(stage / RECEIPT_NAME, members[RECEIPT_NAME])
        _write_new_private(stage / PUBLIC_NAME, members[PUBLIC_NAME])
        receive_original(
            stage / ARCHIVE_NAME,
            stage / RECEIPT_NAME,
            stage / PUBLIC_NAME,
            independently_trusted_fingerprint,
            output_dir,
        )
    print("REVIEW_ONLY: portable software received after trusted key + original source admission.")
    print("Untrusted bundled public key was NEVER automatically trusted.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("pack", help="produce one source-only portable bundle")
    create.add_argument("--archive", required=True, type=Path)
    create.add_argument("--receipt", required=True, type=Path)
    create.add_argument("--trusted-public-key", required=True, type=Path)
    create.add_argument("--trusted-fingerprint", required=True)
    create.add_argument("--output-bundle", required=True, type=Path)
    extract = sub.add_parser("receive", help="verify and receive original pinned software offline")
    extract.add_argument("--bundle", required=True, type=Path)
    extract.add_argument("--trusted-fingerprint", required=True)
    extract.add_argument("--output-dir", required=True, type=Path)
    options = parser.parse_args()
    try:
        if options.command == "pack":
            pack(
                options.archive, options.receipt, options.trusted_public_key,
                options.trusted_fingerprint, options.output_bundle,
            )
        else:
            receive(options.bundle, options.trusted_fingerprint, options.output_dir)
    except (OSError, ValueError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
