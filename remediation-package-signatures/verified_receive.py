#!/usr/bin/env python3
"""Verified human-custody receive: trusted signature BEFORE native ZIP admission.

Only wraps the existing original source-bound offline software receiver.
Does not install the signer into the original suite or relax its DRAFT/HOLD.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
import sys

from offline_signatures import Hold, verify


def receive(
    archive: Path,
    receipt: Path,
    trusted_public_key: Path,
    trusted_fingerprint: str,
    fresh_output_dir: Path,
    secondary: tuple[Path, Path, str] | None = None,
) -> None:
    root = Path(__file__).resolve().parent.parent
    original = root / "remediation-integrated-workspace"
    if not (original / "install.py").is_file() or not (original / "receiver.py").is_file():
        raise Hold("original source-bound suite receiver is absent")
    # The output must be a new, literal, absolute directory; original enforces
    # owner-only parent and no-overwrite atomic publication as a separate gate.
    if not fresh_output_dir.is_absolute() or fresh_output_dir.exists() or fresh_output_dir.is_symlink():
        raise Hold("recipient output must be a fresh absolute directory")
    verified_archive_bytes = verify(archive, receipt, trusted_public_key, trusted_fingerprint)
    if secondary is not None:
        second_receipt, second_public_key, second_fingerprint = secondary
        if second_fingerprint == trusted_fingerprint:
            raise Hold("a second signature must use a distinct independently trusted key")
        second_archive_bytes = verify(
            archive, second_receipt, second_public_key, second_fingerprint,
        )
        if second_archive_bytes != verified_archive_bytes:
            raise Hold("two trusted signatures must bind exactly the same archive bytes")
        print("REVIEW_ONLY: two distinct trusted Ed25519 key fingerprints matched.")
    sys.path.insert(0, str(original))
    import receiver  # original source-owner's native ZIP admission and publication
    import install  # original source-owner's source-lock / receipt inspector

    # Native receiver consumes the exact cryptographically captured bytes,
    # NOT a second open of the user-controlled source ZIP (TOCTOU boundary).
    # Important: native receiver publishes its destination *before* its
    # independent inspect. Receive into a private stage, inspect THERE, and
    # publish the final destination ONLY after both gates succeeded.
    install.owner_dir(fresh_output_dir.parent)
    if (
        fresh_output_dir == install.ROOT
        or install.ROOT in fresh_output_dir.parents
        or fresh_output_dir in install.ROOT.parents
    ):
        raise Hold("recipient must not overlap original source-owner checkout")
    with tempfile.TemporaryDirectory(
        prefix=".lightup-signed-admission-", dir=str(fresh_output_dir.parent)
    ) as temporary:
        parent = Path(temporary)
        captured = parent / "captured-software.zip"
        fd = os.open(
            captured, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as out:
                out.write(verified_archive_bytes)
                out.flush()
                os.fsync(out.fileno())
        finally:
            os.close(fd)
        unpublished = parent / "source-pinned-private-suite"
        receiver.receive(captured, unpublished)
        install.verify(unpublished)
        # Native Linux NO_REPLACE atomically publishes only complete source-
        # admitted software; failures leave no partially received final suite.
        install.exclusive_publish(unpublished, fresh_output_dir)
    print("SIGNED-CUSTODY + SOURCE-LOCK REVIEW_ONLY: PRIVATE local suite received.")
    print("Published new source-admitted recipient:", fresh_output_dir)
    print("Open offline original local suite:", fresh_output_dir / "index.html")
    print("This is NOT release approval, identity proof, consent, or permission to run scans.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--trusted-fingerprint", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--second-receipt", type=Path)
    parser.add_argument("--second-trusted-public-key", type=Path)
    parser.add_argument("--second-trusted-fingerprint")
    args = parser.parse_args()
    secondary_values = (
        args.second_receipt,
        args.second_trusted_public_key,
        args.second_trusted_fingerprint,
    )
    try:
        if any(value is not None for value in secondary_values) and not all(
            value is not None for value in secondary_values
        ):
            raise Hold("second signer requires receipt, public key AND trusted fingerprint")
        receive(
            args.archive,
            args.receipt,
            args.trusted_public_key,
            args.trusted_fingerprint,
            args.output_dir,
            secondary=secondary_values if all(value is not None for value in secondary_values) else None,
        )
    except (OSError, ValueError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2  # original receiver's REVIEW_ONLY status, not a release success.


if __name__ == "__main__":
    raise SystemExit(main())
