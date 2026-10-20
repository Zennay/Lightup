#!/usr/bin/env python3
"""Verified human-custody receive: trusted signature BEFORE native ZIP admission.

Only wraps the existing original source-bound offline software receiver.
Does not install the signer into the original suite or relax its DRAFT/HOLD.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from offline_signatures import Hold, verify


def receive(
    archive: Path,
    receipt: Path,
    trusted_public_key: Path,
    trusted_fingerprint: str,
    fresh_output_dir: Path,
) -> None:
    root = Path(__file__).resolve().parent.parent
    original = root / "remediation-integrated-workspace"
    if not (original / "install.py").is_file() or not (original / "receiver.py").is_file():
        raise Hold("original source-bound suite receiver is absent")
    # The output must be a new, literal, absolute directory; original enforces
    # owner-only parent and no-overwrite atomic publication as a separate gate.
    if not fresh_output_dir.is_absolute() or fresh_output_dir.exists() or fresh_output_dir.is_symlink():
        raise Hold("recipient output must be a fresh absolute directory")
    verify(archive, receipt, trusted_public_key, trusted_fingerprint)
    sys.path.insert(0, str(original))
    import receiver  # original source-owner's native ZIP admission and publication
    import install  # original source-owner's source-lock / receipt inspector

    receiver.receive(archive, fresh_output_dir)
    install.verify(fresh_output_dir)
    print("SIGNED-CUSTODY + SOURCE-LOCK REVIEW_ONLY: PRIVATE local suite received.")
    print("This is NOT release approval, identity proof, consent, or permission to run scans.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--trusted-fingerprint", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        receive(
            args.archive,
            args.receipt,
            args.trusted_public_key,
            args.trusted_fingerprint,
            args.output_dir,
        )
    except (OSError, ValueError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2  # original receiver's REVIEW_ONLY status, not a release success.


if __name__ == "__main__":
    raise SystemExit(main())
