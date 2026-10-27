"""Verify a received LightUp HUMAN artifact against the exact offline JSON bytes.

This is a local read-only byte equality check, not an attestation, a signature,
source authorization, evidence validation, cost approval or release clearance.
No original record IDs, paths, targets, questions or metrics are ever printed.
"""
from __future__ import annotations

import json
import sys
from hashlib import sha256
from hmac import compare_digest

import assessment_runtime_report_html_1513 as reports
from assessment_runtime_review_bundle_inspect_cli_1513 import (
    _canonical_sha256, _read_private_bundle, _validated_review_bundle_packet,
)


_RENDERERS = {
    "bundle-html": reports._render_review_bundle_packet_html,
    "bundle-csv": reports._render_review_bundle_packet_csv,
    "bundle-md": reports._render_review_bundle_packet_markdown,
}


def _hold_receipt() -> dict:
    """Source-free HOLD even when just one artifact fails admission."""
    return {
        "schema_version": 1,
        "render_matches": False,
        "source_status": "HOLD",
        "notice": "input_hold",
        "received_json_sha256": None,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_provenance_authenticated": False,
    }


def verify_rendered_human_artifact(
    source_path: str,
    artifact_path: str,
    *,
    output_format: str,
    expected_sha256: str | None = None,
) -> dict:
    """Re-render one complete admitted bundle; compare all bytes, fail closed.

    Both paths use the original symlink-free, race-hardened inode-pinned read.
    The source hash is emitted only on a complete structural/byte match.
    A matching pair can still be forged; use an independently obtained source
    SHA256 to establish source byte equality before any human review.
    """
    failure = _hold_receipt()
    if output_format not in _RENDERERS:
        return failure
    if expected_sha256 is not None and not _canonical_sha256(expected_sha256):
        return failure
    try:
        source = _read_private_bundle(source_path)
        source_digest = sha256(source).hexdigest()
        if expected_sha256 is not None and not compare_digest(
            source_digest, expected_sha256.lower(),
        ):
            return failure
        packet = _validated_review_bundle_packet(source)
        if packet is None or packet["input_admitted"] is not True:
            return failure
        rendered = _RENDERERS[output_format](
            packet, source_sha256=source_digest,
        ).encode("utf-8")
        # Both artifacts are bounded regular local files. Exact render bytes,
        # not just the embedded source digest, must match after any transfer.
        received = _read_private_bundle(artifact_path)
        if not compare_digest(rendered, received):
            return failure
        return {
            **failure,
            "render_matches": True,
            "source_status": packet["source_status"],
            "notice": "byte_match_only_unauthenticated",
            "received_json_sha256": source_digest,
        }
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return failure


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    output_format = None
    expected_sha256 = None
    seen: set[str] = set()
    cursor = 0
    valid = True
    # Unknown/duplicate flags, missing values and extra positional inputs
    # all become the same source-free HOLD; never echo either local path.
    while cursor < len(args) and args[cursor] in ("--format", "--expected-sha256"):
        option = args[cursor]
        if option in seen or cursor + 1 >= len(args):
            valid = False
            break
        seen.add(option)
        value = args[cursor + 1]
        if option == "--format":
            if value not in _RENDERERS:
                valid = False
                break
            output_format = value
        elif not _canonical_sha256(value):
            valid = False
            break
        else:
            expected_sha256 = value
        cursor += 2

    receipt = _hold_receipt()
    if valid and output_format is not None and len(args) - cursor == 2:
        receipt = verify_rendered_human_artifact(
            args[cursor], args[cursor + 1],
            output_format=output_format, expected_sha256=expected_sha256,
        )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return (
        2 if receipt["render_matches"]
        and receipt["source_status"] == "REVIEW_ONLY" else 3
    )


if __name__ == "__main__":
    raise SystemExit(main())
