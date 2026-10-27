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
    "bundle-zip": reports._render_review_bundle_packet_zip,
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


def _verify_complete_artifact_set(
    source_path: str,
    artifacts: tuple[tuple[str, str], ...],
    *,
    expected_sha256: str | None = None,
) -> dict:
    """Admit the source once; re-render and verify every required artifact.

    A successful set receipt requires *every* complete output to match bytes
    from the same inode-pinned JSON read. Never expose partial success,
    per-format failure clues, identifiers or source content.
    """
    failure = _hold_receipt()
    if (
        not artifacts
        or any(fmt not in _RENDERERS for fmt, _ in artifacts)
        or len({fmt for fmt, _ in artifacts}) != len(artifacts)
        or (expected_sha256 is not None
            and not _canonical_sha256(expected_sha256))
    ):
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
        for output_format, artifact_path in artifacts:
            rendered = _RENDERERS[output_format](
                packet, source_sha256=source_digest,
            )
            # HTML/CSV/Markdown are text, but the fixed-entry ZIP is bytes.
            # Compare exact bytes without normalizing archive structure.
            if type(rendered) is str:
                rendered = rendered.encode("utf-8")
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


def verify_rendered_human_artifact(
    source_path: str,
    artifact_path: str,
    *,
    output_format: str,
    expected_sha256: str | None = None,
) -> dict:
    """Verify one complete HUMAN artifact, never source attestation."""
    return _verify_complete_artifact_set(
        source_path, ((output_format, artifact_path),),
        expected_sha256=expected_sha256,
    )


def verify_rendered_human_artifact_set(
    source_path: str,
    html_path: str,
    csv_path: str,
    markdown_path: str,
    *,
    expected_sha256: str | None = None,
) -> dict:
    """All-or-nothing HUMAN handoff: HTML, CSV and Markdown from one source."""
    return _verify_complete_artifact_set(
        source_path,
        (
            ("bundle-html", html_path),
            ("bundle-csv", csv_path),
            ("bundle-md", markdown_path),
        ),
        expected_sha256=expected_sha256,
    )


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
            if value not in (*_RENDERERS, "bundle-set"):
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
    if valid and output_format == "bundle-set" and len(args) - cursor == 4:
        receipt = verify_rendered_human_artifact_set(
            args[cursor], args[cursor + 1], args[cursor + 2],
            args[cursor + 3], expected_sha256=expected_sha256,
        )
    elif valid and output_format in _RENDERERS and len(args) - cursor == 2:
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
