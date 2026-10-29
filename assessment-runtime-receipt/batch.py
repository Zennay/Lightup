"""Bounded, all-or-nothing offline batch receipt for private laboratory JSON.

This tool checks local byte custody only; it cannot validate a source, consent,
assessment, finding, grant, deployment, or authorization.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys

from receipt import (
    FALSE_FLAGS,
    _finite_float,
    _read_private_regular,
    _reject_constant,
    _unique_pairs,
    inspect,
)

FORMAT = "lightup-offline-receipt-batch-v2"
RECEIPT_FORMAT = "lightup-offline-receipt-batch-receipt-v2"
MIN_SOURCES = 2
MAX_SOURCES = 8


def _hold():
    return {
        "receipt_format": RECEIPT_FORMAT,
        "status": "HOLD",
        "manifest_authenticated": False,
        "source_authenticated": False,
        "source_schema_verified": False,
        "byte_expectations_match": False,
        **{flag: False for flag in FALSE_FLAGS},
    }


def _digest_ok(value):
    return (
        type(value) is str
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def inspect_batch(manifest_path, expected_manifest_sha256):
    """Admit 2–8 original private files or disclose no source-level details.

    Manifest expectations and the independently supplied manifest hash establish
    byte equality only. They do not authenticate the person holding either.
    The manifest path and every source path must be canonical absolute paths.
    Reads are sequential, not an atomic snapshot of changing files.
    """
    result = _hold()
    try:
        manifest_name = os.fspath(manifest_path)
        if type(manifest_name) is not str or not os.path.isabs(manifest_name):
            return result
        if not _digest_ok(expected_manifest_sha256):
            return result
        data = _read_private_regular(manifest_name)
        manifest_digest = hashlib.sha256(data).hexdigest()
        if not secrets.compare_digest(manifest_digest, expected_manifest_sha256):
            return result
        manifest = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        if type(manifest) is not dict or set(manifest) != {"format", "sources"}:
            return result
        if manifest["format"] != FORMAT:
            return result
        sources = manifest["sources"]
        if type(sources) is not list or not MIN_SOURCES <= len(sources) <= MAX_SOURCES:
            return result

        seen_paths = set()
        seen_digests = {manifest_digest}
        items = []
        commitment = hashlib.sha256(b"LightUp offline batch receipt v2\0")
        commitment.update(bytes.fromhex(manifest_digest))
        total_bytes = 0
        for ordinal, entry in enumerate(sources, 1):
            if type(entry) is not dict or set(entry) != {"path", "expected_sha256"}:
                return result
            path = entry["path"]
            expected = entry["expected_sha256"]
            if (
                type(path) is not str or not path.startswith("/")
                or len(path) > 4096 or path in seen_paths
                or not _digest_ok(expected)
            ):
                return result
            seen_paths.add(path)
            # Single-source admission repeats the no-follow, private-owner,
            # single-hardlink, stable-descriptor and strict-JSON checks.
            source = inspect(path, expected)
            if source.get("byte_identity_matches") is not True:
                return result
            digest = source["source_sha256"]
            if digest in seen_digests:
                return result
            seen_digests.add(digest)
            item = {
                "ordinal": ordinal,
                "source_reported_status": source["source_reported_status"],
                "byte_count": source["byte_count"],
                "source_sha256": digest,
            }
            items.append(item)
            total_bytes += item["byte_count"]
            # Explicit ordinal and length fields avoid ambiguous concatenation.
            commitment.update(ordinal.to_bytes(2, "big"))
            commitment.update(item["byte_count"].to_bytes(8, "big"))
            commitment.update(bytes.fromhex(digest))
            commitment.update(item["source_reported_status"].encode("ascii"))
            commitment.update(b"\0")

        result.update(
            byte_expectations_match=True,
            sources_admitted=len(items),
            total_bytes=total_bytes,
            manifest_sha256=manifest_digest,
            ordered_receipt_sha256=commitment.hexdigest(),
            items=items,
        )
    except (OSError, ValueError, UnicodeError, TypeError,
            RecursionError, OverflowError, KeyError):
        return _hold()
    return result


if __name__ == "__main__":
    manifest = sys.argv[1] if len(sys.argv) == 3 else ""
    expectation = sys.argv[2] if len(sys.argv) == 3 else None
    print(json.dumps(inspect_batch(manifest, expectation), sort_keys=True))
    raise SystemExit(3)
