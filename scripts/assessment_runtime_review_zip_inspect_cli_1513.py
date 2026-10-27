"""Inspect the integrity of a received private LightUp HUMAN ZIP without source JSON.

This is a bounded offline *internal consistency* read. ZIP bytes and embedded
hashes may both be forged, so only an independently authenticated ZIP SHA-256
can establish external byte identity. Neither case grants any authority.
No archive entry is ever extracted, executed, opened in a browser or written.
"""
from __future__ import annotations

import json
import sys
from hashlib import sha256
from hmac import compare_digest
from io import BytesIO
from zipfile import BadZipFile, ZIP_STORED, ZipFile

import assessment_runtime_report_html_1513 as reports
from assessment_runtime_review_bundle_inspect_cli_1513 import (
    _canonical_sha256, _pairs_without_duplicates, _read_private_bundle,
    _reject_constant,
)

_MAX_BYTES = 4 * 1024 * 1024
_NAMES = ("manifest.json", "human-review.html", "human-review.csv", "human-review.md")
_FALSE_AUTHORITY = (
    "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
    "source_provenance_authenticated",
)
_MANIFEST_FIELDS = frozenset((
    "schema_version", "package_type", "source_status", "input_admitted",
    "received_json_sha256", "artifacts", *_FALSE_AUTHORITY,
))


def _hold_receipt() -> dict:
    return {
        "schema_version": 1,
        "internal_zip_consistent": False,
        "source_status": "HOLD",
        "notice": "input_hold",
        "received_json_sha256": None,
        "received_zip_sha256": None,
        "verified_artifact_count": 0,
        **{flag: False for flag in _FALSE_AUTHORITY},
    }


def _canonical_lower_digest(value) -> bool:
    return _canonical_sha256(value) and value == value.lower()


def inspect_offline_human_zip(
    zip_path: str, *, expected_zip_sha256: str | None = None,
) -> dict:
    """Check four canonical stored members and all internal hashes, fail closed.

    Internal hashes are attacker-rewriteable. An independently obtained ZIP
    digest is mandatory for any authenticated byte-identity claim; it never
    authenticates the source facts, consent or scope.
    """
    hold = _hold_receipt()
    if expected_zip_sha256 is not None and not _canonical_sha256(
        expected_zip_sha256,
    ):
        return hold
    try:
        raw = _read_private_bundle(zip_path)
        zip_digest = sha256(raw).hexdigest()
        if expected_zip_sha256 is not None and not compare_digest(
            zip_digest, expected_zip_sha256.lower(),
        ):
            return hold
        with ZipFile(BytesIO(raw), mode="r") as archive:
            infos = archive.infolist()
            if (
                archive.comment
                or tuple(info.filename for info in infos) != _NAMES
                or any(
                    info.file_size <= 0
                    or info.file_size > _MAX_BYTES
                    or info.compress_type != ZIP_STORED
                    or info.flag_bits != 0
                    or info.extra or info.comment
                    or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.create_system != 3
                    or info.external_attr != (0o100600 << 16)
                    for info in infos
                )
                or sum(info.file_size for info in infos) > _MAX_BYTES
            ):
                return hold
            # ZIP_STORED + a bounded archive caps all bytes read into memory.
            # ZipFile validates member lengths and CRC; no extraction to disk.
            entries = tuple(
                (name, archive.read(name)) for name in _NAMES
            )
        # Also reject duplicate headers, trailing bytes, alternative metadata,
        # concatenated payloads and any noncanonical ZIP serialization.
        if not compare_digest(
            raw, reports._pack_fixed_handoff_zip_entries(entries),
        ):
            return hold
        manifest_bytes = entries[0][1]
        if len(manifest_bytes) > 4096:
            return hold
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
        if (
            type(manifest) is not dict
            or set(manifest) != _MANIFEST_FIELDS
            or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["package_type"] != "lightup_offline_human_handoff"
            or manifest["input_admitted"] is not True
            or manifest["source_status"] not in ("HOLD", "REVIEW_ONLY")
            or not _canonical_lower_digest(manifest["received_json_sha256"])
            or any(manifest[flag] is not False for flag in _FALSE_AUTHORITY)
            or type(manifest["artifacts"]) is not list
            or len(manifest["artifacts"]) != 3
            or manifest_bytes != (
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
        ):
            return hold
        for entry, (name, payload) in zip(manifest["artifacts"], entries[1:]):
            if (
                type(entry) is not dict
                or set(entry) != {"name", "sha256"}
                or entry["name"] != name
                or not _canonical_lower_digest(entry["sha256"])
                or not compare_digest(
                    sha256(payload).hexdigest(), entry["sha256"],
                )
            ):
                return hold
        return {
            **hold,
            "internal_zip_consistent": True,
            "source_status": manifest["source_status"],
            "notice": "internal_hashes_only_unauthenticated",
            "received_json_sha256": manifest["received_json_sha256"],
            "received_zip_sha256": zip_digest,
            "verified_artifact_count": 3,
        }
    except (
        BadZipFile, EOFError, OSError, RuntimeError, TypeError, ValueError,
        KeyError, OverflowError, UnicodeError,
    ):
        return hold


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    receipt = _hold_receipt()
    if len(args) == 1 and type(args[0]) is str:
        receipt = inspect_offline_human_zip(args[0])
    elif (
        len(args) == 3
        and args[0] == "--expected-zip-sha256"
        and _canonical_sha256(args[1])
    ):
        receipt = inspect_offline_human_zip(
            args[2], expected_zip_sha256=args[1],
        )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return (
        2 if receipt["internal_zip_consistent"]
        and receipt["source_status"] == "REVIEW_ONLY" else 3
    )


if __name__ == "__main__":
    raise SystemExit(main())
