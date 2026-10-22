#!/usr/bin/env python3
"""Export the original installed LightUp fixture ground truth without starting it."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

from native_bridge import (Hold, build_native_catalog, ensure, private_create,
                           private_ip, read_catalog)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
SOURCE_FILES = (
    ROOT / "src" / "lightup" / "labfixtures.py",
    ROOT / "src" / "lightup" / "workers" / "http_baseline.py",
)
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 512 * 1024



def read_stable_source(path: Path) -> bytes:
    """Hash a bounded regular source file without following links or accepting mid-read drift."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode):
            raise Hold("Original source inventory requires regular files")
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            ensure((path_stat.st_dev, path_stat.st_ino) == (before.st_dev, before.st_ino))
            ensure(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_SOURCE_BYTES)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(fd)
            identity_before = (
                before.st_dev, before.st_ino, before.st_size, before.st_mode,
                before.st_mtime_ns, before.st_ctime_ns,
            )
            identity_after = (
                after.st_dev, after.st_ino, after.st_size, after.st_mode,
                after.st_mtime_ns, after.st_ctime_ns,
            )
            ensure(len(raw) == before.st_size and identity_before == identity_after)
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise Hold("Original source inventory could not be admitted") from exc


def source_snapshot() -> dict[str, bytes]:
    """Return stable source bytes under repository-relative names; never export source code."""
    return {path.relative_to(ROOT).as_posix(): read_stable_source(path)
            for path in SOURCE_FILES}


def build_private_bundle(catalog_payload: bytes, source_bytes: dict[str, bytes]) -> bytes:
    """Package canonical private catalog and local source fingerprints; never run a fixture."""
    manifest = {
        "schema": "lightup.installed_fixture_catalog_bundle.v1",
        "status": "DRAFT_ONLY",
        "catalog_bytes": len(catalog_payload),
        "catalog_sha256": hashlib.sha256(catalog_payload).hexdigest(),
        "source_files_observed": {
            name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in sorted(source_bytes.items())
        },
        "source_identity_authenticated": False,
        "runtime_import_identity_authenticated": False,
        "fixture_started": False,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }
    manifest_payload = (json.dumps(
        manifest, indent=2, sort_keys=True, ensure_ascii=True
    ) + "\n").encode("utf-8")
    readme = (
        "LIGHTUP PRIVATE INSTALLED-FIXTURE CATALOG BUNDLE\n"
        "DRAFT_ONLY / PLAN-LAB ONLY / REVIEW_ONLY.\n\n"
        "catalog.json contains original fixture profile declarations, numeric loopback target "
        "context and expected finding identities. Treat it as sensitive private material.\n"
        "manifest.json contains local SHA-256 fingerprints and byte lengths for the catalog and "
        "the observed source files. These hashes are unsigned local integrity references only; "
        "they do not authenticate source identity, the imported runtime, a person or authority.\n"
        "No fixture server, DNS lookup, HTTP client, scanner, grant, consent or release is started "
        "or created by this bundle. The catalog remains DRAFT_ONLY.\n"
        "Keep this archive in private storage; archive entries are owner-only (0600).\n"
    ).encode("utf-8")
    entries = [
        ("catalog.json", catalog_payload),
        ("manifest.json", manifest_payload),
        ("README.txt", readme),
    ]
    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9, strict_timestamps=True) as archive:
            for name, raw in entries:
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 22, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED,
                                 compresslevel=9)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        raise Hold("Private fixture catalog bundle could not be composed") from exc
    raw_bundle = buffer.getvalue()
    ensure(0 < len(raw_bundle) <= MAX_BUNDLE_BYTES)
    return raw_bundle


def build_catalog(target: str, profile_names: list[str]) -> dict:
    from lightup.labfixtures import PROFILES, expected_findings

    # The original local fixture binds loopback; a private-subnet IP is NOT a
    # valid alias for a loopback fixture. Do not fabricate fixture bindings.
    target = private_ip(target)
    ensure(ipaddress.ip_address(target).is_loopback)
    ensure(len(profile_names) >= 1 and len(profile_names) <= len(PROFILES))
    ensure(len(profile_names) == len(set(profile_names)))
    ensure(all(p in PROFILES for p in profile_names))
    records = []
    for name in profile_names:
        source = PROFILES[name]
        ground_truth = [
            {"identifier": item.identifier, "title": item.title,
             "capability_id": item.capability_id, "severity": item.severity}
            for item in expected_findings(source)
        ]
        records.append({
            "scenario_id": "fixture-" + name,
            "name": "Installed fixture: " + name,
            "description": source.description,
            "targets": [target],
            "expected_findings": ground_truth
        })
    return {"schema": "lightup.lab_design_catalog.v1", "status": "DRAFT_ONLY",
            "authorized": False, "consent_verified": False,
            "dispatch_allowed": False, "release_allowed": False,
            "scenarios": records}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export ORIGINAL offline fixture profile declarations. No fixture server or scan.")
    parser.add_argument("--target", default="127.0.0.1",
                        help="numeric loopback-only fixture identity (127.x or ::1)")
    parser.add_argument("--profile", action="append",
                        help="one or more ORIGINAL fixture IDs; default all")
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--output", type=Path,
                         help="NEW PRIVATE .json file, owner-only 0600, never overwritten")
    outputs.add_argument("--bundle-output", type=Path,
                         help="NEW PRIVATE .zip with catalog, source fingerprints and caveats")
    args = parser.parse_args()
    try:
        from lightup.labfixtures import PROFILES
        names = args.profile or sorted(PROFILES)
        source_before = source_snapshot() if args.bundle_output else None
        catalog = build_catalog(args.target, names)
        payload = (json.dumps(catalog, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ensure(0 < len(payload) <= 262144)
        # Construct original dataclasses only. No runnable fixture is constructed or started.
        build_native_catalog(catalog["scenarios"])
        if args.bundle_output:
            ensure(args.bundle_output.suffix == ".zip")
            source_after = source_snapshot()
            ensure(source_before == source_after)
            archive = build_private_bundle(payload, source_before)
            private_create(args.bundle_output, archive)
            print("PRIVATE source-bound fixture catalog bundle written (no fixture started).")
            print("Bundle bytes:", len(archive), "catalog bytes:", len(payload))
        else:
            ensure(args.output.suffix == ".json")
            private_create(args.output, payload)
            print("PRIVATE source-bound fixture catalog written (no fixture started).")
            print("Payload SHA-256 (not authenticated provenance):", hashlib.sha256(payload).hexdigest())
        print("Source declarations:", len(names), "original planted findings:",
              sum(len(s["expected_findings"]) for s in catalog["scenarios"]))
        print("No original target, named fixture address, operator approval or grant shown.")
        return 0
    except (Hold, ValueError, OSError, TypeError, ImportError) as exc:
        print("HOLD: original fixture catalog could not be safely admitted or written; "
              "no fixture/scan started.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
