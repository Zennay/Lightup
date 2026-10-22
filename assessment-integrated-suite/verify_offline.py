#!/usr/bin/env python3
"""Verify a LightUp software-only offline ZIP's exact local byte inventory.

This is an unsigned integrity check only. It does not authenticate authorship,
source provenance, consent, authorization, findings, remediation or release.
No archive files are extracted and no target/network operations are performed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys
from zipfile import BadZipFile, ZipFile

MAX_ARCHIVE = 50 * 1024 * 1024
MAX_MEMBERS = 100
MAX_MEMBER = 4 * 1024 * 1024
MAX_TOTAL = 40 * 1024 * 1024
HASH = re.compile(r"^[a-f0-9]{64}$")
FLAGS = ("authorization_granted", "consent_verified", "source_authenticated",
         "finding_verified", "dispatch_allowed", "release_allowed")
PACKAGE_ASSETS = {"START-HERE.html", "README.txt", "GUIDE-LAB-PLANNING.md"}

class Hold(Exception):
    pass


def reject_symlink_components(path: Path) -> Path:
    """Refuse path traversal through any existing symlink component."""
    candidate = path.absolute()
    for component in (*reversed(candidate.parents), candidate):
        try:
            info = component.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise Hold("HOLD: symbolic-link path component refused")
    return candidate


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("HOLD: duplicate manifest JSON property")
        result[key] = value
    return result

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe_member(info) -> str:
    name = info.filename
    parts = name.split("/")
    if (not name or name.startswith("/") or "\\" in name or
            any(part in ("", ".", "..") for part in parts) or
            info.is_dir() or (info.flag_bits & 1) or
            stat.S_ISLNK(info.external_attr >> 16)):
        raise Hold("HOLD: unsafe, encrypted, directory or symbolic-link archive member")
    if info.file_size < 0 or info.file_size > MAX_MEMBER:
        raise Hold("HOLD: archive member size outside bound")
    return name

def descriptor(value, expected_names: set[str], *, with_source: bool):
    if not isinstance(value, dict):
        raise Hold("HOLD: malformed inventory entry")
    allowed = {"filename", "bytes", "sha256_unsigned"}
    if with_source:
        allowed.add("source_path")
    if set(value) != allowed:
        raise Hold("HOLD: unexpected inventory fields")
    name, size, sha = value["filename"], value["bytes"], value["sha256_unsigned"]
    if (not isinstance(name, str) or name not in expected_names or
            type(size) is not int or size <= 0 or size > MAX_MEMBER or
            not isinstance(sha, str) or not HASH.fullmatch(sha)):
        raise Hold("HOLD: malformed inventory identity, size or digest")
    if with_source:
        source = value["source_path"]
        if (not isinstance(source, str) or source.startswith("/") or "\\" in source or
                any(part in ("", ".", "..") for part in source.split("/"))):
            raise Hold("HOLD: unsafe original source path in inventory")
    return name, size, sha

def stream_digest(stream) -> str:
    """Hash an already-open regular file without reopening its path."""
    digestor = hashlib.sha256()
    stream.seek(0)
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digestor.update(chunk)
    return digestor.hexdigest()


def sidecar_digest(sidecar: Path, package: Path) -> str:
    sidecar = reject_symlink_components(sidecar)
    package = reject_symlink_components(package)
    try:
        fd = os.open(sidecar, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            path_before = sidecar.lstat()
            if (not stat.S_ISREG(before.st_mode) or
                    not stat.S_ISREG(path_before.st_mode) or stat.S_ISLNK(path_before.st_mode) or
                    (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino) or
                    not 0 < before.st_size <= 4096):
                raise Hold("HOLD: SHA-256 sidecar must be a bounded ordinary file")
            identity_before = (before.st_dev, before.st_ino, before.st_size,
                               before.st_mtime_ns, before.st_ctime_ns)
            raw_bytes = stream.read(4097)
            after = os.fstat(stream.fileno())
            path_after = sidecar.lstat()
            identity_after = (after.st_dev, after.st_ino, after.st_size,
                              after.st_mtime_ns, after.st_ctime_ns)
            if (identity_before != identity_after or
                    (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino) or
                    not stat.S_ISREG(path_after.st_mode) or stat.S_ISLNK(path_after.st_mode) or
                    len(raw_bytes) != before.st_size or len(raw_bytes) > 4096):
                raise Hold("HOLD: SHA-256 sidecar changed during read")
        raw = raw_bytes.decode("utf-8", errors="strict")
    except Hold:
        raise
    except (OSError, UnicodeDecodeError):
        raise Hold("HOLD: SHA-256 sidecar unavailable or not UTF-8") from None
    lines = raw.splitlines()
    if len(lines) != 1:
        raise Hold("HOLD: SHA-256 sidecar must contain exactly one checksum line")
    match = re.fullmatch(r"([a-f0-9]{64})  ([^/\\\\]+)", lines[0])
    if not match or match.group(2) != package.name:
        raise Hold("HOLD: SHA-256 sidecar digest or package filename mismatch")
    return match.group(1)


def verify_source_checkout(source_root: Path, files: list[dict]) -> int:
    """Compare packaged software bytes with an explicit local checkout, fail closed."""
    root = reject_symlink_components(source_root)
    try:
        root_stat = root.lstat()
    except OSError:
        raise Hold("HOLD: explicit source checkout is unavailable") from None
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise Hold("HOLD: source checkout root must be an ordinary directory")

    compared = 0
    for item in files:
        relative = item["source_path"]
        candidate = reject_symlink_components(root / relative)
        try:
            fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_CLOEXEC", 0))
        except OSError:
            raise Hold("HOLD: source checkout member is missing or unsafe") from None
        try:
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                try:
                    path_before = candidate.lstat()
                except OSError:
                    raise Hold("HOLD: source checkout member changed during admission") from None
                identity_before = (before.st_dev, before.st_ino, before.st_size,
                                   before.st_mtime_ns, before.st_ctime_ns)
                if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(path_before.st_mode) or
                        not stat.S_ISREG(path_before.st_mode) or
                        (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino) or
                        before.st_size != item["bytes"] or before.st_size > MAX_MEMBER):
                    raise Hold("HOLD: source checkout member is unsafe or differs from package")
                raw = stream.read(MAX_MEMBER + 1)
                after = os.fstat(stream.fileno())
                try:
                    path_after = candidate.lstat()
                except OSError:
                    raise Hold("HOLD: source checkout member changed during read") from None
                identity_after = (after.st_dev, after.st_ino, after.st_size,
                                  after.st_mtime_ns, after.st_ctime_ns)
                if (identity_before != identity_after or
                        (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino) or
                        len(raw) != item["bytes"] or digest(raw) != item["sha256_unsigned"]):
                    raise Hold("HOLD: package software is stale against the supplied source checkout")
        except Hold:
            raise
        except OSError:
            raise Hold("HOLD: source checkout member could not be read safely") from None
        compared += 1
    return compared


def verify(path: Path, expected_sha256: str = "",
           sha256_file: Path | None = None,
           source_root: Path | None = None,
           return_manifest: bool = False) -> int | dict:
    path = reject_symlink_components(path)
    if source_root is not None:
        source_root = reject_symlink_components(source_root)
    if sha256_file is not None:
        sha256_file = reject_symlink_components(sha256_file)
    sidecar_value = sidecar_digest(sha256_file, path) if sha256_file else ""
    if expected_sha256 and sidecar_value and expected_sha256 != sidecar_value:
        raise Hold("HOLD: explicit expected digest conflicts with sidecar")
    if sidecar_value:
        expected_sha256 = sidecar_value
    if expected_sha256:
        if not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256):
            raise Hold("HOLD: expected SHA-256 must be 64 lowercase hexadecimal characters")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as package_stream:
            before = os.fstat(package_stream.fileno())
            path_before = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or
                    not stat.S_ISREG(path_before.st_mode) or stat.S_ISLNK(path_before.st_mode) or
                    (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino) or
                    not 0 < before.st_size <= MAX_ARCHIVE):
                raise Hold("HOLD: package must be a bounded ordinary regular file")
            identity_before = (before.st_dev, before.st_ino, before.st_size,
                               before.st_mtime_ns, before.st_ctime_ns)
            if expected_sha256 and stream_digest(package_stream) != expected_sha256:
                raise Hold("HOLD: package bytes do not match the supplied expected SHA-256")
            package_stream.seek(0)
            with ZipFile(package_stream, "r") as archive:
                infos = archive.infolist()
                if not 1 <= len(infos) <= MAX_MEMBERS:
                    raise Hold("HOLD: unexpected archive member count")
                by_name = {}
                total = 0
                for info in infos:
                    name = safe_member(info)
                    if name in by_name:
                        raise Hold("HOLD: duplicate archive member name")
                    by_name[name] = info
                    total += info.file_size
                    if total > MAX_TOTAL:
                        raise Hold("HOLD: expanded archive exceeds size bound")
                if "manifest.json" not in by_name:
                    raise Hold("HOLD: inventory manifest is missing")
                raw_manifest = archive.read(by_name["manifest.json"])
                if len(raw_manifest) > 256 * 1024:
                    raise Hold("HOLD: inventory manifest exceeds size bound")
                manifest = json.loads(raw_manifest.decode("utf-8", errors="strict"),
                                      object_pairs_hook=unique_object)
                if not isinstance(manifest, dict):
                    raise Hold("HOLD: inventory root must be an object")
                common_required = {"schema", "status", "software_only",
                                   "sources_or_client_data_included", "original_app_count",
                                   "support_asset_count", "files", "operator_guide", *FLAGS}
                has_assets = "package_assets" in manifest or "manifest_self_hash_excluded" in manifest
                required = common_required | ({"package_assets", "manifest_self_hash_excluded"}
                                               if has_assets else set())
                if set(manifest) != required:
                    raise Hold("HOLD: unsupported manifest schema or fields")
                schema = manifest["schema"]
                if schema not in ("lightup.assessment_offline_software_kit.v1",
                                  "lightup.assessment_offline_software_kit.v2"):
                    raise Hold("HOLD: unsupported manifest version")
                if schema == "lightup.assessment_offline_software_kit.v2" and not has_assets:
                    raise Hold("HOLD: v2 manifest lacks full package asset inventory")
                if has_assets and manifest["manifest_self_hash_excluded"] is not True:
                    raise Hold("HOLD: manifest self-hash posture is missing")
                if (manifest["status"] != "REVIEW_ONLY" or
                        manifest["software_only"] is not True or
                        manifest["sources_or_client_data_included"] is not False or
                        any(manifest[flag] is not False for flag in FLAGS)):
                    raise Hold("HOLD: package posture or non-authority flags do not match")
                files = manifest["files"]
                assets = manifest.get("package_assets", [])
                if (not isinstance(files, list) or not files or
                        not isinstance(assets, list)):
                    raise Hold("HOLD: inventory collections are malformed")
                file_names = set()
                app_count = support_count = verified = 0
                for item in files:
                    studio_names = {n for n in by_name if n.startswith("studios/")}
                    name, size, sha = descriptor(item, studio_names, with_source=True)
                    if not name.startswith("studios/") or name in file_names:
                        raise Hold("HOLD: duplicate or non-studio software entry")
                    file_names.add(name)
                    if name.endswith(".html"):
                        app_count += 1
                    else:
                        support_count += 1
                    content = archive.read(by_name[name])
                    if len(content) != size or digest(content) != sha:
                        raise Hold("HOLD: software asset bytes do not match manifest")
                    verified += 1
                asset_names = set()
                for item in assets:
                    name, size, sha = descriptor(item, PACKAGE_ASSETS, with_source=False)
                    if name in asset_names:
                        raise Hold("HOLD: duplicate package support asset")
                    asset_names.add(name)
                    content = archive.read(by_name[name])
                    if len(content) != size or digest(content) != sha:
                        raise Hold("HOLD: package support asset bytes do not match manifest")
                    verified += 1
                guide = manifest["operator_guide"]
                if assets:
                    if asset_names != PACKAGE_ASSETS:
                        raise Hold("HOLD: package support inventory is incomplete")
                    if guide != next(x for x in assets if x["filename"] == "GUIDE-LAB-PLANNING.md"):
                        raise Hold("HOLD: operator guide inventory entries disagree")
                else:
                    # Legacy v1 manifest: original guide/apps are hashed, but the
                    # generated launcher and README are not independently inventoried.
                    name, size, sha = descriptor(
                        guide, {"GUIDE-LAB-PLANNING.md"}, with_source=False)
                    content = archive.read(by_name[name])
                    if len(content) != size or digest(content) != sha:
                        raise Hold("HOLD: legacy operator guide does not match manifest")
                    verified += 1
                    print("LEGACY MANIFEST: START-HERE.html and README.txt have no individual hashes; " +
                          "supply an independently trusted expected ZIP SHA-256 for whole-package matching.")
                expected = {"manifest.json", "START-HERE.html", "README.txt",
                            "GUIDE-LAB-PLANNING.md"} | file_names
                if set(by_name) != expected:
                    raise Hold("HOLD: unexpected or missing archive members")
                if (assets and asset_names != PACKAGE_ASSETS):
                    raise Hold("HOLD: package support inventory is incomplete")
                if (type(manifest["original_app_count"]) is not int or
                        manifest["original_app_count"] != app_count or
                        type(manifest["support_asset_count"]) is not int or
                        manifest["support_asset_count"] != support_count):
                    raise Hold("HOLD: declared studio/support counts do not match")
                if source_root is not None:
                    compared = verify_source_checkout(source_root, files)
                    print("SOURCE CHECKOUT PARITY: " + str(compared) +
                          " packaged software files match the explicit local checkout.")
                    print("This is local byte parity only; it does not authenticate authorship or provenance.")
            after = os.fstat(package_stream.fileno())
            path_after = path.lstat()
            identity_after = (after.st_dev, after.st_ino, after.st_size,
                              after.st_mtime_ns, after.st_ctime_ns)
            if (identity_before != identity_after or
                    (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino) or
                    not stat.S_ISREG(path_after.st_mode)):
                raise Hold("HOLD: package changed while it was being verified")
            if expected_sha256 and stream_digest(package_stream) != expected_sha256:
                raise Hold("HOLD: package bytes changed during verification")
    except Hold:
        raise
    except (OSError, BadZipFile, UnicodeDecodeError, json.JSONDecodeError,
            KeyError, TypeError, ValueError, RuntimeError):
        raise Hold("HOLD: invalid archive or malformed manifest") from None
    print("VERIFIED LOCAL INTEGRITY ONLY: exact ZIP inventory and " +
          str(verified) + " unsigned byte-length/SHA-256 entries match.")
    if expected_sha256:
        print("SUPPLIED EXPECTED SHA-256 MATCHES: package bytes match the supplied reference.")
        print("The reference proves no provenance unless obtained independently from a trusted channel.")
    print("REVIEW_ONLY: no source authenticity, trusted origin, consent, permission, " +
          "finding verification, remediation or release is established.")
    if return_manifest:
        return manifest
    return 0


def comparison_inventory(manifest: dict) -> dict[tuple[str, str], dict]:
    """Build an unambiguous source-path/support-name index from a verified manifest."""
    inventory = {}
    for item in manifest["files"]:
        identity = ("software", item["source_path"])
        if identity in inventory:
            raise Hold("HOLD: ambiguous duplicate software source path in comparison inventory")
        inventory[identity] = {
            "filename": item["filename"],
            "bytes": item["bytes"],
            "sha256_unsigned": item["sha256_unsigned"],
        }
    support = manifest.get("package_assets", [])
    if not support:
        support = [manifest["operator_guide"]]
    for item in support:
        identity = ("support", item["filename"])
        if identity in inventory:
            raise Hold("HOLD: ambiguous duplicate support asset in comparison inventory")
        inventory[identity] = {
            "filename": item["filename"],
            "bytes": item["bytes"],
            "sha256_unsigned": item["sha256_unsigned"],
        }
    return inventory


def compare_packages(package: Path, comparison_package: Path,
                     expected_sha256: str = "",
                     sha256_file: Path | None = None,
                     source_root: Path | None = None) -> int:
    """Verify two complete packages, then print a local-only inventory delta."""
    package = reject_symlink_components(package)
    comparison_package = reject_symlink_components(comparison_package)
    if package == comparison_package:
        raise Hold("HOLD: comparison requires two distinct package paths")
    try:
        current_stat, previous_stat = package.stat(), comparison_package.stat()
    except OSError:
        raise Hold("HOLD: both comparison packages must exist") from None
    if (current_stat.st_dev, current_stat.st_ino) == (previous_stat.st_dev, previous_stat.st_ino):
        raise Hold("HOLD: comparison package paths resolve to the same file")
    current_manifest = verify(
        package, expected_sha256, sha256_file, source_root, return_manifest=True
    )
    previous_manifest = verify(comparison_package, return_manifest=True)
    if not isinstance(current_manifest, dict) or not isinstance(previous_manifest, dict):
        raise Hold("HOLD: verified package inventory was not available for comparison")
    current = comparison_inventory(current_manifest)
    previous = comparison_inventory(previous_manifest)
    changes = {"software": {"ADDED": 0, "REMOVED": 0, "CHANGED": 0, "UNCHANGED": 0},
               "support": {"ADDED": 0, "REMOVED": 0, "CHANGED": 0, "UNCHANGED": 0}}
    details = []
    for identity in sorted(set(previous) | set(current)):
        old = previous.get(identity)
        new = current.get(identity)
        category, logical_name = identity
        if old is None:
            state = "ADDED"
            details.append((state, category, logical_name, "", new))
        elif new is None:
            state = "REMOVED"
            details.append((state, category, logical_name, old, ""))
        elif old == new:
            state = "UNCHANGED"
        else:
            state = "CHANGED"
            details.append((state, category, logical_name, old, new))
        changes[category][state] += 1

    print("PACKAGE INVENTORY COMPARISON — LOCAL REVIEW ONLY")
    print("Baseline: " + comparison_package.name + " (" +
          str(previous_manifest["schema"]) + ")")
    print("Candidate: " + package.name + " (" + str(current_manifest["schema"]) + ")")
    for category, label in (("software", "Software"), ("support", "Package support assets")):
        counts = changes[category]
        print(label + ": " + ", ".join(
            str(counts[state]) + " " + state.lower()
            for state in ("ADDED", "CHANGED", "REMOVED", "UNCHANGED")
        ))
    for state, category, logical_name, old, new in details:
        label = category + " " + logical_name
        if state == "CHANGED":
            print("CHANGED " + label + ": " + old["filename"] + " (" +
                  str(old["bytes"]) + " bytes) -> " + new["filename"] + " (" +
                  str(new["bytes"]) + " bytes)")
        elif state == "ADDED":
            print("ADDED " + label + ": " + new["filename"] + " (" +
                  str(new["bytes"]) + " bytes)")
        else:
            print("REMOVED " + label + ": " + old["filename"] + " (" +
                  str(old["bytes"]) + " bytes)")
    if not details:
        print("No software or package-support inventory differences.")
    print("Both ZIPs passed local inventory integrity checks. This comparison does not " +
          "authenticate origin, authorship, provenance, consent, authorization or release.")
    print("No ZIP was extracted and no files were written.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify legacy v1 or current v2 LightUp software-only ZIP bytes without extracting")
    parser.add_argument("--package", required=True,
                        help="path to an existing offline software ZIP")
    parser.add_argument("--expected-sha256", default="",
                        help="optional expected ZIP digest from a separately trusted channel")
    parser.add_argument("--sha256-file", default="",
                        help="optional standard sha256sum sidecar bound to the package filename")
    parser.add_argument("--source-root", default="",
                        help="optional local checkout root; fail if packaged software bytes are stale")
    parser.add_argument("--compare-package", default="",
                        help="optional second verified ZIP; print software/support inventory differences without extracting")
    args = parser.parse_args()
    try:
        package = Path(args.package).absolute()
        sha256_file = Path(args.sha256_file).absolute() if args.sha256_file else None
        source_root = Path(args.source_root).absolute() if args.source_root else None
        if args.compare_package:
            return compare_packages(
                package, Path(args.compare_package).absolute(),
                args.expected_sha256, sha256_file, source_root
            )
        return verify(package, args.expected_sha256, sha256_file, source_root)
    except (Hold, OSError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: cannot read package",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
