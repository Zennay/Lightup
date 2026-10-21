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

def file_digest(path: Path) -> str:
    digestor = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digestor.update(chunk)
    return digestor.hexdigest()


def sidecar_digest(sidecar: Path, package: Path) -> str:
    try:
        st = sidecar.lstat()
        if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or
                not 0 < st.st_size <= 4096):
            raise Hold("HOLD: SHA-256 sidecar must be a bounded ordinary file")
        raw = sidecar.read_bytes().decode("utf-8", errors="strict")
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


def verify(path: Path, expected_sha256: str = "",
           sha256_file: Path | None = None) -> int:
    sidecar_value = sidecar_digest(sha256_file, path) if sha256_file else ""
    if expected_sha256 and sidecar_value and expected_sha256 != sidecar_value:
        raise Hold("HOLD: explicit expected digest conflicts with sidecar")
    if sidecar_value:
        expected_sha256 = sidecar_value
    try:
        st = path.lstat()
    except OSError:
        raise Hold("HOLD: package path unavailable") from None
    if (not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or
            not 0 < st.st_size <= MAX_ARCHIVE):
        raise Hold("HOLD: package must be a bounded ordinary regular file")
    if expected_sha256:
        if not isinstance(expected_sha256, str) or not HASH.fullmatch(expected_sha256):
            raise Hold("HOLD: expected SHA-256 must be 64 lowercase hexadecimal characters")
        if file_digest(path) != expected_sha256:
            raise Hold("HOLD: package bytes do not match the supplied expected SHA-256")
    try:
        with ZipFile(path, "r") as archive:
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
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify legacy v1 or current v2 LightUp software-only ZIP bytes without extracting")
    parser.add_argument("--package", required=True,
                        help="path to an existing offline software ZIP")
    args = parser.parse_args()
    try:
        return verify(Path(args.package).absolute())
    except (Hold, OSError) as exc:
        print(str(exc) if isinstance(exc, Hold) else "HOLD: cannot read package",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
