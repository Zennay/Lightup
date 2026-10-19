#!/usr/bin/env python3
"""Build a portable, entirely offline PRIVATE HUMAN LightUp evidence workspace.

Integrates pre-existing original-source product directories without modifying their
contents. The manifest is an integrity inventory, not a signature or authority grant.
No network I/O, browser automation, targets, scans, or security tests are used.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
HUB = ROOT / "remediation-operations"
DESTINATION = HUB / "LightUp-PRIVATE-Evidence-Hub.zip"
MANIFEST = HUB / "MANIFEST.json"
APPLICATIONS = (
    "remediation-artifact-ledger",
    "remediation-response-reconciliation",
    "remediation-handoff-inbox",
    "remediation-human-runbooks",
    "remediation-vault",
    "remediation-change-windows",
)
INTEGRATION = "remediation-operations"
SOURCE_PR_HEADS = {
    "1642": "6a8cd3baf6535705a7baca77dc3dc5067f862b3d",
    "1643": "58ad10f0b8cfb949287d4751b782221fc4ff9948",
    "1644": "933a0a4e278c957bbeaa564c3effcab6d1ae8a31",
    "1645": "f08fb96f7094d021493a39aa5d1a3eed025509f3",
    "1640": "1a1ec2b95db5fdb15716e5c7dde21d22322bbb54",
    "1631": "b7291f4cf560638509cac414207a5e126b4f07de",
}
PERMITTED_EXTENSIONS = {".html", ".js", ".css", ".py", ".md", ".json", ".zip"}
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PACKAGE_BYTES = 32 * 1024 * 1024


def source_files() -> list[tuple[str, bytes]]:
    """Bounded, sorted real source files only; no symlinks, hidden data or caches."""
    result: list[tuple[str, bytes]] = []
    total = 0
    for directory in (*APPLICATIONS, INTEGRATION):
        base = ROOT / directory
        if not base.is_dir() or base.is_symlink():
            raise ValueError(f"Required original product directory unavailable: {directory}")
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise ValueError("Refusing source symlink")
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT).as_posix()
            if "__pycache__" in path.relative_to(ROOT).parts or path.suffix == ".pyc":
                continue
            if any(part.startswith(".") or part == "__pycache__" for part in path.relative_to(ROOT).parts):
                raise ValueError("Refusing private or hidden path")
            if path.suffix == ".zip" and path != DESTINATION and rel != "remediation-vault/LightUp-Private-Handoff-Vault.zip":
                raise ValueError(f"Unexpected nested ZIP source: {rel}")
            if path.suffix not in PERMITTED_EXTENSIONS:
                if path.name in (DESTINATION.name,) or path.suffix == ".pyc":
                    continue
                raise ValueError(f"Unexpected file type: {rel}")
            if path in (MANIFEST, DESTINATION):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"Source file too large: {rel}")
            data = path.read_bytes()
            total += len(data)
            if total > MAX_PACKAGE_BYTES:
                raise ValueError("Integrated package exceeds 32 MiB")
            result.append((rel, data))
    if len(result) < 43:
        raise ValueError("Missing source-owned evidence workflow files")
    return result


def build() -> tuple[int, int]:
    # Keep complete ready-to-open single HTML synchronized with the ORIGINAL parser and desk sources.
    from build_triage_standalone import main as publish_triage
    publish_triage()
    from build_source_continuity_standalone import main as publish_continuity
    publish_continuity()
    sources = source_files()
    manifest = {
        "schema": "lightup-private-human-evidence-integration-v1",
        "release": "INCUBATE M3/M7 - PLAN/LAB ONLY - DRAFT/HOLD",
        "authentication": False,
        "client_consent": False,
        "operator_consent": False,
        "active_execution": False,
        "security_fix_verified": False,
        "production_release_approved": False,
        "original_source_pr_heads": SOURCE_PR_HEADS,
        "privacy": "PRIVATE HUMAN only. App integrity hashes are NOT authenticated owner consent or security approval.",
        "start": "remediation-operations/index.html",
        "files": [
            {"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sources
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    # Retained unbundled manifest makes exact release inventory inspectable on GitHub.
    fd, temp_manifest = tempfile.mkstemp(prefix=".manifest-", dir=HUB)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(manifest_bytes)
        os.replace(temp_manifest, MANIFEST)
    finally:
        if os.path.exists(temp_manifest):
            os.unlink(temp_manifest)
    fd, temp_zip = tempfile.mkstemp(prefix=".evidence-hub-", suffix=".zip", dir=HUB)
    os.close(fd)
    try:
        with zipfile.ZipFile(temp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in (*sources, ("remediation-operations/MANIFEST.json", manifest_bytes)):
                item = zipfile.ZipInfo(name, date_time=(2026, 10, 19, 0, 0, 0))
                item.compress_type = zipfile.ZIP_DEFLATED
                item.external_attr = 0o644 << 16
                item.create_system = 3
                archive.writestr(item, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temp_zip, DESTINATION)
    finally:
        if os.path.exists(temp_zip):
            os.unlink(temp_zip)
    return len(sources), DESTINATION.stat().st_size


if __name__ == "__main__":
    count, size = build()
    print(f"Packaged {count} original + integration source files: {DESTINATION.name} ({size} bytes)")
