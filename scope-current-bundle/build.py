#!/usr/bin/env python3
"""Build immutable DRAFT/HOLD LightUp scope offline distribution.

Only original, pinned workspace sources are packaged. No assessment, network
scanner, authorization, external data, CI or QA suites are invoked.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEST = Path(__file__).resolve().parent
SOURCE = ROOT / "scope-unified-workspace"
PARENT = "0f76f2f90a89f5b64bc8033aa2e2ee6ec2fc49cc"
SOURCE_PINS = {
    "source-inspector.js": "a530524e5fe3e372373e8f16ede88c2fa008bc0e4e33f5ba8713239a29ed2c92",
    "source-drift.js": "7f71fedd841e1a1bc3eb9d4957e8bcbc73f84e947d33641093bf045691964d95",
    "handoff.js": "4bdc774d6020e83dc4ae9cc7a4b90cc68a8d22bceb875eab4494fd4ab578e6c3",
    "build.py": "48efc4c471f18378d6f7856464226e202debe06235c6f760b8712212295bebc8",
}
WORKROOMS = ("scope-intake-matrix", "scope-casebook-history",
             "scope-casebook-transfer", "scope-casebook-reconcile",
             "authorization-portfolio", "withdrawal-desk", "scope-vault", "studio")
OUTPUTS = ("LightUp-Scope-Offline-DRAFT-HOLD.zip", "index.html",
           "handoff.html", "verify.html", "SOURCE-MANIFEST.json")


def read_regular(path: Path, max_bytes: int = 10_000_000) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes:
        raise ValueError("Unsafe or missing source: " + path.name)
    return path.read_bytes()


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def copy_pinned(src: Path, dst: Path) -> None:
    if not src.is_dir() or src.is_symlink():
        raise ValueError("Missing pinned directory " + src.name)
    # No links or device files; preserve file content only.
    for entry in src.rglob("*"):
        if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
            raise ValueError("Unsafe entry in source " + src.name)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def publish_immutable(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        if read_regular(path) != content:
            raise ValueError("Distribution exists with different bytes: " + path.name)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def build() -> None:
    for name, pin in SOURCE_PINS.items():
        if digest(read_regular(SOURCE / name)) != pin:
            raise ValueError("Source HEAD pin violation: " + name)
    with tempfile.TemporaryDirectory(prefix="lightup-scope-dist-") as scratch:
        scratch_root = Path(scratch)
        copy_pinned(SOURCE, scratch_root / SOURCE.name)
        for name in WORKROOMS:
            copy_pinned(ROOT / name, scratch_root / name)
        subprocess.run([sys.executable, str(scratch_root / SOURCE.name / "build.py")],
                       check=True, cwd=scratch_root, timeout=120)
        produced = scratch_root / SOURCE.name
        manifest_bytes = read_regular(produced / "SOURCE-MANIFEST.json")
        manifest = json.loads(manifest_bytes)
        if manifest.get("format") != "lightup.scope_offline_bundle.v1" or manifest.get("posture") != "INCUBATE_M3_M7_DRAFT_HOLD":
            raise ValueError("Original distribution source/status changed")
        authority = manifest.get("authority")
        if not isinstance(authority, dict) or set(authority) != {
                "client_consent", "operator_consent", "grant", "scan", "deploy", "release"
        } or any(value is not False for value in authority.values()):
            raise ValueError("Source asserted authority")
        if set(manifest.get("pinned_original_branch_heads", {})) != set(WORKROOMS):
            raise ValueError("Original workrooms changed")
        if len(manifest.get("file_entries", [])) < 60:
            raise ValueError("Incomplete original pinned package")
        blobs = {name: read_regular(produced / name) for name in OUTPUTS}
        summary = {
            "format": "lightup.scope_offline_distribution.v1",
            "posture": "INCUBATE_M3_M7_DRAFT_HOLD",
            "source_parent_sha": PARENT,
            "authenticated_release": False,
            "authority": dict.fromkeys(("client_consent", "operator_consent",
                "grant", "scan", "deploy", "release"), False),
            "files": [{"name": name, "sha256": digest(blobs[name]), "bytes": len(blobs[name])}
                      for name in OUTPUTS],
            "note": "Unsigned, source-byte-bound offline build, not approved consent or release."
        }
        summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
        # Preflight all destination collisions before any publication.
        for name, payload in [*blobs.items(), ("DIST-MANIFEST.json", summary_bytes)]:
            target = DEST / name
            if target.exists() and read_regular(target) != payload:
                raise ValueError("Immutable destination collision: " + name)
        for name, payload in [*blobs.items(), ("DIST-MANIFEST.json", summary_bytes)]:
            publish_immutable(DEST / name, payload)
            print(name, len(payload), digest(payload))


if __name__ == "__main__":
    build()
