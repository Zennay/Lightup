#!/usr/bin/env python3
"""Build a deterministic portable PRIVATE receipt-history CLI kit; no source data."""
from __future__ import annotations

import hashlib
import io
import os
import stat
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

HERE = Path(__file__).resolve().parent
FILES = (
    "README.md",
    "START-HERE-RECEIPT-HISTORY.txt",
    "build_offline_kit.py",
    "compare_receipts.py",
    "private_workroom.py",
    "receipt_history.py",
)
OUTPUT = "LightUp-Private-Receipt-History-Kit.zip"
SIDECAR = OUTPUT + ".sha256"
FIXED_TIME = (2026, 10, 22, 0, 0, 0)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def atomic_write(path: Path, raw: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=HERE)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        directory = os.open(HERE, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def zip_info(name: str) -> ZipInfo:
    info = ZipInfo(name, date_time=FIXED_TIME)
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def build() -> tuple[bytes, str]:
    artifacts = {}
    for name in FILES:
        path = HERE / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise ValueError("HOLD: kit inputs must be regular non-symlink files")
        artifacts[name] = path.read_bytes()
    manifest = [
        "UNSIGNED SHA-256 digests (integrity aid only; NOT source authenticity or authority)",
        *(f"{digest(raw)}  {name}" for name, raw in sorted(artifacts.items())),
        "",
    ]
    artifacts["HASHES.txt"] = "\n".join(manifest).encode("utf-8")
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(artifacts.items()):
            archive.writestr(zip_info(name), raw, compress_type=ZIP_DEFLATED, compresslevel=9)
    blob = stream.getvalue()
    return blob, digest(blob)


def main() -> int:
    blob, checksum = build()
    atomic_write(HERE / OUTPUT, blob)
    atomic_write(HERE / SIDECAR, f"{checksum}  {OUTPUT}\n".encode("ascii"))
    print(f"{OUTPUT} {len(blob)} bytes SHA-256 {checksum}")
    print(f"{SIDECAR} written; no lab/source/client data packaged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
