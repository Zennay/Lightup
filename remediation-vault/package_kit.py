#!/usr/bin/env python3
"""Build deterministic user-ready offline-only LightUp vault kit."""
from pathlib import Path
from hashlib import sha256
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
import json

HOME = Path(__file__).resolve().parent
OUTPUT = HOME / "LightUp-Private-Handoff-Vault.zip"
FILES = ["START-HERE.html", "standalone.html", "README.md"]
readable = {name: (HOME / name).read_bytes() for name in FILES}
manifest = {
    "product": "LightUp Private Remediation Handoff Vault",
    "stage": "INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD",
    "human_only": True,
    "execution_authorized": False,
    "files": [{"path": n, "bytes": len(b), "sha256": sha256(b).hexdigest()} for n,b in readable.items()]
}
readable["MANIFEST.json"] = (json.dumps(manifest, indent=2, ensure_ascii=False)+"\n").encode("utf-8")
with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
    for name, blob in sorted(readable.items()):
        info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, blob, compress_type=ZIP_DEFLATED, compresslevel=9)
blob=OUTPUT.read_bytes()
print("Built", OUTPUT.name, len(blob), "bytes sha256", sha256(blob).hexdigest())
