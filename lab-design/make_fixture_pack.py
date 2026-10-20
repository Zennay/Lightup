#!/usr/bin/env python3
"""Build static original fixture source pack. No fixture server, DNS or scanner."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

from fixture_catalog import build_catalog
from native_bridge import build_native_catalog

ROOT=Path(__file__).resolve().parent.parent
SOURCE=[ROOT/"src"/"lightup"/"labfixtures.py",
        ROOT/"src"/"lightup"/"workers"/"http_baseline.py"]


def source_pack()->dict:
    from lightup.labfixtures import PROFILES
    names=sorted(PROFILES)
    catalog=build_catalog("127.0.0.1",names)
    build_native_catalog(catalog["scenarios"])
    integrity={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
               for p in SOURCE}
    return {
        "version": "lightup.installed_fixture_pack.v1",
        "source_sha256": integrity,
        "status": "DRAFT_ONLY",
        "source_identity_authenticated": False,
        "built_in_fixtures_only": True,
        "fixture_started": False,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "catalog":catalog
    }


def make()->Path:
    pack=source_pack()
    content=json.dumps(pack,sort_keys=True,separators=(",",":"),
                       ensure_ascii=True).replace("<","\\u003c")
    output=Path(__file__).resolve().parent/"fixture-pack.js"
    output.write_text("globalThis.LightUpOriginalFixturePack="+content+";\n",
                      encoding="utf-8")
    return output


if __name__=="__main__":
    p=make()
    print("Original static fixture source pack:",p.stat().st_size,"bytes; no fixture started")
