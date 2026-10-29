#!/usr/bin/env python3
"""Build the offline LightUp workbench from immutable Git commit objects."""
from __future__ import annotations
import hashlib, json, subprocess, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent
REPO=ROOT.parent
APPS=ROOT/"apps"
SOURCES={
"studio":(1567,"71d9e5f760ef2bff46a72b979173bb3181179afb",("studio/","docs/scope-proposal-studio.md")),
"schedule":(1572,"b9bfaf439cdd506f5cd7292b25c14db017fb5dc6",("studio/scope-schedule-board.html","studio/scope-schedule-board.js","docs/scope-schedule-board.md")),
"readiness":(1573,"1786ee9e8034736aa0f1ff1b3904f2b1b5305678",("coordination/","docs/scope-readiness-workspace.md")),
"vault":(1574,"49a569b2125a80dcaac21655febc07861afa0df2",("scope-vault/","docs/private-scope-packet-vault.md")),
"assessment":(1576,"bb5c2299d3697781db7093aaea79ed418f1cc07c",("assessment-review/","docs/assessment-review-desk.md")),
"withdrawal":(1577,"0235d93fe285edc0cc49ea3aec3580b7dc4e1338",("withdrawal-desk/","docs/scope-withdrawal-coordination-desk.md")),
"permission":(1578,"f88df4b9732fb180cf77e92ed9af90b752316200",("scope-permission-brief/","docs/scope-permission-brief.md")),
"handoff":(1579,"78ad5e20dd8ea03a3f548b5f83648b923a6598d7",("scope-handoff-register/",)),
"briefing":(1580,"22afcb7669ce078be504e288b03b8adf2b4412d8",("scope-briefing/",)),
"casework":(1568,"9c73e8468ce271bf8c6bef4cac071e5ad9c1806b",("casework/",)),
}
def git(*args):
    return subprocess.run(("git",*args),cwd=REPO,check=True,capture_output=True).stdout
def put(group, pr, sha, source, target=None):
    if source.startswith("/") or ".." in Path(source).parts:
        raise ValueError("unsafe path")
    body=git("show",sha+":"+source)
    if len(body)>2_000_000:
        raise ValueError("oversized source")
    dest=APPS/group/(target or source)
    dest.parent.mkdir(parents=True,exist_ok=True)
    if dest.is_symlink():
        raise ValueError("refusing symlink destination: "+str(dest))
    if dest.exists():
        if dest.read_bytes()!=body:
            raise ValueError("pinned source differs from existing copy: "+str(dest))
    else:
        dest.write_bytes(body)
    return dict(component=group,pr=pr,commit=sha,source_path=source,
                bundled_path=str(dest.relative_to(ROOT)),sha256=hashlib.sha256(body).hexdigest(),bytes=len(body))
def main():
    if not (ROOT/"index.html").is_file(): raise ValueError("missing launchpad")
    artifacts=[]
    for group,(pr,sha,prefixes) in SOURCES.items():
        if git("rev-parse",sha).decode().strip()!=sha: raise ValueError("missing pinned commit "+group)
        paths=git("ls-tree","-r","--name-only",sha).decode().splitlines()
        selected=[p for p in paths if any(p==q or (q.endswith("/") and p.startswith(q)) for q in prefixes)]
        if not selected: raise ValueError("empty source "+group)
        artifacts.extend(put(group,pr,sha,p) for p in selected)
    original=SOURCES["studio"][1]
    studio=git("ls-tree","-r","--name-only",original,"studio").decode().splitlines()
    for p in studio:
        if p not in {"studio/scope-schedule-board.html","studio/scope-schedule-board.js"}:
            artifacts.append(put("schedule",1567,original,p))
    for p in ("scope-network.js","scope-fingerprint.js","planning-window.js"):
        artifacts.append(put("readiness",1567,original,"studio/"+p,"coordination/"+p))
    (APPS/"README.md").write_text("DRAFT/HOLD offline source snapshots; no authority. See ../README.md.\n")
    for group in ("studio", "schedule"):
        (APPS/group/"README.md").write_text(
            "# LightUp "+group+" offline preview\n\n"
            "DRAFT / HOLD, not consent, authorization, permission or release.\n\n"
            "Read the copied original documentation under docs/ in this folder.\n"
            "Open studio/index.html for original Studio navigation; for the schedule "
            "board open studio/scope-schedule-board.html.\n"
            "Return to ../../index.html for the full offline workbench.\n",
            encoding="utf-8")
    manifest={
        "kind":"lightup.offline_scope_workbench","schema_version":1,"state":"DRAFT_HOLD_REVIEW_ONLY",
        "authenticated":False,"consent_verified":False,"authorized":False,"grant_issued":False,
        "scan_allowed":False,"dispatch_allowed":False,"deploy_allowed":False,"release_allowed":False,
        "note":"Git SHA and raw-file SHA256 are only byte identifiers, NEVER signatures, ownership, consent or permits.",
        "components":[{"name":k,"pr":v[0],"commit":v[1],"state":"DRAFT_HOLD"} for k,v in SOURCES.items()],
        "files":sorted(artifacts,key=lambda x:x["bundled_path"])
    }
    (ROOT/"manifest.json").write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n")
    zpath=ROOT/"LightUp-offline-workbench.zip"
    with zipfile.ZipFile(zpath,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(ROOT.rglob("*")):
            if p.is_file() and p != zpath and p.name != "package.py":
                z.write(p,"LightUp-offline-workbench/"+str(p.relative_to(ROOT)))
    print("Built",len(SOURCES),"draft components;",len(artifacts),"snapshotted files",
          "zip bytes",zpath.stat().st_size,"sha256",hashlib.sha256(zpath.read_bytes()).hexdigest())
if __name__=="__main__":main()
