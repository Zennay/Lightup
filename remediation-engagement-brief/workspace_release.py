"""One-command PRIVATE HUMAN multi-view workstation from an original .ltv.

Caller first obtains the ORIGINAL account/tenant authorized source. All
original owner apps and history are rebuilt and admitted IN MEMORY before
creating an exclusive directory with owner-private standalone HTML files.
No scanning, remote service, grant issuance, or verified retest is performed.
"""
from __future__ import annotations

from html import escape
import os
from pathlib import Path
import stat

from desk import build_desk
from history import review as history_review
from history_desk import build_history_desk
from sealed_browser import (_admit_encrypted_source, _original_workspace_apps,
                            _rows, WORKSPACE_MODES)
from secure_export import _vault

MAX_FILES = 5

def _landing(views: tuple[str,...], finding_count: int) -> bytes:
    names={
        "review": ("01-review.html","Original source finding review"),
        "ticketdesk": ("02-ticketdesk.html","Original HUMAN Ticket Desk"),
        "casework": ("03-casework.html","Original HUMAN Casework"),
        "history": ("04-history.html","Original source history"),
    }
    links=[]
    for view in views:
        filename,label=names[view]
        links.append('<li><a href="'+escape(filename,quote=True)+'">'+
                     escape(label)+'</a></li>')
    raw = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &apos;none&apos;; '
        'connect-src &apos;none&apos;; img-src &apos;none&apos;; '
        'script-src &apos;none&apos;; style-src &apos;none&apos;; '
        'form-action &apos;none&apos;; object-src &apos;none&apos;; '
        'base-uri &apos;none&apos;; frame-src &apos;none&apos;">'
        '<title>LightUp PRIVATE source-only workbench</title></head><body>'
        '<main><h1>LightUp · PRIVATE HUMAN source-only workspace</h1>'
        '<p>Private local files from ONE freshly authenticated original LightUp '
        'engagement read. Current source finding rows: '+str(finding_count)+'.</p>'
        '<p><strong>DRAFT/HOLD — not verified findings, fixes, retests, grants, '
        'client/operator consent, permission to scan, or production release.</strong></p>'
        '<p>Each standalone view is offline and contains confidential original '
        'source content; never serve these files publicly. '
        'Only the current original source feeds original Ticket Desk/Casework. '
        'Historical absent/fixed source labels are NOT verified remediation.</p>'
        '<nav aria-label="Original source human workspaces"><ul>'+
        "".join(links)+'</ul></nav>'
        '<p>No external scripts, local storage, network requests, or target calls '
        'are needed. Close and securely dispose of this folder after approved '
        'human review. Any client permission must be checked separately at action time.</p>'
        '</main></body></html>'
    )
    result=raw.encode("utf-8","strict")
    if len(result)>8192:
        raise ValueError("PRIVATE source workbench landing page exceeded fixed bound")
    return result


def _admit_folder(directory: Path) -> Path:
    """Require new child of existing owner-only directory; no symlink parents."""
    target=directory.expanduser().absolute()
    if target.name in ("", ".", ".."):
        raise ValueError("PRIVATE workspace directory requires a new name")
    info=os.lstat(target.parent)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid()
        or info.st_mode & 0o077):
        raise ValueError("PRIVATE workspace parent must be owner-owned 0700 directory")
    # New exclusive directory. No reuse, overwrite or private file merging.
    return target


def open_all(current_csv: str, client_id: str, engagement_id: str,
             source: Path, output_dir: Path) -> tuple[str,...]:
    """ONE auth + ONE existing vault password -> 3-4 already-owned views."""
    target=_admit_folder(output_dir)
    if source.expanduser().absolute()==target:
        raise ValueError("Encrypted original source cannot be a workspace directory")
    packet=_admit_encrypted_source(current_csv,client_id,engagement_id,source)
    if packet["mode"] not in WORKSPACE_MODES:
        raise ValueError("Only a NEW sealed multiview source workspace can be unpacked")
    now=_rows(current_csv)
    earlier=[_rows(data) for data in packet["historical_original_csv"]]
    original=_original_workspace_apps(packet,current_csv,client_id,engagement_id)
    views=("review","ticketdesk","casework")+ (("history",) if earlier else ())
    contents={
        "01-review.html": build_desk(now,earlier[-1] if earlier else None),
        "02-ticketdesk.html":original["ticketdesk"],
        "03-casework.html":original["casework"],
    }
    if earlier:
        snapshots=[(dict(unverified_historical=True),records) for records in earlier]
        snapshots.append((dict(current_authenticated=True),now))
        contents["04-history.html"]=build_history_desk(history_review(snapshots))
    contents["index.html"]=_landing(views,len(now))
    if not 3<=len(views)<=4 or len(contents)>MAX_FILES:
        raise ValueError("Unsupported PRIVATE workspace view set")
    # No output is created until every source, hash-pinned original owner app,
    # and generated human HTML file has been admitted in memory.
    os.mkdir(target,0o700)
    created=[]
    try:
        vault=_vault()
        for filename,html in contents.items():
            vault._exclusive_output(target/filename,html)
            created.append(filename)
    except BaseException:
        # A failed multi-view delivery must not leave an apparently complete
        # workstation: no partially published original client findings.
        for filename in created:
            (target/filename).unlink(missing_ok=True)
        try:
            target.rmdir()
        except OSError:
            pass
        raise
    return views
