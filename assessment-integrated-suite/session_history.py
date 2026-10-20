#!/usr/bin/env python3
"""Review 2–8 original PRIVATE operator sessions without reading client inputs.

Compares operator-declared local path references and creates a separate
scriptless PRIVATE continuity summary. Never claims a validated source,
chronology, resolved finding, consent, authorization or execution.
"""
from __future__ import annotations

import html
import os
from pathlib import Path
import shutil

import private_session


def prepare(session, parent_name: str, name: str,
            inputs: list[str]) -> Path:
    if not 2 <= len(inputs) <= 8 or len(set(inputs)) != len(inputs):
        raise private_session.Hold("2–8 distinct private operator session manifests required")
    if not private_session.NAME.fullmatch(name):
        raise private_session.Hold("invalid PRIVATE history name")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == private_session.ROOT
            or private_session.ROOT in parent.parents
            or not private_session.private(parent, True)):
        raise private_session.Hold("owner-only 0700 output parent required")
    destination = parent / name
    if os.path.lexists(destination):
        raise private_session.Hold("private session history folder exists")
    snapshots = [private_session.restore(session, filename) for filename in inputs]
    entries = []
    keys = list(session.__dataclass_fields__)
    for i in range(1, len(snapshots)):
        older, newer = snapshots[i - 1], snapshots[i]
        changes = [key for key in keys if older[key] != newer[key]]
        appeared = sum(bool(newer[key]) and not older[key] for key in changes)
        cleared = sum(bool(older[key]) and not newer[key] for key in changes)
        updated = len(changes) - appeared - cleared
        if changes:
            cells = "".join("<li><code>" + html.escape(key) +
                            "</code>: HUMAN path reference changed; reopen with native source admission.</li>"
                            for key in changes)
        else:
            cells = "<li>No operator path fields changed between these two snapshots.</li>"
        entries.append(
            '<section><h2>Operator-declared snapshot #' + str(i) + ' → #' +
            str(i + 1) + '</h2><p>' + str(appeared) + ' references added, ' +
            str(cleared) + ' cleared, ' + str(updated) +
            ' replaced. These are not source-byte changes.</p><ul>' +
            cells + '</ul></section>')
    linked = []
    for i, path in enumerate(inputs, 1):
        source = Path(path)
        index = source.parent / "OPEN-PRIVATE.html"
        if private_session.private(index, False):
            linked.append('<li><a rel="noopener noreferrer" href="' +
                          html.escape(index.as_uri(), quote=True) +
                          '">Open saved PRIVATE operator workspace #' + str(i) +
                          '</a></li>')
    document = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN operator continuity</title>
<style>body{font:16px/1.6 system-ui;max-width:920px;margin:2rem auto;padding:0 1rem;background:#edf2f6;color:#183247}
main,section{background:white;padding:1.5rem;margin:1rem 0;border:1px solid #ccd7e3;border-radius:16px}
h1,h2{line-height:1.2}a{color:#145c8b}li{margin:.5rem 0}
.warn{font-weight:750;color:#824521}</style><main>
<h1>PRIVATE HUMAN operator workspace continuity</h1>
<p class="warn">REVIEW_ONLY / HOLD — operator-specified order, not authenticated chronology.</p>
<p>This compares prior LOCAL SESSION PATH REFERENCES only. No PRIVATE client
source, finding, original file, credential, human note, actual path value or
target is included in this report. A path changing does not prove original
source bytes changed; a path remaining stable does not prove source bytes remain
unchanged. Re-admit originals through their own native tool before any use.</p>""" +
                "".join(entries) +
                "<h2>Original local operator workspaces</h2><ul>" +
                ("".join(linked) if linked else "<li>No prior private launcher is currently accessible.</li>") +
                """</ul>
<p>Current separate client/operator consent with revocation-at-use,
original source owner/privacy/security review and HUMAN GO not verified.
No networking, model, assessment, grant, deletion, retest, recipient contact,
original source modification or automatic session restore. Keep this file
PRIVATE. Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>""")
    destination.mkdir(mode=0o700)
    try:
        if not private_session.private(destination, True):
            raise private_session.Hold("new private history directory denied")
        private_session.private_write(destination, "OPEN-PRIVATE.html", document.encode("utf-8"))
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(destination)
        raise private_session.Hold("private HUMAN operator history not created")
    return destination / "OPEN-PRIVATE.html"
