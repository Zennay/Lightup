"""Create an immutable, source-bound PRIVATE ready-to-open offline Impact Map.

Only an original validated, owner-private Casebook byte snapshot is embedded.
No transport, login, permission, grant, STOP mutation or live target access.
"""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256

from prepare import APP_LIMIT, SOURCE_LIMIT, Refused, _validate_source
from app_integrity import InvalidApp, admit_standalone

READY_LIMIT = 1_300_000
SOURCE_SLOT = b'<template id="original-casebook-b64" data-source-sha256=""></template>'


def render_ready(app: bytes, source: bytes) -> bytes:
    if type(app) is not bytes or type(source) is not bytes:
        raise Refused("noncanonical source")
    if not 2 <= len(app) <= APP_LIMIT or not 2 <= len(source) <= SOURCE_LIMIT:
        raise Refused("offline ready-room source length")
    _validate_source(source)
    try:
        admit_standalone(app)
    except InvalidApp as exc:
        raise Refused("unsafe offline app source") from exc
    if app.count(SOURCE_SLOT) != 1:
        raise Refused("missing unique inert Casebook source slot")
    # Base64 is an inert ASCII alphabet; it cannot close a template, change a
    # CSP header, introduce an HTML script, or interpret JSON as markup.
    embedded = (
        b'<template id="original-casebook-b64" data-source-sha256="'
        + sha256(source).hexdigest().encode("ascii")
        + b'">'
        + b64encode(source)
        + b'</template>'
    )
    ready = app.replace(SOURCE_SLOT, embedded)
    if len(ready) > READY_LIMIT:
        raise Refused("offline ready-room limit")
    return ready


def admit_ready(app: bytes, source: bytes, ready: bytes) -> None:
    """Require exact reproduction from the original source; no unknown HTML."""
    if type(ready) is not bytes or len(ready) > READY_LIMIT:
        raise Refused("invalid ready-room bytes")
    if ready != render_ready(app, source):
        raise Refused("private ready-room source or executable markup drift")
