"""Pinned-CSP admission for the actual portable LightUp offline Impact Map.

Runtime admission code, not QA: a private packet may contain only a
self-contained app whose executing JavaScript and stylesheet are byte-pinned
by its own restrictive CSP. Hashes are not signatures or owner attestation.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import re


class InvalidApp(ValueError):
    pass


def admit_standalone(raw: bytes) -> None:
    if type(raw) is not bytes or not 2 <= len(raw) <= 524288:
        raise InvalidApp("invalid offline application size")
    try:
        html = raw.decode("utf-8")
        if not html.startswith("<!doctype html>"):
            raise InvalidApp("wrong application")
        head_end = html.index("</head>")
        first_style = html.index("<style>")
        style_end = html.index("</style>", first_style)
        script_start = html.index("<script>", style_end)
        script_end = html.index("</script>", script_start)
        if not (0 < first_style < style_end < head_end < script_start < script_end):
            raise InvalidApp("unsafe script placement")
        if html.count("<script>") != 1 or html.count("</script>") != 1:
            raise InvalidApp("extra active scripts")
        if '<title>LightUp | Scope Impact Map</title>' not in html[:head_end]:
            raise InvalidApp("unexpected application")
        head = html[:head_end]
        meta = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', head)
        if len(meta) != 1:
            raise InvalidApp("ambiguous CSP")
        policy = meta[0]
        directives = [item.strip() for item in policy.split(";") if item.strip()]
        names = [x.split(" ", 1)[0] for x in directives]
        if len(names) != len(set(names)):
            raise InvalidApp("duplicate CSP directive")
        expected = {
            "default-src": "'none'",
            "connect-src": "'none'",
            "img-src": "'none'",
            "object-src": "'none'",
            "base-uri": "'none'",
            "form-action": "'none'",
            # Static style attributes are allowed; executable style blocks
            # are accepted exclusively by their computed SHA-256 CSP.
            "style-src-attr": "'unsafe-inline'",
        }
        directives_by_name = {x.split(" ", 1)[0]: x.partition(" ")[2] for x in directives}
        for name, value in expected.items():
            if directives_by_name.get(name) != value:
                raise InvalidApp("unsafe offline CSP")
        for name, body in (
            ("style-src-elem", html[first_style + len("<style>"):style_end]),
            ("script-src", html[script_start + len("<script>"):script_end]),
        ):
            value = "'sha256-" + base64.b64encode(sha256(body.encode("utf-8")).digest()).decode("ascii") + "'"
            if directives_by_name.get(name) != value:
                raise InvalidApp("source/CSP digest mismatch")
        if set(directives_by_name) != set(expected) | {"style-src-elem", "script-src"}:
            raise InvalidApp("unexpected app CSP")
    except (ValueError, UnicodeError, IndexError) as exc:
        raise InvalidApp("offline application cannot be admitted") from exc
