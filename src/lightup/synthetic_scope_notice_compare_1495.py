"""Two-preview comparison for fictional scopes only. NEVER authority.

Unwired: compares two *untrusted*, internally consistent, synthetic-only
operator notices. A comparison does not prove identity, consent, revocation,
grant issuance or that either preview came from a trusted source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
import json

from .synthetic_scope_notice_consumer_1495 import (
    _deny_nonfinite, _unique_json_keys, decode_fictional_notice_for_display,
)
from .synthetic_scope_notice_html_1495 import _shell

_MAX_PAIR_BYTES = 131072
_MAX_HTML_CHARS = 65536
_PAIR_KEYS = frozenset(("before", "after"))

_GATE_LINES = (
    "Independently verify client and operator identity",
    "Check actual ownership and scope before execution",
    "Verify revocation against the trusted store at actual use",
    "Obtain independent security/privacy review and explicit human GO",
)
_LABELS = ("Asset", "Capability", "Before risk / window", "After risk / window", "Change")
_CHANGE_LABELS = {
    "added": "ONLY IN AFTER — NOT GRANTED",
    "removed": "ONLY IN BEFORE — NOT REVOKED",
    "changed": "PROPOSED DETAILS CHANGED",
    "same": "IDENTICAL FICTIONAL ENTRY",
}


@dataclass(frozen=True, slots=True)
class FictionalScopeComparison:
    status: str
    html: str
    compared: int
    changes: int
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _hold() -> FictionalScopeComparison:
    body = (
        '<header class="warning" role="alert"><span class="tag stop">HOLD</span>'
        '<h1>NOT AUTHORIZED — COMPARISON REJECTED</h1>'
        '<p>The two fictional review documents were rejected. No records, '
        'permissions, targets or untrusted input are displayed.</p></header>'
        '<footer>HOLD · authorized=false · consent_verified=false · '
        'dispatch_allowed=false · release_allowed=false</footer>'
    )
    return FictionalScopeComparison("HOLD", _shell(language="en", body=body), 0, 0)


def _validated_rows(view):
    """Extract row data from a report ALREADY checked against pure producer."""
    lines = view.notice.split("\n")
    result = {}
    for line in lines[6:6 + view.reviewed]:
        cells = line[2:].split(" | ")
        # The consumer performed full original-producer reconstruction, so
        # parsing here is just for presentation, NEVER authorization.
        asset, capability, risk, start, end = cells
        result[(asset, capability)] = (risk, start, end)
    return result


def compare_fictional_scope_envelopes(raw: bytes) -> FictionalScopeComparison:
    """Display-only delta of two valid fictional REVIEW_ONLY JSON envelopes.

    Fail atomically: any invalid half means NO details from either half.
    The response never confers authorization, regardless of changes count.
    """
    if type(raw) is not bytes or not (1 <= len(raw) <= _MAX_PAIR_BYTES):
        return _hold()
    try:
        pair = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_json_keys,
            parse_constant=_deny_nonfinite,
        )
        if type(pair) is not dict or frozenset(pair) != _PAIR_KEYS:
            return _hold()
        docs = []
        for key in ("before", "after"):
            candidate = pair[key]
            if type(candidate) is not dict:
                return _hold()
            serialized = json.dumps(
                candidate, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("ascii")
            view = decode_fictional_notice_for_display(serialized)
            if view is None or view.status != "REVIEW_ONLY":
                return _hold()
            docs.append(view)
        old, new = docs
        old_rows, new_rows = _validated_rows(old), _validated_rows(new)
        keys = sorted(set(old_rows) | set(new_rows))
        if len(keys) > 64:
            return _hold()
        body_rows = []
        changes = 0
        for asset, capability in keys:
            left, right = old_rows.get((asset, capability)), new_rows.get((asset, capability))
            if left is None:
                kind = "added"
            elif right is None:
                kind = "removed"
            elif left != right:
                kind = "changed"
            else:
                kind = "same"
            if kind != "same":
                changes += 1

            def detail(item):
                return "—" if item is None else " / ".join(item)

            body_rows.append(
                "<tr><th scope=\"row\"><code>" + escape(asset)
                + "</code></th><td><code>" + escape(capability)
                + "</code></td><td>" + escape(detail(left))
                + "</td><td>" + escape(detail(right))
                + "</td><td>" + escape(_CHANGE_LABELS[kind]) + "</td></tr>"
            )
        headings = "".join('<th scope="col">' + escape(label) + "</th>" for label in _LABELS)
        gates = "".join(
            '<li><strong class="pending">PENDING — </strong>'
            + escape(task) + "</li>" for task in _GATE_LINES
        )
        body = (
            '<header class="warning" role="alert">'
            '<span class="tag stop">REVIEW_ONLY</span>'
            '<h1>NOT AUTHORIZED — FICTIONAL SCOPE COMPARISON</h1>'
            '<p>Changes below describe two untrusted fictional documents, '
            'NOT new grants, deletions, consent, or a real revocation event.</p></header>'
            '<section aria-labelledby="diff-title"><h2 id="diff-title">'
            'Proposed differences only</h2>'
            '<p class="meta">Fictional before entries: ' + str(old.reviewed)
            + ' · Fictional after entries: ' + str(new.reviewed)
            + ' · Proposed changed pairs: ' + str(changes) + '</p>'
            '<div class="wrap"><table><thead><tr>' + headings
            + '</tr></thead><tbody>' + "".join(body_rows)
            + '</tbody></table></div></section>'
            '<section aria-labelledby="pending-title">'
            '<h2 id="pending-title">Unverified release prerequisites</h2>'
            '<ol class="gates">' + gates + '</ol></section>'
            '<footer>NOT AUTHORIZED · authorized=false · consent_verified=false · '
            'dispatch_allowed=false · release_allowed=false'
            '<p>Before/after are display labels only. This cannot create '
            'or revoke access to any live asset.</p></footer>'
        )
        page = _shell(language="en", body=body)
        if len(page) > _MAX_HTML_CHARS:
            return _hold()
        return FictionalScopeComparison("REVIEW_ONLY", page, 2, changes)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError, KeyError):
        return _hold()
