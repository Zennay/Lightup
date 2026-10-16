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


_NL_LABELS = ("Systeem", "Handeling", "Voor: risico / periode", "Na: risico / periode", "Verschil")
_NL_CHANGE_LABELS = {
    "added": "ALLEEN IN NA — NIET TOEGEKEND",
    "removed": "ALLEEN IN VOOR — NIET INGETROKKEN",
    "changed": "VOORGESTELDE DETAILS VERANDERD",
    "same": "IDENTIEK FICTIEF VOORSTEL",
}
_NL_GATE_LINES = (
    "Controleer identiteit van cliënt en operator onafhankelijk",
    "Laat echte eigendom en exacte scope vóór uitvoering controleren",
    "Controleer intrekking bij werkelijk gebruik tegen de vertrouwde bron",
    "Verkrijg onafhankelijke security-/privacyreview en menselijke GO",
)



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


def _hold(language: str = "en") -> FictionalScopeComparison:
    dutch = type(language) is str and language == "nl"
    heading = (
        "NOT AUTHORIZED — NIET GEAUTORISEERD | VERGELIJKING AFGEWEZEN"
        if dutch else "NOT AUTHORIZED — COMPARISON REJECTED"
    )
    message = (
        "De twee fictieve beoordelingen zijn afgewezen. Er worden geen "
        "systemen, bevoegdheden of ongecontroleerde gegevens getoond."
        if dutch else
        "The two fictional review documents were rejected. No records, "
        "permissions, targets or untrusted input are displayed."
    )
    body = (
        '<header class="warning" role="alert"><span class="tag stop">HOLD</span>'
        "<h1>" + escape(heading) + "</h1><p>" + escape(message)
        + '</p></header><footer>HOLD · authorized=false · consent_verified=false · '
        'dispatch_allowed=false · release_allowed=false</footer>'
    )
    return FictionalScopeComparison(
        "HOLD", _shell(language="nl" if dutch else "en", body=body), 0, 0,
    )


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


def compare_fictional_scope_envelopes(raw: bytes, *, language: str = "en") -> FictionalScopeComparison:
    """Display-only delta of two valid fictional REVIEW_ONLY JSON envelopes.

    Fail atomically: any invalid half means NO details from either half.
    The response never confers authorization, regardless of changes count.
    """
    if type(language) is not str or language not in ("en", "nl"):
        return _hold(language)
    dutch = language == "nl"
    labels = _NL_LABELS if dutch else _LABELS
    change_labels = _NL_CHANGE_LABELS if dutch else _CHANGE_LABELS
    gate_lines = _NL_GATE_LINES if dutch else _GATE_LINES
    if type(raw) is not bytes or not (1 <= len(raw) <= _MAX_PAIR_BYTES):
        return _hold(language)
    try:
        pair = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_json_keys,
            parse_constant=_deny_nonfinite,
        )
        if type(pair) is not dict or frozenset(pair) != _PAIR_KEYS:
            return _hold(language)
        docs = []
        for key in ("before", "after"):
            candidate = pair[key]
            if type(candidate) is not dict:
                return _hold(language)
            serialized = json.dumps(
                candidate, sort_keys=True, ensure_ascii=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("ascii")
            view = decode_fictional_notice_for_display(serialized)
            if view is None or view.status != "REVIEW_ONLY":
                return _hold(language)
            docs.append(view)
        old, new = docs
        old_rows, new_rows = _validated_rows(old), _validated_rows(new)
        keys = sorted(set(old_rows) | set(new_rows))
        if len(keys) > 64:
            return _hold(language)
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
                + "</td><td>" + escape(change_labels[kind]) + "</td></tr>"
            )
        headings = "".join('<th scope="col">' + escape(label) + "</th>" for label in labels)
        gates = "".join(
            '<li><strong class="pending">PENDING — </strong>'
            + escape(task) + "</li>" for task in gate_lines
        )
        title = (
            "NOT AUTHORIZED — NIET GEAUTORISEERD | FICTIEVE SCOPEVERGELIJKING"
            if dutch else "NOT AUTHORIZED — FICTIONAL SCOPE COMPARISON"
        )
        intro = (
            "Dit zijn wijzigingen tussen twee niet-geverifieerde fictieve "
            "documenten, GEEN verleende rechten, toestemming of echte intrekking."
            if dutch else
            "Changes below describe two untrusted fictional documents, "
            "NOT new grants, deletions, consent, or a real revocation event."
        )
        section_title = "Uitsluitend voorgestelde verschillen" if dutch else "Proposed differences only"
        info = (
            ("Fictieve regels voor: " + str(old.reviewed)
             + " · Fictieve regels na: " + str(new.reviewed)
             + " · Veranderde voorstellen: " + str(changes))
            if dutch else
            ("Fictional before entries: " + str(old.reviewed)
             + " · Fictional after entries: " + str(new.reviewed)
             + " · Proposed changed pairs: " + str(changes))
        )
        pending_title = "Nog niet geverifieerde vrijgavevoorwaarden" if dutch else "Unverified release prerequisites"
        footer_message = (
            "Voor/na zijn uitsluitend schermlabels. Dit verleent of trekt "
            "nooit rechten op echte systemen in."
            if dutch else
            "Before/after are display labels only. This cannot create "
            "or revoke access to any live asset."
        )
        body = (
            '<header class="warning" role="alert">'
            '<span class="tag stop">REVIEW_ONLY</span><h1>' + escape(title)
            + '</h1><p>' + escape(intro) + '</p></header>'
            '<section aria-labelledby="diff-title"><h2 id="diff-title">'
            + escape(section_title) + '</h2><p class="meta">' + escape(info)
            + '</p><div class="wrap"><table><thead><tr>' + headings
            + '</tr></thead><tbody>' + "".join(body_rows)
            + '</tbody></table></div></section>'
            '<section aria-labelledby="pending-title"><h2 id="pending-title">'
            + escape(pending_title) + '</h2><ol class="gates">' + gates
            + '</ol></section>'
            '<footer>NOT AUTHORIZED · authorized=false · consent_verified=false · '
            'dispatch_allowed=false · release_allowed=false<p>'
            + escape(footer_message) + '</p></footer>'
        )
        page = _shell(language=language, body=body)
        if len(page) > _MAX_HTML_CHARS:
            return _hold(language)
        return FictionalScopeComparison("REVIEW_ONLY", page, 2, changes)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError, KeyError):
        return _hold(language)
