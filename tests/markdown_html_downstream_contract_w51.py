"""W51 explicit opt-in synthetic downstream Markdown-to-HTML acceptance gate.

This is deliberately *not* a Markdown/HTML parser or sanitizer: callers must
explicitly supply the actual pinned downstream engine via module:callable.
A passing synthetic fixture cannot authorize production, retest or targets.
"""
from __future__ import annotations

import copy
import hashlib
from html import unescape
from html.parser import HTMLParser
import importlib
import sys
from typing import Callable
from unicodedata import normalize

from lightup.finding_markdown_escaped_optin_w31 import (
    render_escaped_evidence_markdown_optin_w31,
)
from lightup.models import Finding, RetestStatus, Severity

_ERROR = "invalid downstream finding html integrity"
_MAX_HTML_BYTES = 4 * 1024 * 1024
_PRIVATE = "SYNTHETIC-W51-METADATA-PRIVATE"
_VISIBLE = "W51_VISIBLE_EVIDENCE_TOKEN"
# Synthetic *diagnostic* only: strip known zero-width / formatting characters
# for marker matching, never from the caller's HTML or persisted evidence.
# A real content/secret privacy policy requires a separate reviewed engine.
_CANARY_IGNORE = str.maketrans("", "", (
    "\u00ad\u034f\u061c\u180e\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062"
    "\u2063\u2064\u2066\u2067\u2068\u2069\ufeff\ufe0e\ufe0f"
))


def _has_visible_synthetic_canary(text: str) -> bool:
    if _PRIVATE in text:
        return True
    if text.isascii():
        return False
    # The caller has already enforced the 4 MiB HTML byte input ceiling.
    # NFKC/format removal are for refusal only: never rewrite report data.
    return _PRIVATE in normalize("NFKC", text.translate(_CANARY_IGNORE))

# Intentionally reject hyperlinks and *all* attributes, including class.
# Linkification, MathML, images, inline CSS and extensions need a separate,
# explicit security/privacy review; this is only a conservative lab contract.
_ALLOWED_TAGS = frozenset((
    "blockquote", "br", "code", "em", "h1", "h2", "h3", "h4",
    "hr", "li", "ol", "p", "pre", "span", "strong", "ul",
))
_VOID_TAGS = frozenset(("br", "hr"))


def _assert_private_canary_not_obscured(text: str) -> None:
    """Bounded lab-only entity decoding, denying ambiguous deep nesting.

    This checks only the synthetic private marker, not real client privacy.
    A fragment requiring more than eight decoding passes is refused rather
    than silently classified as safe; no decoded value is returned.
    """
    for _ in range(8):
        if _has_visible_synthetic_canary(text):
            raise ValueError(_ERROR)
        decoded = unescape(text)
        if decoded == text:
            return
        text = decoded
    raise ValueError(_ERROR)


class _RestrictedFragment(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.data: list[str] = []
        self.seen_tag = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _ALLOWED_TAGS or attrs:
            raise ValueError(_ERROR)
        self.seen_tag = True
        if tag not in _VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID_TAGS or attrs:
            raise ValueError(_ERROR)
        self.seen_tag = True

    def handle_endtag(self, tag: str) -> None:
        if tag not in _ALLOWED_TAGS or tag in _VOID_TAGS:
            raise ValueError(_ERROR)
        if not self.stack or self.stack.pop() != tag:
            raise ValueError(_ERROR)

    def handle_data(self, data: str) -> None:
        self.data.append(data)

    def handle_comment(self, data: str) -> None:
        raise ValueError(_ERROR)

    def handle_decl(self, decl: str) -> None:
        raise ValueError(_ERROR)

    def unknown_decl(self, data: str) -> None:
        raise ValueError(_ERROR)

    def handle_pi(self, data: str) -> None:
        raise ValueError(_ERROR)


def check_conservative_html_fragment(
    fragment: object, *, expected_text: str, required_text: tuple[str, ...] = ()
) -> None:
    """Reject nontrivial DOM surfaces without claiming browser equivalence."""
    if type(fragment) is not str or len(fragment) > _MAX_HTML_BYTES:
        raise ValueError(_ERROR)
    try:
        encoded = fragment.encode("utf-8", "strict")
    except UnicodeError:
        raise ValueError(_ERROR) from None
    if len(encoded) > _MAX_HTML_BYTES:
        raise ValueError(_ERROR)
    # This is a diagnostic privacy canary, not a comprehensive redactor.
    _assert_private_canary_not_obscured(fragment)
    parser = _RestrictedFragment()
    try:
        parser.feed(fragment)
        parser.close()
    except (ValueError, AssertionError):
        raise ValueError(_ERROR) from None
    if parser.stack or not parser.seen_tag:
        raise ValueError(_ERROR)
    visible = "".join(parser.data)
    _assert_private_canary_not_obscured(visible)
    if any(marker not in visible for marker in (expected_text, *required_text)):
        raise ValueError(_ERROR)


def synthetic_downstream_adapter_acceptance(
    convert_markdown_to_html: Callable[[str], str],
) -> str:
    """Return SHA-256 for an accepted synthetic fragment (not real proof)."""
    if not callable(convert_markdown_to_html):
        raise ValueError(_ERROR)
    finding = Finding(
        finding_id="w51:offline-only",
        title="Synthetic [click](javascript:alert(1)) $x$ <svg/onload=alert(1)>",
        severity=Severity.INFO,
        target="https://synthetic.invalid/<img>",
        evidence=[_VISIBLE + " <img src=x onerror=alert(1)>"],
        remediation="Treat raw <script>alert(1)</script> and [links](https://invalid.example) as text",
        retest_status=RetestStatus.NOT_TESTED,
        metadata={"private": {"token": _PRIVATE}},
    )
    before = (
        finding.finding_id, finding.title, finding.target, finding.remediation,
        copy.deepcopy(finding.evidence), copy.deepcopy(finding.metadata),
    )
    markdown = render_escaped_evidence_markdown_optin_w31([finding])
    if _PRIVATE in markdown or r"\$x\$" not in markdown:
        raise ValueError(_ERROR)
    html_fragment = convert_markdown_to_html(markdown)
    check_conservative_html_fragment(
        html_fragment,
        expected_text="W51",
        required_text=("LightUp Assessment Findings", "Synthetic", "Treat raw"),
    )
    after = (
        finding.finding_id, finding.title, finding.target, finding.remediation,
        copy.deepcopy(finding.evidence), copy.deepcopy(finding.metadata),
    )
    if after != before:
        raise ValueError(_ERROR)
    return hashlib.sha256(html_fragment.encode("utf-8", "strict")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "--renderer" or args[1].count(":") != 1:
        print(
            "INCONCLUSIVE: explicit --renderer pinned_module:callable required; "
            "no downstream engine is installed/proven by default",
            file=sys.stderr,
        )
        return 2
    module_name, attribute = args[1].split(":", 1)
    if not module_name or not attribute or attribute.startswith("_"):
        print("INCONCLUSIVE: invalid explicit adapter", file=sys.stderr)
        return 2
    try:
        adapter = getattr(importlib.import_module(module_name), attribute)
        digest = synthetic_downstream_adapter_acceptance(adapter)
    except (ImportError, AttributeError, ValueError, TypeError) as exc:
        print(
            f"REJECTED/INCONCLUSIVE: adapter or strict synthetic HTML contract failed "
            f"({type(exc).__name__})",
            file=sys.stderr,
        )
        return 1
    print(
        "SYNTHETIC-ONLY downstream adapter contract PASS; "
        f"adapter={args[1]}; html_sha256={digest}; "
        "NOT installed security/privacy or release proof"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
