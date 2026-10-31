"""Fail-closed admission of inert HTML in unsigned synthetic HUMAN ZIPs.

A digest-verified ZIP can still be forged: its unsigned manifest offers no
origin authentication. Never accept active content or remote navigation merely
because an attacker recomputed the member hashes. This is content safety, not
source identity or permission to assess real targets.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re

_ALLOWED_TAGS = frozenset((
    "html", "head", "body", "meta", "title", "style", "header", "main",
    "footer", "nav", "section", "div", "p", "h1", "h2", "h3", "strong",
    "span", "a", "table", "thead", "tbody", "tr", "td", "th", "caption",
    "details", "summary", "ul", "li",
))
_ALLOWED_ATTRIBUTES = frozenset((
    "id", "class", "href", "lang", "charset", "name", "content",
    "http-equiv", "role", "tabindex", "scope", "aria-label",
    "aria-labelledby",
))
_ALLOWED_CSP = frozenset((
    "default-src 'none'; style-src 'unsafe-inline'",
    "default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; "
    "img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'",
))
_LOCAL_LINKS = frozenset((
    "#content", "history.html", "index.html", "README.txt", "review.md",
    "review.csv", "review.json",
))
_ANCHOR = re.compile(r"(?:history\.html)?#(?:pair-[1-8]-[1-8]|archive-[1-8])\Z")
_FORBIDDEN_CSS = ("url(", "@import", "expression(", "-moz-binding")


class _InertHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp_count = 0
        self.html_count = 0
        self.body_count = 0
        self.in_style = False

    def handle_decl(self, decl: str) -> None:
        if decl.lower() != "doctype html":
            raise ValueError("invalid offline HTML declaration")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _ALLOWED_TAGS:
            raise ValueError("active or unknown HTML element")
        values = dict(attrs)
        if (len(values) != len(attrs) or set(values) - _ALLOWED_ATTRIBUTES
                or any(v is None or len(v) > 440 or "\x00" in v
                       for v in values.values())):
            raise ValueError("unknown or invalid HTML attribute")
        if tag != "a" and "href" in values:
            raise ValueError("unexpected HTML navigation")
        if "href" in values:
            target = values["href"]
            if target not in _LOCAL_LINKS and not _ANCHOR.fullmatch(target):
                raise ValueError("remote or unsafe HTML navigation")
        if tag == "meta":
            if values.get("http-equiv") is not None:
                if (values.get("http-equiv") != "Content-Security-Policy"
                        or values.get("content") not in _ALLOWED_CSP):
                    raise ValueError("unsafe HTML content policy")
                self.csp_count += 1
            elif values.get("charset") != "utf-8" and values.get("name") != "viewport":
                raise ValueError("unexpected HTML meta")
        elif "content" in values or "http-equiv" in values:
            raise ValueError("unexpected HTML content attribute")
        if tag == "html":
            self.html_count += 1
        if tag == "body":
            self.body_count += 1
        if tag == "style":
            if self.in_style:
                raise ValueError("nested HTML style")
            self.in_style = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            raise ValueError("unrecognized standalone HTML element")
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag not in _ALLOWED_TAGS:
            raise ValueError("unexpected HTML closing tag")
        if tag == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style and any(x in data.lower() for x in _FORBIDDEN_CSS):
            raise ValueError("CSS external resource or active expression")

    def handle_comment(self, data: str) -> None:
        raise ValueError("unexpected HTML comment")

    def handle_pi(self, data: str) -> None:
        raise ValueError("unexpected HTML processing instruction")


def admit_inert_html(data: bytes) -> None:
    """Validate the seven-file package's HTML without executing or fetching it."""
    if len(data) > 1024 * 1024:
        raise ValueError("offline HTML too large")
    source = data.decode("utf-8", errors="strict")
    if not source.lower().startswith("<!doctype html>"):
        raise ValueError("missing HTML5 declaration")
    parser = _InertHTML()
    parser.feed(source)
    parser.close()
    if parser.csp_count != 1 or parser.html_count != 1 or parser.body_count > 1:
        raise ValueError("unsafe or incomplete offline HTML")
