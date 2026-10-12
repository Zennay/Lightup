"""Opt-in synthetic HTML nesting preflight; never an installed renderer or sanitizer."""
from __future__ import annotations

from html.parser import HTMLParser
from tests.markdown_html_downstream_contract_w51 import check_conservative_html_fragment

_ERROR = "invalid downstream finding html integrity"
_MAX_HTML_BYTES = 4 * 1024 * 1024
_MAX_NESTING = 64
_VOID = frozenset(("br", "hr"))


class _DepthProbe(HTMLParser):
    """Deny depth overflow before the downstream W51 review."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID:
            if len(self.stack) >= _MAX_NESTING:
                raise ValueError(_ERROR)
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag not in _VOID:
            if not self.stack or self.stack.pop() != tag:
                raise ValueError(_ERROR)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID:
            raise ValueError(_ERROR)


def check_depth_bounded_html_fragment_w60(
    fragment: object, *, expected_text: str, required_text: tuple[str, ...] = ()
) -> None:
    """Add a conservative lab-only depth budget to W51's strict reviewer."""
    if type(fragment) is not str:
        raise ValueError(_ERROR)
    try:
        if len(fragment.encode("utf-8", "strict")) > _MAX_HTML_BYTES:
            raise ValueError(_ERROR)
    except UnicodeError:
        raise ValueError(_ERROR) from None
    probe = _DepthProbe()
    try:
        probe.feed(fragment)
        probe.close()
    except (ValueError, AssertionError):
        raise ValueError(_ERROR) from None
    if probe.stack:
        raise ValueError(_ERROR)
    check_conservative_html_fragment(
        fragment, expected_text=expected_text, required_text=required_text
    )
