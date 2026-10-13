"""Issue #1221: synthetic, tests-only structured-field Markdown injection matrix.

W46 opt-in renderer only. No network, database, auth, live target or default
reporting paths. A passing parser test is not browser/DOM/CSP or tenant proof.
"""
from __future__ import annotations

import copy
from html.parser import HTMLParser
import unittest

from lightup.finding_markdown_escaped_optin_w31 import (
    render_escaped_evidence_markdown_optin_w31 as render,
)
from lightup.models import Finding, Severity

try:
    import mistune
except ImportError:
    mistune = None
try:
    from markdown_it import MarkdownIt
except ImportError:
    MarkdownIt = None


class _Capture(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.tags = []

    def handle_data(self, value):
        self.text.append(value)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


def _sample(field, value):
    fields = dict(finding_id="synthetic-81", title="Synthetic finding",
                  severity=Severity.INFO, target="example.invalid",
                  evidence=["Safe observation"], remediation="Offline only",
                  metadata={"private": "W81_CANARY_DO_NOT_RENDER"})
    fields[field] = value
    return Finding(**fields)


@unittest.skipUnless(mistune is not None and MarkdownIt is not None,
                     "optional real Markdown parsers unavailable")
class W81StructuredMarkupLiteral(unittest.TestCase):
    def _check(self, field, value):
        item = _sample(field, value)
        original = copy.deepcopy(item)
        markdown = render([item])
        for name, html in (
            ("mistune", mistune.create_markdown(escape=True)(markdown)),
            ("markdown-it", MarkdownIt("commonmark", {"html": False}).render(markdown)),
        ):
            with self.subTest(field=field, parser=name, value=value):
                capture = _Capture()
                capture.feed(html)
                visible = "".join(capture.text)
                self.assertIn(value, visible)
                self.assertFalse(set(capture.tags) & {"a", "img", "script", "iframe", "math"})
                self.assertEqual(1, capture.tags.count("h2"))
                self.assertNotIn("W81_CANARY_DO_NOT_RENDER", html)
        self.assertEqual(item, original)

    def test_title_link_is_plain_text(self):
        self._check("title", "[verify](https://example.invalid/x)")

    def test_title_emphasis_is_plain_text(self):
        self._check("title", "**important** _not-italic_")

    def test_title_inline_code_is_plain_text(self):
        self._check("title", "Literal `admin` text")

    def test_finding_id_image_is_plain_text(self):
        self._check("finding_id", "![badge](https://example.invalid/a.png)")

    def test_target_link_is_plain_text(self):
        self._check("target", "[asset](https://example.invalid/path)")

    def test_remediation_inline_code_is_plain_text(self):
        self._check("remediation", "Use `safe --offline` only")

    def test_remediation_emphasis_is_plain_text(self):
        self._check("remediation", "Do **not** run _live_ checks")

    def test_structured_field_header_marker_is_plain_text(self):
        self._check("title", "# Synthetic title")

    def test_malformed_late_field_fails_atomically(self):
        items = [_sample("title", "Valid"), _sample("finding_id", "invalid\rfield")]
        before = copy.deepcopy(items)
        with self.assertRaises(ValueError):
            render(items)
        self.assertEqual(items, before)


if __name__ == "__main__":
    unittest.main()
