"""W55 fail-closed optional HTML acceptance of truncated raw markup.

Synthetic-only: does not prove installed Markdown/HTML, DOM or browser policy.
"""
from __future__ import annotations

from html import escape
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    synthetic_downstream_adapter_acceptance,
)

_ERROR = "invalid downstream finding html integrity"


class HtmlTruncatedMarkupW55(unittest.TestCase):
    def deny(self, fragment: str) -> None:
        before = fragment[:]
        with self.assertRaises(ValueError) as caught:
            check_conservative_html_fragment(fragment, expected_text="W51")
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(str(caught.exception), _ERROR)
        self.assertEqual(fragment, before)

    def test_truncated_executable_and_attribute_tokens_are_denied(self) -> None:
        for trailing in ("<script", "<iframe", "<svg", "<img src=x",
                         "<p onclick=", "<pre class", "<style", "<form"):
            with self.subTest(trailing=trailing):
                self.deny("<p>W51</p>" + trailing)

    def test_incomplete_comment_doctype_and_angle_tokens_are_denied(self) -> None:
        for trailing in ("<!--", "<!--W51", "<!DOCTYPE", "<!doctype html",
                         "<!", "<?xml", "<", "</", "</p"):
            with self.subTest(trailing=trailing):
                self.deny("<pre>W51</pre>" + trailing)

    def test_malformed_nested_angle_brackets_are_denied(self) -> None:
        for fragment in ("<p>W51 <<script</p>", "<p>W51 <x<y></p>",
                         "<pre>W51 <b <i></pre>"):
            with self.subTest(fragment=fragment):
                self.deny(fragment)

    def test_renderer_adapter_cannot_append_unparsed_markup(self) -> None:
        def poisoned(markdown: str) -> str:
            return "<pre>" + escape(markdown, quote=True) + "</pre><script"
        with self.assertRaisesRegex(ValueError, "^" + _ERROR + "$"):
            synthetic_downstream_adapter_acceptance(poisoned)

    def test_complete_allowlisted_markup_and_literal_escaped_angles_pass(self) -> None:
        for fragment in ("<p>W51 &lt;script&gt; is harmless text</p>",
                         "<pre>W51 2 &lt; 5 &amp; 6 &gt; 4</pre>",
                         "<h2>W51</h2><p>ok<br/>safe</p>",
                         "<blockquote><strong>W51</strong></blockquote>"):
            with self.subTest(fragment=fragment):
                check_conservative_html_fragment(fragment, expected_text="W51")

    def test_parent_escaped_adapter_still_passes(self) -> None:
        value = synthetic_downstream_adapter_acceptance(
            lambda md: "<pre>" + escape(md, quote=True) + "</pre>"
        )
        self.assertRegex(value, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
