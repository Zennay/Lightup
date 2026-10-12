"""W58 optional HTML reviewer strictly validates raw start-tag lexical shape.

Synthetic-only lab gate. This does not implement a browser tokenizer, pinned
Markdown renderer, CSP policy, sanitization, tenant admission or deployment.
"""
from __future__ import annotations

from html import escape
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    synthetic_downstream_adapter_acceptance,
)

_ERROR = "invalid downstream finding html integrity"


class HtmlStartTagLexicalW58(unittest.TestCase):
    def reject(self, html: str) -> None:
        snapshot = html[:]
        with self.assertRaises(ValueError) as ctx:
            check_conservative_html_fragment(html, expected_text="W51")
        self.assertIs(type(ctx.exception), ValueError)
        self.assertEqual(str(ctx.exception), _ERROR)
        self.assertEqual(html, snapshot)

    def test_htmlparser_discards_slash_whitespace_in_nonvoid_start_tags(self) -> None:
        for opening in ("<p/ >", "<p / >", "<h2/ >", "<strong / >",
                        "<blockquote/ >", "<pre/ >"):
            with self.subTest(opening=opening):
                close = opening[1:].split("/")[0].strip()
                self.reject(opening + "W51</" + close + ">")

    def test_void_tags_with_malformed_slash_syntax_are_denied(self) -> None:
        for opening in ("<br / >", "<hr / >", "<br///>", "<hr / / >"):
            with self.subTest(opening=opening):
                self.reject("<p>W51" + opening + "</p>")

    def test_whitespace_only_start_tag_tails_are_conservatively_denied(self) -> None:
        for opening in ("<p >", "<p  >", "<p\n>", "<p\t>", "<p\r>"):
            with self.subTest(opening=repr(opening)):
                self.reject(opening + "W51</p>")

    def test_renderer_adapter_cannot_emit_noncanonical_raw_tag(self) -> None:
        def poisoned(markdown: str) -> str:
            return "<pre/ >" + escape(markdown, quote=True) + "</pre>"

        with self.assertRaisesRegex(ValueError, "^" + _ERROR + "$"):
            synthetic_downstream_adapter_acceptance(poisoned)

    def test_valid_standard_void_and_nested_tags_and_unicode_pass(self) -> None:
        for html in (
            "<p>W51</p>",
            "<P>W51</P>",
            "<h2>W51</h2><hr/>",
            "<p>W51<br/>ok</p>",
            "<p>W51<br />ok<hr />safe</p>",
            "<blockquote><strong>W51 東京 naïve</strong></blockquote>",
        ):
            with self.subTest(html=html):
                check_conservative_html_fragment(html, expected_text="W51")

    def test_escaped_ambiguous_tag_and_text_control_still_pass(self) -> None:
        check_conservative_html_fragment(
            "<pre>W51 literal &lt;p/ &gt; and &lt;br / &gt;</pre>",
            expected_text="W51",
        )
        digest = synthetic_downstream_adapter_acceptance(
            lambda markdown: "<pre>" + escape(markdown, quote=True) + "</pre>"
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
