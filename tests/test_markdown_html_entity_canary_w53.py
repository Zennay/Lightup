"""W53 independent synthetic nested HTML-entity canary acceptance tests.

All fixtures are local strings. No real Markdown engine, client, or targets.
"""
from __future__ import annotations

from html import escape
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    synthetic_downstream_adapter_acceptance,
)


_CANARY = "SYNTHETIC-W51-METADATA-PRIVATE"
_ERROR = "invalid downstream finding html integrity"


class HtmlEntityCanaryW53(unittest.TestCase):
    def assert_denied(self, fragment: str) -> None:
        with self.assertRaises(ValueError) as error:
            check_conservative_html_fragment(fragment, expected_text="W51")
        self.assertIs(type(error.exception), ValueError)
        self.assertEqual(str(error.exception), _ERROR)

    def test_raw_and_singly_encoded_private_canary_fail(self) -> None:
        for source in (_CANARY, "&#83;" + _CANARY[1:], "&#x53;" + _CANARY[1:]):
            with self.subTest(source=source):
                self.assert_denied("<p>W51 " + source + "</p>")

    def test_double_and_triple_encoded_decimal_canary_fail(self) -> None:
        source = "&#83;" + _CANARY[1:]
        for depth in (2, 3, 4):
            fragment = source
            for _ in range(depth):
                fragment = escape(fragment)
            with self.subTest(depth=depth):
                self.assert_denied("<pre>W51 " + fragment + "</pre>")

    def test_double_and_triple_encoded_hex_canary_fail(self) -> None:
        source = "&#x53;" + _CANARY[1:]
        for depth in (2, 3, 4):
            fragment = source
            for _ in range(depth):
                fragment = escape(fragment)
            with self.subTest(depth=depth):
                self.assert_denied("<p>W51 " + fragment + "</p>")

    def test_entity_encoded_private_canary_split_across_allowed_tags_fail(self) -> None:
        head = escape(escape("&#83;YNTHETIC-"))
        tail = "W51-METADATA-PRIVATE"
        self.assert_denied("<h2>W51</h2><p>" + head + "</p><p>" + tail + "</p>")

    def test_deep_entity_encoding_is_ambiguous_and_denied(self) -> None:
        source = "&#83;" + _CANARY[1:]
        for _ in range(10):
            source = escape(source)
        self.assert_denied("<p>W51 " + source + "</p>")
        # Even benign >8 nested entity levels are rejected, by design:
        # this lab gate must not claim that it decoded hidden content.
        benign = "&amp;"
        for _ in range(10):
            benign = escape(benign)
        self.assert_denied("<p>W51 " + benign + "</p>")

    def test_ordinary_escaped_text_and_unicode_remain_accepted(self) -> None:
        for fragment in (
            "<p>W51 &lt;script&gt;not active&lt;/script&gt; €</p>",
            "<pre>W51 &amp;amp; https://synthetic.invalid/ not a hyperlink</pre>",
            "<p>W51 café, 東京, emoji 🛡️ &quot;quoted&quot;</p>",
        ):
            with self.subTest(fragment=fragment):
                check_conservative_html_fragment(fragment, expected_text="W51")

    def test_existing_text_only_adapter_control_still_passes(self) -> None:
        # The known safe-text adapter is NOT a Markdown-to-HTML engine.
        digest = synthetic_downstream_adapter_acceptance(
            lambda markdown: "<pre>" + escape(markdown, quote=True) + "</pre>"
        )
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
