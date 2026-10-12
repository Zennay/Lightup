"""W54 opt-in Unicode-obscured synthetic HTML canary acceptance.

All HTML and findings are invented strings; this does not test an installed
Markdown renderer, real tenants, clients or target systems.
"""
from __future__ import annotations

from html import escape
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    synthetic_downstream_adapter_acceptance,
)

_PRIVATE = "SYNTHETIC-W51-METADATA-PRIVATE"
_ERROR = "invalid downstream finding html integrity"


class HtmlUnicodeCanaryW54(unittest.TestCase):
    def assert_denied(self, fragment: str) -> None:
        with self.assertRaises(ValueError) as caught:
            check_conservative_html_fragment(fragment, expected_text="W51")
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(str(caught.exception), _ERROR)

    def test_invisible_codepoints_inside_private_marker_are_denied(self) -> None:
        # Each synthetic insertion must be rejected even though an exact
        # substring search cannot see the original ASCII marker.
        for cp in ("\u00ad", "\u034f", "\u061c", "\u200b", "\u200c",
                   "\u200d", "\u200e", "\u200f", "\u202e", "\u2060",
                   "\u2066", "\u2069", "\ufeff", "\ufe0f"):
            source = _PRIVATE[:10] + cp + _PRIVATE[10:]
            with self.subTest(codepoint=hex(ord(cp))):
                self.assert_denied("<p>W51 " + source + "</p>")

    def test_html_encoded_invisible_markers_are_denied(self) -> None:
        for hidden in ("&#8203;", "&#x200D;", "&#x2060;", "&zwj;"):
            source = _PRIVATE[:10] + hidden + _PRIVATE[10:]
            with self.subTest(hidden=hidden):
                self.assert_denied("<pre>W51 " + source + "</pre>")
                self.assert_denied("<pre>W51 " + escape(source) + "</pre>")

    def test_unicode_compatibility_confusable_canary_is_denied(self) -> None:
        for source in ("\uff33" + _PRIVATE[1:],
                       _PRIVATE[:10] + "\uff2d" + _PRIVATE[11:]):
            with self.subTest(source=source):
                self.assert_denied("<p>W51 " + source + "</p>")

    def test_cross_tag_split_and_entity_invisible_combination_is_denied(self) -> None:
        head = escape(_PRIVATE[:10] + "&#8203;")
        tail = _PRIVATE[10:]
        self.assert_denied("<h2>W51</h2><p>" + head + "</p><p>" + tail + "</p>")

    def test_adapter_cannot_emit_obscured_canary(self) -> None:
        def poisoned_text_adapter(markdown: str) -> str:
            return "<pre>" + escape(markdown) + "\n" + (
                _PRIVATE[:10] + "\u200b" + _PRIVATE[10:]) + "</pre>"
        with self.assertRaisesRegex(ValueError, "^" + _ERROR + "$"):
            synthetic_downstream_adapter_acceptance(poisoned_text_adapter)

    def test_ordinary_international_text_and_emoji_joiners_remain_accepted(self) -> None:
        for fragment in (
            "<p>W51 café 東京 مرحبا €</p>",
            "<pre>W51 👩\u200d💻 family 👨\u200d👩\u200d👧</pre>",
            "<p>W51 \u2764\ufe0f &amp; safe &#x1F6E1;</p>",
            "<p>W51 Fullwidth \uff33 is not a secret</p>",
            "<p>W51 a\u0301 combining accent and \u200bordinary spacing</p>",
        ):
            with self.subTest(fragment=fragment):
                check_conservative_html_fragment(fragment, expected_text="W51")

    def test_original_text_only_adapter_positive_control_remains_green(self) -> None:
        digest = synthetic_downstream_adapter_acceptance(
            lambda text: "<pre>" + escape(text, quote=True) + "</pre>"
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
