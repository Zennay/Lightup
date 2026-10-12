"""W57 reject malformed HTML end-tag suffixes in optional synthetic reviewer.

Python html.parser may ignore trailing bytes on a closing tag. This suite is
strict lab acceptance only, not an HTML5 browser, deployed parser or XSS proof.
"""
from __future__ import annotations

from html import escape
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    synthetic_downstream_adapter_acceptance,
)

_ERROR = "invalid downstream finding html integrity"


class HtmlEndTagSuffixW57(unittest.TestCase):
    def reject(self, fragment: str) -> None:
        unchanged = fragment[:]
        with self.assertRaises(ValueError) as caught:
            check_conservative_html_fragment(fragment, expected_text="W51")
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(str(caught.exception), _ERROR)
        self.assertEqual(fragment, unchanged)

    def test_parser_ignored_closing_tag_suffixes_are_denied(self) -> None:
        # Several suffixes are swallowed by Python HTMLParser.handle_endtag,
        # whose callback exposes the normalized name but not raw token bytes.
        for suffix in (" data-x=1", " unexpected", " /junk", " 4", " /", " / ",
                       "\t", "  ", " =bad"):
            with self.subTest(suffix=repr(suffix)):
                self.reject("<p>W51</p" + suffix + ">")

    def test_endtag_comment_and_attribute_shapes_cannot_be_normalized_away(self) -> None:
        for fragment in (
            "<p>W51</p onclick=alert(1)>",
            "<pre>W51</pre hidden=synthetic>",
            "<h2>W51</h2 invalid><p>still here</p>",
            "<ul><li>W51</li bogus></ul>",
        ):
            with self.subTest(fragment=fragment):
                self.reject(fragment)

    def test_poisoned_adapter_cannot_append_bogus_endtag_attributes(self) -> None:
        def poisoned(markdown: str) -> str:
            return "<pre>" + escape(markdown, quote=True) + "</pre extra>"

        with self.assertRaisesRegex(ValueError, "^" + _ERROR + "$"):
            synthetic_downstream_adapter_acceptance(poisoned)

    def test_canonical_balanced_tags_and_ascii_case_still_pass(self) -> None:
        for fragment in (
            "<p>W51</p>",
            "<P>W51</P>",
            "<h2>W51</h2><p>safe <em>content</em></p>",
            "<pre>W51 \u6771\u4eac caf\u00e9</pre>",
            "<ul><li>W51</li><li>ok</li></ul>",
        ):
            with self.subTest(fragment=fragment):
                check_conservative_html_fragment(fragment, expected_text="W51")

    def test_escaped_literal_bogus_endtag_is_safe_display_text(self) -> None:
        check_conservative_html_fragment(
            "<p>W51 &lt;/p data-x=1&gt; is a literal sample</p>",
            expected_text="W51",
        )

    def test_inherited_escaped_text_adapter_remains_a_synthetic_control(self) -> None:
        digest = synthetic_downstream_adapter_acceptance(
            lambda markdown: "<pre>" + escape(markdown, quote=True) + "</pre>"
        )
        self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
