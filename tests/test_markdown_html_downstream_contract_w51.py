"""W51 offline synthetic reviewer tests; no actual downstream engine is claimed."""
from __future__ import annotations

from contextlib import redirect_stderr
from html import escape
import io
import re
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    main,
    synthetic_downstream_adapter_acceptance,
)


def _lab_text_only_adapter(markdown: str) -> str:
    """Deliberately NOT a Markdown parser; safe negative-control fixture."""
    return "<pre>" + escape(markdown, quote=True) + "</pre>"


class DownstreamHtmlAdapterContractW51(unittest.TestCase):
    ERROR = "invalid downstream finding html integrity"

    def _denied(self, fragment: object, *, expected_text: str = "W51"):
        with self.assertRaises(ValueError) as caught:
            check_conservative_html_fragment(fragment, expected_text=expected_text)
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(str(caught.exception), self.ERROR)

    def test_pure_text_positive_control_is_not_real_html_renderer_proof(self):
        digest = synthetic_downstream_adapter_acceptance(_lab_text_only_adapter)
        self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertEqual(digest, synthetic_downstream_adapter_acceptance(_lab_text_only_adapter))

    def test_safe_fragment_allows_escaped_untrusted_tag_as_text(self):
        check_conservative_html_fragment(
            "<p>W51 &lt;script&gt;alert(1)&lt;/script&gt;</p>",
            expected_text="W51",
        )
        check_conservative_html_fragment(
            "<h2>W51</h2><ul><li><strong>Evidence</strong></li></ul>",
            expected_text="W51",
        )

    def test_disallow_executable_or_unknown_tags(self):
        for fragment in (
            "<script>W51</script>", "<svg>W51</svg>", "<iframe>W51</iframe>",
            "<form>W51</form>", "<style>W51</style>",
            "<math>W51</math>", "<img src=x />W51",
            "<!--W51--><pre>W51</pre>", "<!DOCTYPE html><p>W51</p>",
        ):
            with self.subTest(fragment=fragment):
                self._denied(fragment)

    def test_disallow_all_attributes_including_event_css_and_class(self):
        for fragment in (
            '<p onclick="alert(1)">W51</p>',
            '<p style="background:url(javascript:alert(1))">W51</p>',
            '<pre class="highlight">W51</pre>',
            '<span data-secret="synthetic">W51</span>',
            '<a href="https://outside.invalid">W51</a>',
            '<a href="javascript:alert(1)">W51</a>',
        ):
            with self.subTest(fragment=fragment):
                self._denied(fragment)

    def test_missing_expected_evidence_token_is_refused(self):
        self._denied("<pre>other evidence</pre>")

    def test_private_metadata_refuses_raw_or_encoded_or_split(self):
        self._denied("<pre>W51 SYNTHETIC-W51-METADATA-PRIVATE</pre>")
        self._denied("<pre>W51 &#83;YNTHETIC-W51-METADATA-PRIVATE</pre>")
        self._denied("<p>W51 SYNTHETIC-</p><p>W51-METADATA-PRIVATE</p>")

    def test_reject_unbalanced_and_non_fragment_markup(self):
        for fragment in (
            "<pre>W51", "<p><strong>W51</p></strong>",
            "</pre><pre>W51</pre>", "<p>W51</br>",
            '<?xml version="1.0"?><p>W51</p>',
        ):
            with self.subTest(fragment=fragment):
                self._denied(fragment)

    def test_reject_wrong_types_surrogates_and_oversized_html(self):
        for value in (None, b"<pre>W51</pre>", ["<pre>W51</pre>"],
                      "<pre>W51\ud800</pre>",
                      "<pre>W51" + ("x" * (4 * 1024 * 1024)) + "</pre>"):
            with self.subTest(value_type=type(value).__name__):
                self._denied(value)

    def test_adapter_rejects_unsafe_html_and_wrong_return_type(self):
        for adapter in (
            lambda markdown: "<script>W51</script>",
            lambda markdown: '<a href="https://outside.invalid">W51</a>',
            lambda markdown: "<pre>W51 SYNTHETIC-W51-METADATA-PRIVATE</pre>",
            lambda markdown: None,
            "not a callable",
        ):
            with self.subTest(adapter=repr(adapter)[:100]):
                with self.assertRaises(ValueError):
                    synthetic_downstream_adapter_acceptance(adapter)

    def test_cli_without_explicit_engine_returns_inconclusive_not_pass(self):
        out = io.StringIO()
        with redirect_stderr(out):
            status = main([])
        self.assertEqual(status, 2)
        self.assertIn("INCONCLUSIVE", out.getvalue())
        self.assertNotIn("PASS", out.getvalue())


if __name__ == "__main__":
    unittest.main()
