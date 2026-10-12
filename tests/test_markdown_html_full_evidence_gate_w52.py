"""W52 independent offline synthetic evidence-preservation tests."""
from __future__ import annotations

from html import escape
import re
import unittest

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
)
from tests.markdown_html_full_evidence_gate_w52 import (
    synthetic_full_evidence_acceptance,
)

ERROR = "invalid downstream finding html integrity"
FULL = "W51_VISIBLE_EVIDENCE_TOKEN"


def text_only(markdown: str) -> str:
    return "<pre>" + escape(markdown, quote=True) + "</pre>"


class FullEvidenceMarkerW52(unittest.TestCase):
    def denied(self, adapter):
        with self.assertRaisesRegex(ValueError, "^" + re.escape(ERROR) + "$"):
            synthetic_full_evidence_acceptance(adapter)

    def test_full_token_survives_text_only_diagnostic_control(self):
        digest = synthetic_full_evidence_acceptance(text_only)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, synthetic_full_evidence_acceptance(text_only))

    def test_four_generic_markers_do_not_prove_evidence_preservation(self):
        truncated = "<pre>LightUp Assessment Findings Synthetic Treat raw W51</pre>"
        check_conservative_html_fragment(
            truncated,
            expected_text="W51",
            required_text=("LightUp Assessment Findings", "Synthetic", "Treat raw"),
        )
        self.assertNotIn(FULL, truncated)
        self.denied(lambda _markdown: truncated)

    def test_shortened_evidence_token_is_denied(self):
        self.denied(
            lambda _markdown: (
                "<pre>LightUp Assessment Findings Synthetic Treat raw "
                "W51_VISIBLE_EVIDENCE</pre>"
            )
        )

    def test_full_token_is_accepted_as_visible_text(self):
        fragment = "<p>LightUp Assessment Findings Synthetic Treat raw " + FULL + "</p>"
        check_conservative_html_fragment(fragment, expected_text=FULL)

    def test_missing_evidence_from_multiple_paragraphs_is_denied(self):
        self.denied(
            lambda _markdown: (
                "<h1>LightUp Assessment Findings</h1>"
                "<p>Synthetic W51</p><p>Treat raw</p>"
            )
        )

    def test_wrong_adapter_type_is_denied(self):
        self.denied(None)
        self.denied("not callable")


if __name__ == "__main__":
    unittest.main()
