"""Independent offline W52 evidence-marker controls (synthetic only).

No installed renderer, browser, network, tenant or target is exercised.
"""
import unittest
from html import escape

from tests.markdown_html_full_evidence_gate_w52 import synthetic_full_evidence_acceptance
from tests.test_markdown_html_full_evidence_gate_w52 import text_only


class EvidenceMarkerEdges(unittest.TestCase):
    def assert_denied(self, renderer):
        with self.assertRaisesRegex(ValueError, "^invalid downstream finding html integrity$"):
            synthetic_full_evidence_acceptance(renderer)

    def test_fixture_decodes_single_markdown_escaped_underscore(self):
        self.assertEqual(
            text_only(r"W51\_VISIBLE\_EVIDENCE\_TOKEN"),
            "<pre>W51_VISIBLE_EVIDENCE_TOKEN</pre>",
        )

    def test_fixture_does_not_decode_double_escaped_underscore(self):
        self.assertIn(r"\_VISIBLE", text_only(r"W51\\_VISIBLE"))

    def test_evidence_marker_only_in_attribute_is_denied(self):
        self.assert_denied(
            lambda _md: '<pre data-token="W51_VISIBLE_EVIDENCE_TOKEN">'
            "LightUp Assessment Findings Synthetic Treat raw W51</pre>"
        )

    def test_evidence_marker_only_in_comment_is_denied(self):
        self.assert_denied(
            lambda _md: "<pre>LightUp Assessment Findings Synthetic Treat raw W51</pre>"
            "<!--W51_VISIBLE_EVIDENCE_TOKEN-->"
        )

    def test_non_string_html_result_is_denied(self):
        self.assert_denied(lambda _md: b"W51_VISIBLE_EVIDENCE_TOKEN")

    def test_private_metadata_in_visible_html_is_denied(self):
        self.assert_denied(
            lambda _md: "<pre>LightUp Assessment Findings Synthetic Treat raw "
            "W51_VISIBLE_EVIDENCE_TOKEN SYNTHETIC-W51-METADATA-PRIVATE</pre>"
        )

    def test_entity_encoded_visible_marker_is_accepted_in_synthetic_control(self):
        def renderer(markdown):
            return (
                "<pre>"
                + escape(markdown.replace("\\_", "_")).replace("_", "&#95;")
                + "</pre>"
            )
        digest = synthetic_full_evidence_acceptance(renderer)
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
