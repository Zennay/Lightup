"""Offline synthetic W60 HTML depth regressions; no target or client data."""
from __future__ import annotations

from unittest import TestCase, mock

from tests.markdown_html_depth_guard_w60 import (
    _ERROR, _MAX_NESTING, check_depth_bounded_html_fragment_w60,
)


class HtmlDepthGuardW60Tests(TestCase):
    def check(self, fragment: object, *, expected_text: str = "W51") -> None:
        check_depth_bounded_html_fragment_w60(fragment, expected_text=expected_text)

    def refuse(self, fragment: object) -> None:
        with self.assertRaisesRegex(ValueError, "^" + _ERROR + "$"):
            self.check(fragment)

    def test_empty_fragment_rejected_by_downstream(self) -> None:
        self.refuse("")

    def test_exact_limit_balanced(self) -> None:
        self.check("<p>" * _MAX_NESTING + "W51" + "</p>" * _MAX_NESTING)

    def test_limit_plus_one_refused_before_downstream(self) -> None:
        fragment = "<p>" * (_MAX_NESTING + 1) + "W51" + "</p>" * (_MAX_NESTING + 1)
        with mock.patch("tests.markdown_html_depth_guard_w60.check_conservative_html_fragment") as downstream:
            self.refuse(fragment)
            downstream.assert_not_called()

    def test_depth_counts_concurrent_elements_not_total(self) -> None:
        self.check("<p>W51</p>" * 1000)

    def test_void_elements_do_not_consume_depth(self) -> None:
        self.check("<p>W51" + "<br><hr>" * 1000 + "</p>")

    def test_mixed_balanced_allowed_tags(self) -> None:
        self.check("<ul><li><strong>W51</strong></li></ul>")

    def test_unicode_positive_control(self) -> None:
        self.check("<p>W51 東京 café 👩\u200d💻</p>")

    def test_missing_close_refused(self) -> None:
        self.refuse("<p>W51")

    def test_mismatched_close_refused(self) -> None:
        self.refuse("<p>W51</ul>")

    def test_early_unexpected_close_refused(self) -> None:
        self.refuse("</p><p>W51</p>")

    def test_late_overflow_atomic(self) -> None:
        self.refuse("<p>W51</p>" * 100 + "<p>" * (_MAX_NESTING + 1))

    def test_non_string_refused(self) -> None:
        for item in (None, 3, b"<p>W51</p>", ["<p>W51</p>"]):
            with self.subTest(type=type(item).__name__):
                self.refuse(item)

    def test_string_subclass_refused(self) -> None:
        class Forged(str):
            pass
        self.refuse(Forged("<p>W51</p>"))

    def test_unpaired_surrogate_refused(self) -> None:
        self.refuse("<p>W51\ud800</p>")

    def test_byte_limit_refused_before_downstream(self) -> None:
        fragment = "<p>W51" + "x" * (4 * 1024 * 1024) + "</p>"
        with mock.patch("tests.markdown_html_depth_guard_w60.check_conservative_html_fragment") as downstream:
            self.refuse(fragment)
            downstream.assert_not_called()

    def test_w51_rejects_attributes(self) -> None:
        self.refuse('<p class="unsafe">W51</p>')

    def test_w51_rejects_script(self) -> None:
        self.refuse("<script>W51</script>")

    def test_w51_rejects_private_canary(self) -> None:
        self.refuse("<p>W51 SYNTHETIC-W51-METADATA-PRIVATE</p>")

    def test_w51_rejects_missing_visible_marker(self) -> None:
        self.refuse("<p>no required marker</p>")

    def test_caller_input_remains_unchanged(self) -> None:
        accepted = "<p>W51</p>"
        rejected = "<p>" * (_MAX_NESTING + 1) + "W51"
        self.check(accepted)
        self.refuse(rejected)
        self.assertEqual(accepted, "<p>W51</p>")
        self.assertEqual(rejected, "<p>" * (_MAX_NESTING + 1) + "W51")

    def test_required_text_delegates_to_w51(self) -> None:
        check_depth_bounded_html_fragment_w60("<p>W51 proof</p>", expected_text="W51", required_text=("proof",))
        with self.assertRaisesRegex(ValueError, "^" + _ERROR + "$"):
            check_depth_bounded_html_fragment_w60("<p>W51</p>", expected_text="W51", required_text=("proof",))
