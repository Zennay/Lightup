"""#1221 W77 offline math-plugin composition tripwires on immutable W46.

Expected failures document known optional-renderer presentation gaps.
Not installed, not a browser/security guarantee, no target interaction.
"""
import unittest

from lightup.models import Finding, Severity
from lightup.finding_markdown_escaped_optin_w31 import (
    render_escaped_evidence_markdown_optin_w31 as render,
)

try:
    import mistune
except ImportError:
    mistune = None


def synthetic(evidence):
    return Finding(
        finding_id="w77-synthetic", title="Evidence title",
        severity=Severity.INFO, target="example.invalid",
        evidence=[evidence], remediation="Review offline",
    )


class W77MathPluginRed(unittest.TestCase):
    def test_plain_currency_control(self):
        text = render([synthetic("Cost €12 and £9")])
        self.assertIn("€12", text)
        self.assertIn("£9", text)

    @unittest.expectedFailure
    def test_math_plugin_does_not_reinterpret_dollar_evidence(self):
        if mistune is None:
            self.skipTest("mistune unavailable")
        text = render([synthetic("price $123$ literal")])
        html = mistune.create_markdown(escape=True, plugins=["math"])(text)
        self.assertNotIn('class="math"', html)
        self.assertIn("$123$", html)

    @unittest.expectedFailure
    def test_compatibility_dollar_is_rejected_before_render(self):
        with self.assertRaisesRegex(ValueError, "invalid finding markdown evidence integrity"):
            render([synthetic("FULLWIDTH ＄price")])


if __name__ == "__main__":
    unittest.main()
