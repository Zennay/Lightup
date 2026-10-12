"""W62 opt-in synthetic HTML evidence-body presence canary.

This composes W51/W52 and checks for a visible body fragment from their
synthetic finding. It is not an installed renderer, an equivalence proof,
a tenant authorization check, or permission for active testing/release.
"""
from __future__ import annotations

from typing import Callable

from tests.markdown_html_downstream_contract_w51 import check_conservative_html_fragment
from tests.markdown_html_full_evidence_gate_w52 import synthetic_full_evidence_acceptance

_ERROR = "invalid downstream finding html integrity"


def synthetic_payload_presence_acceptance(
    convert_markdown_to_html: Callable[[str], str],
) -> str:
    """Require a visible synthetic evidence-body canary and the full W52 token."""
    if not callable(convert_markdown_to_html):
        raise ValueError(_ERROR)

    def require_payload(markdown: str) -> str:
        fragment = convert_markdown_to_html(markdown)
        check_conservative_html_fragment(fragment, expected_text="img src=x")
        return fragment

    return synthetic_full_evidence_acceptance(require_payload)
