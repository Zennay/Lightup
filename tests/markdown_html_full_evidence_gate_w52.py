"""W52 opt-in synthetic HTML evidence marker gate; never a production adapter.

This composes the W51 conservative HTML checks and refuses downstream output
that keeps a generic "W51" marker but discards the actual evidence reference.
No live renderer, tenant data, target, browser or authorization is exercised.
"""
from __future__ import annotations

from typing import Callable

from tests.markdown_html_downstream_contract_w51 import (
    check_conservative_html_fragment,
    synthetic_downstream_adapter_acceptance,
)

_ERROR = "invalid downstream finding html integrity"
_FULL_EVIDENCE_MARKER = "W51_VISIBLE_EVIDENCE_TOKEN"


def synthetic_full_evidence_acceptance(
    convert_markdown_to_html: Callable[[str], str],
) -> str:
    """Return W51's synthetic digest only if the full evidence token survives.

    A successful result is an offline canary, not actual renderer/browser
    security, complete report equivalence, or permission to merge/deploy.
    """
    if not callable(convert_markdown_to_html):
        raise ValueError(_ERROR)

    def require_evidence(markdown: str) -> str:
        fragment = convert_markdown_to_html(markdown)
        check_conservative_html_fragment(
            fragment,
            expected_text=_FULL_EVIDENCE_MARKER,
        )
        return fragment

    return synthetic_downstream_adapter_acceptance(require_evidence)
