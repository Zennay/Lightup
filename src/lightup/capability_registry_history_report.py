"""Human-readable non-authorizing report for declared offline registry histories.

Never includes source capability names, descriptions, arguments, customer data,
target addresses, claims of consent, nor an execution/merge/release permit.
"""
from __future__ import annotations

import re

from .capability_registry_history_review import review_capability_registry_history

_CANONICAL_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
_APPROVED_FIELDS = frozenset({
    "added", "removed", "state", "requires_explicit_activation", "name", "description",
})
_MAX_REPORT_CHARS = 131_072

_NON_AUTHORITY = (
    "\n---\n"
    "**Authority: NONE.** Offline metadata review only. No authorization verified, "
    "permit issued, execution enabled, merge approved or release approved.\n"
    "Declared snapshots are not authenticated release history, signed consent or proof "
    "of current tenant/asset authority. **Do not run security tests from this report.**\n"
)


def _hold_report() -> tuple[str, int]:
    return (
        "# LightUp capability history — HOLD\n\n"
        "The declared history cannot be safely reviewed. Inspect the local inputs independently.\n"
        + _NON_AUTHORITY,
        2,
    )


def render_capability_registry_history_markdown(snapshots: tuple[bytes, ...]) -> tuple[str, int]:
    """Render a strict, bounded review from raw local snapshot metadata.

    This function accepts no arbitrary Markdown body or user-controlled labels.
    It does not read files or perform network/authorization operations.
    """
    review = review_capability_registry_history(snapshots)
    if review.status not in ("HOLD", "REVIEW_ONLY") or review.snapshot_count < 2:
        return _hold_report()

    lines = [
        "# LightUp capability history — " + review.status,
        "",
        f"Declared snapshots: **{review.snapshot_count}**. Snapshot order is provided by the reviewer, not independently proven.",
        "",
    ]
    if review.transitions:
        lines.extend([
            "**Historical drift detected: review required.** A reverted intermediate change",
            "does not disappear when the first and last snapshots happen to match.",
            "",
            "| Declared transition | Canonical capability ID | Changed fields |",
            "| --- | --- | --- |",
        ])
        for transition in review.transitions:
            if type(transition.from_index) is not int or type(transition.to_index) is not int:
                return _hold_report()
            if not 0 <= transition.from_index < transition.to_index < review.snapshot_count:
                return _hold_report()
            for capability_id, fields in transition.changed_fields:
                if type(capability_id) is not str or _CANONICAL_ID.fullmatch(capability_id) is None:
                    return _hold_report()
                if not fields or any(type(field) is not str or field not in _APPROVED_FIELDS for field in fields):
                    return _hold_report()
                lines.append(
                    f"| {transition.from_index + 1} → {transition.to_index + 1} "
                    f"| \\`{capability_id}\\` | {', '.join(fields)} |"
                )
    else:
        lines.extend([
            "**No differences in the declared metadata sequence.** This does not establish",
            "that the provided files cover all real releases or that any capability is authorized.",
        ])
    report = "\n".join(lines) + "\n" + _NON_AUTHORITY
    if len(report) > _MAX_REPORT_CHARS:
        return _hold_report()
    return report, 2 if review.status == "HOLD" else 3
