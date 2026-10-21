#!/usr/bin/env python3
"""Source-minimized count reporting, never a formal anonymity guarantee.

Pure formatting for offline PRIVATE HUMAN distribution artefacts; unrelated
to scope permissions, scanner runtime, assessment quality or QA suites.
"""
from __future__ import annotations

def suppressed_counts(values: dict[str, int], population: int) -> dict:
    if type(population) is not int or not 0 <= population <= 256:
        raise ValueError("Invalid PRIVATE review population")
    if type(values) is not dict or not values or any(
        type(key) is not str or type(n) is not int or n < 0 or n > population
        for key, n in values.items()
    ):
        raise ValueError("Invalid PRIVATE category counters")
    small = population < 5
    return {
        "privacy_notice": "Source-minimized counts only; NOT anonymous, especially with rare categories.",
        "small_cohort_suppressed": small,
        "low_frequency_suppressed": True,
        "categories": {
            k: (None if small or 1 <= count < 3 else count)
            for k, count in sorted(values.items())
        },
        "suppressed_marker": "null = withheld for a small cohort or count 1-2",
        "counts_are_authority_or_security_evidence": False
    }
