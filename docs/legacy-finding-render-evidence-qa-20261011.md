# Issue #894 — legacy Finding evidence/report boundary

Status: **expected RED, tests/docs only, HOLD**. This is an in-memory
evidence-integrity acceptance contract, not a target security assessment.
Production ownership remains with #100 (`src/lightup/models.py`) and #732
(`src/lightup/reporting.py`).

## Reproducible acceptance

Run from a complete LightUp checkout with:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_legacy_finding_render_evidence_gate_20261011.py' -v
```

The test exercises both `Finding.validate()` and `render_markdown()`.
The exact built-in `list[str]` and empty-list fallback must remain valid.
A list subclass, tuple, dict, string or null evidence container must fail
closed. Each item must be an exact built-in non-blank string. In particular,
string subclasses, nonstrings, empty/whitespace strings and late invalid
items must be rejected without changing the caller-owned evidence object.

## Source-owner integration sketch (not applied)

Within `Finding.validate()`, after existing identity/title/target/remediation
checks and before any report output, use a narrow guard equivalent to:

```python
if type(self.evidence) is not list:
    raise ValueError("finding evidence must be a list")
for item in self.evidence:
    if type(item) is not str or not item.strip():
        raise ValueError("finding evidence item must be nonblank text")
```

No normalization, string coercion, sorting, target access or evidence
creation is permitted. The existing `render_markdown` validation call
should remain the single report-entry boundary.

## Evidence and release boundary

2026-10-11: isolated offline Python unittest against a locally reconstructed
mirror of the two inspected current-main source functions: **3 methods;
1 passed, 2 failed; 11 negative subcases failed as expected**. This is
not full-repository CI or an installed-service proof. Branch-only until
the shared source owners absorb the fix and the canonical permanent
self-hosted runner supplies green exact-head CI against current main.
Do not merge this expected-RED acceptance branch by itself.
