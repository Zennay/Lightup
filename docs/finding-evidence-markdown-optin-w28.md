# W28 — optional Markdown Finding evidence-integrity gate (#894)

**M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.**

Canonical `models.Finding.validate()` still validates identity/title/target/
remediation but does not check `evidence`; the default
`reporting.render_markdown()` may render malformed legacy in-memory
evidence before the original #894 source-owner repair is absorbed.

## Concrete collision-free opt-in reference

`src/lightup/finding_evidence_markdown_checked_optin_w28.py` adds a
separate `render_checked_findings_markdown(findings)` helper. It is not
installed or the default renderer. Before invoking the existing reporter,
it rejects all malformed finding/evidence containers and items as one
generic evidence-integrity `ValueError`, accepts legacy empty evidence
arrays for the explicit fallback message, then snapshots only fields
needed by Markdown and detaches mutable caller-owned evidence/metadata.

The bounded batch checks all records *before any Markdown is produced*,
including malformed later entries. It preserves the original order of
canonical evidence references and never mutates caller records or imports
metadata into the report. It also checks the other rendered fields'
canonical scalar/enum types to avoid accidental polymorphic dispatch.

This optional module **does not fix** `Finding.validate` or the default
`render_markdown`, and **does not** make unescaped Markdown, arbitrary
free text, credentials, metadata, tenant identities, or reports safe
for unreviewed external disclosure. Batch limits (128 findings and
128 evidence entries per finding) are provisional acceptance ceilings,
subject to original source-owner compatibility review.

## Eight synthetic in-memory regressions

`tests/test_finding_evidence_markdown_checked_optin_w28.py` proves:

1. Canonical ordered international evidence remains in its original order.
2. Canonical `[]` keeps the "No evidence recorded." fallback.
3. Tuple/string/list-subclass/noncontainer evidence refuses before renderer.
4. Non-string, string-subclass, blank or whitespace elements deny without mutation.
5. Invalid later evidence suppresses the *whole* report before rendering.
6. Snapshot isolates caller mutation and omits unrelated metadata.
7. Malformed batches, oversize findings and Finding subclasses are denied.
8. The existing default renderer's legacy gap remains visible as an explicit control, not silently claimed as repaired.

Reproduce on an isolated CI checkout:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_evidence_markdown_checked_optin_w28.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

## Owner handoff

Open issue [#894](https://github.com/Zennay/Lightup/issues/894)
and independent [draft #1200](https://github.com/Zennay/Lightup/pull/1200)
retain the canonical negative acceptance. PR #100 owns `models.py`,
and #732 owns `reporting.py`; neither is changed here. The original
source owner must implement the strict `Finding.validate` read model,
then retest the actual default rendering boundary. Independent
security/privacy/Markdown output review, exact-head permanent
self-hosted VPS CI, integration with latest main and release approval
remain required. No actual client, live target, scanner, authorization
grant, executed remediation, verified retest, merge or deployment.
