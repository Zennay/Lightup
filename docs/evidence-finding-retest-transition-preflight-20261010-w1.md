# Finding retest transition preflight — isolated evidence-remediation slice

## What this changes

The offline `preflight_retest_transition(previous, candidate)` works against
**real** `lightup.models.Finding` instances. It catches a high-risk presentation
error: an object can flip its `retest_status` to `fixed` without recording any
new evidence. The function refuses to call that a reviewable retest.

The preflight requires exact built-in Finding/Severity/RetestStatus types;
bounded, unique, nonempty, Unicode-NFC, printable, strictly typed evidence\nitems; unchanged finding,
target, title and severity identity; preserved historical evidence; and at
least one additional item. It does not record or modify any finding.

Unicode normalization rejects visually equivalent decomposed evidence being\nsubmitted as a bogus new observation; control/format characters and invalid\nUnicode surrogate text also reject without bubbling codec errors.\n\nThe result exposes only fixed reason codes, a bounded count, and three always
false flags: `externally_verified`, `remediation_authorized` and
`release_authorized`. No target, evidence text, metadata, finding details or
credentials are emitted.

## Security limitation (crucial)

**Reviewable is not validated.** New text can be forged or stale. Even a
positive result does not authenticate a source, check trusted tenant/finding
lineage, bind a run or approval, prove a target was remediated, verify freshness
or authorize an active retest. Only a later trusted reviewer can independently
inspect signed/immutable provenance and pronounce a finding fixed. Never set
production status from this comparison alone.

This is a pure opt-in helper, **not wired to persistence, public exports,
production reporting, remediation writers, AI reviews, HTTP adapters or the
ToolExecutor**. It does not contact any targets or run verification.

## Ownership / coordination

Three independent new paths on current main; no modifications to active
workers' paths:

- existing finding persistence/read corruption and retest atomicity work:
  #851 / #856 / #883–#894;
- evidence receipt/retest lineage reference: PRs #1065–#1078;
- remediation review/advisor source integration: #845 / #898–#902;
- scope authorization and execution: PR #107.

The helper is not a replacement for those canonical source owners. Merge only
after independent source-owner review and exact-head tests. Do not use pending
LightUp VPS CI as proof: the project handoff documents that there is currently
no runner registered with this repository. Hosted checks can validate the
isolated source, but VPS proof requires fixing runner registration/workflow.

## Test

```bash
PYTHONPATH=src python -m unittest tests.test_finding_retest_preflight_20261010_w1 -v
```

The focused regression is offline, uses synthetic findings, and never
initiates network, scans, live grants, queue dispatches or production mutations.
