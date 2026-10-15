# Issue #777 · Synthetic producer/direct provenance differential

**LightUp posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an independent, add-only acceptance artifact; it does not alter `src/lightup/**`, branch `chatgpt/scope-authorization-direct-grant-approval-provenance-red-20261007`, production authority, workflow configuration, or any other worker's PR.

## Why this adds a distinct acceptance signal

Issue [#777](https://github.com/Zennay/Lightup/issues/777) already has a branch-only direct-policy RED acceptance against frozen PR #100. This follow-on tests a *different observable contract* on the current mainline: a disposable real SQLite `DomainStore.record_authorization_grant` producer accepts legitimate padded input and persists its canonical trimmed provenance; the *same* approval values are then evaluated as a canonical direct `AuthorizationGrant`, while modified caller-owned direct objects are asserted not to authorize. It demonstrates the producer/direct mismatch without borrowing or modifying the first RED branch.

`tests/test_scope_777_producer_direct_provenance_differential_20261015.py` performs four ordinary positive/denial controls and fourteen **expectedFailure** direct-authority canaries. The direct canaries separately exercise empty/whitespace-only/padded values and built-in-`str`-subclass impersonation for both `approved_by` and `reference`, plus non-string values (`bytes`, `int`, `None`) and Unicode whitespace padding (em space and non-breaking space). Each canary builds a valid synthetic persisted grant then modifies only an in-memory copy; policy decisions must be non-authorizing **and** side-effect-free. All names and assets are fictional, with `example.test`; there is no network I/O, handler call, customer data, production state or issuance of real permits.

The fourth regular (non-xfail) regression probes all 14 malformed direct-object variants, requiring a typed policy decision without exceptions and no changes to the in-memory object or SQLite state. This independent green control prevents an unexpected exception from being silently reported as an expected security failure.

## Acceptance and interpretation

- **Current baseline:** direct `ExecutionPolicy.decide` checks validity, risk, asset and capability but does not enforce canonical provenance. Fourteen expected failures intentionally flag the gap; green CI including expected failures **does not** mean the gap is fixed.
- **Production-owner closure:** on the integrated source SHA, fourteen xfails must become ordinary passing denial tests, the three producer/positive tests must still pass, and `approved_by`/`reference` must be exactly built-in `str`, nonempty after strip, and stored without leading/trailing whitespace.
- Rejection must be pure; no change to direct grant, original persisted snapshot, queue, evidence, handler, or target.
- Do not merge, run real active assessments, deploy, make grants, assume VPS success, or promote this branch. Require independent owner review, original PR #100 integration, trusted consent, precise destination and per-dispatch revocation, hosted exact-head CI and canonical registered VPS proof followed by human approval.
- Per [#777](https://github.com/Zennay/Lightup/issues/777), retain **branch-only** while the canonical self-hosted runner queue is saturated; this branch has no new PR or manually dispatched runner job.

## Verification

From a clean source checkout with the repository's established test environment:

```bash
PYTHONPATH=src python -m unittest -v tests/test_scope_777_producer_direct_provenance_differential_20261015.py
```

If dotted discovery does not work because `tests` is not a package, use:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_777_producer_direct_provenance_differential_20261015.py' -v
```

Expected baseline: four ordinary passes and fourteen *expected failures*, zero unexpected passes or errors. These expected failures are security debt, not authorization. Local code-level validation alone cannot establish registered VPS, deployment or security approval.
