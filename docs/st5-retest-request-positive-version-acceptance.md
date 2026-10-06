# ST5 retest-request positive twin-version acceptance

Issue: #387

This is a tests/docs-only acceptance child of exact strict retest-request
handoff head `51ef9d8574e69c2f82c3f9635b508e835a822177`.

## Boundary

The persisted `FutureSecurityRetestRequest` must preserve the positive twin
version lineage already required by the upstream ST3 transition proposal.

Both:

- `current_twin_version`;
- `twin_version`;

must remain exact integers greater than or equal to 1. Boolean lookalikes remain
invalid through the existing strict primitive boundary.

The regression changes each version to zero and recomputes the exact matching
`request_sha256`. Passing therefore requires an explicit positive-version gate;
a stale-digest rejection cannot satisfy this contract.

## Expected RED on the current #359 handoff

The current parser uses a non-negative integer gate (`value < 0`). Zero
therefore survives structural validation, and after digest recomputation the
forged request can be reconstructed as typed persisted state even though the
canonical live producer cannot emit that lineage.

## Collision boundary

This branch adds only:

- `tests/test_future_security_retest_request_positive_version_acceptance.py`;
- this document.

It does not modify #359 source/tests/docs, #356/#357/#363 files, upstream
remediation/retest-plan work, retest authorization/tool-selection, scope
authorization, or target-capable code.

## Safety

Persistence-integrity only. No evidence collection, target interaction, tool
execution, remediation/retest execution, deployment, security verdict creation,
or attack-path mutation is introduced.
