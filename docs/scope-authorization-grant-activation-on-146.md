# Scope authorization — grant activation pack on active domain head

This composition restacks the grant-activation authorization acceptance above
exact active domain/risk-decision source owner #146.

## Exact parent

`33c67f8e8b17bd9214c29d02fc52954cc42655da`

#146 is 34 commits ahead of the earlier #107 parent.

## Regression status on #146

Already source-green on this parent:

- #888: persisted recurring-retest authority accepts only exact SQLite integer
  `0`/`1`; the regression stays as a lock.

Still expected RED on this parent:

- #881: ELEVATED grant issuance does not yet require approved same-engagement
  step-up risk that covers the requested maximum;
- #884: `set_engagement_status(..., RUNNING)` does not yet require a current
  unrevoked same-engagement grant;
- #890: `get_current_grant(now=...)` still treats explicit falsy malformed
  values as omission through `now = now or utcnow()`.

## Ownership

The composition is tests/docs only and makes no production-source changes.
#146 retains domain/risk-decision source ownership; #177 retains
assessment-request -> grant issuance provenance; #651 retains execution-time
pre-authorization lifecycle defense; #734/#735 retain direct
`AuthorizationGrant.is_current` evaluation-input ownership.

## Safety

Temporary-SQLite authorization/lifecycle acceptance only. No DNS/network I/O,
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
