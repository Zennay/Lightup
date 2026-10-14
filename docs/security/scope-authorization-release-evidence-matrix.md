# Scope authorization — release evidence matrix (ST5, plan/lab only)

This document is an **acceptance checklist**, not a grant of permission to execute against a target. The release gate stays closed unless the exact tested production head and its dependencies pass every applicable rule. It intentionally changes **no** execution or authorization source and does not supersede active PR #100, #107, #146 or their test-only sidecars.

## Proof requirements

For each checked row, record: exact source SHA, test SHA, Python version, canonical self-hosted run URL and conclusion, relevant PR, and an immutable evidence timestamp. Hosted-only preflight is not a canonical release proof. A queued, cancelled, skipped or stale-head run is **not** success.

| Gate | Mandatory negative control | Positive control | Current owner / dependency |
| --- | --- | --- | --- |
| Tenant isolation | Cross-tenant assessment, grant, request or decision cannot be read/approved/resolved | Same-tenant current records | #146 and associated provenance sidecars |
| Grant issuance | ELEVATED grant without approved same-engagement ELEVATED step-up is rejected without rows | STANDARD issuance and approved same-engagement step-up | #881 / #887 |
| Activation | RUNNING with missing, expired, revoked or foreign-engagement grant fails without state change | RUNNING with current matching grant | #884 / #887 |
| Durable reads | Malformed persisted asset, requester, decision and grant metadata fail closed without repair | Exact canonical persisted fields | #877 / #879 / #880 and existing domain work |
| Executor provenance | Duck/subclass live grant or substituted evidence ledger denied before handler/evidence | Exact canonical grant plus bound ledger | #948 / #949 / #950 |
| Authority monotonicity | Live same-ID grant expanding assets, capabilities, risk, exclusions or time interval denied | Narrowed live grant retains permitted intersection | #951 / #953 / #954 |
| Temporal boundaries | Falsy non-datetime `now` cannot become current wall clock; expiration not revived | Explicit aware datetime behaves deterministically | #890 and temporal sidecars |
| Scope identity | Unknown public host, unsanctioned CIDR or malformed target cannot be authorized by attached grant | Already-declared membership then valid authorization | #364 / #100 |

## Negative-case invariants

1. Refusal precedes any target handler, DNS lookup, socket/HTTP request, real scanner or lab capability invocation.
2. Refusal writes no fabricated execution evidence, authorization row or altered engagement state. Legitimate denial audit records may exist only where a separately approved specification requires them.
3. Callers, grant snapshots, live grant records and durable inputs remain unchanged after rejection.
4. A passed individual test does not confer authorization: the policy must validate tenant + asset + capability + risk + validity + revocation + current grant **together** at the actual dispatch boundary.
5. A newly approved wider grant requires a new explicit run/approval boundary; refreshing an existing run's grant identifier must not expand its original authority.
6. Cancellation or stale CI evidence cannot silently flip any acceptance checkbox to green.

## Promotion procedure

- Freeze and identify the exact candidate source tree and dependency/PR graph.
- Confirm active source owners have completed review and the production code has actually absorbed each expected-red sidecar contract.
- Run offline tests before any canonical CI. Never run tests against real customer/prospect targets.
- Capture canonical self-hosted test evidence for **that exact head** and all supported interpreters; absence or mismatch keeps gate closed.
- Review authorization threat cases above, including bypass attempts via Python truthiness, type subclassing, object substitution, cross-tenant references and same-ID live broadening.
- Only after all checks pass may an authorized maintainer consider release; this checklist itself cannot approve a release or active scan.

## Explicit non-goals

No new target discovery, live scanning, exploit behavior, account escalation, deployment, evidence fabrication, approval automation, verdict creation, remediation/retest execution or attack-path mutation. This document is orthogonal to parallel source owners and can be cherry-picked independently.
