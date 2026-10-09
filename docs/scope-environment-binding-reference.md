# Scope authorization: environment binding (offline reference)

## Threat boundary
A scope decision for a staging environment must never be transplanted into production (or vice versa), even when tenant, request, issuer and revision are identical. Environment is an explicit authority dimension, not a cosmetic tag, host-name inference, or a label that can be silently defaulted.

## Isolated test material
`tests/test_scope_environment_binding_reference.py` models an immutable evidence envelope and a pure fail-closed decision. Twelve standard-library unittest methods cover matching context; staging→production and production→staging substitutions; tenant/request/issuer/revision substitution; malformed grant environment identities; full test/staging/production matched controls; malformed metadata on both the request and grant side; lexical aliases and controls; truthy flags, malformed revisions and subclass/dictionary envelopes; and input nonmutation.

## Production-owner acceptance
- Define the canonical, issuer-controlled environment identity during grant issuance. Decide migration policy for existing grants that lack this field; never silently treat missing as production.
- Bind grant, run snapshot and live revalidation to the same tenant, request, issuer, revision **and environment**; reject unknown/ambiguous values before dispatch or evidence write.
- Keep cancellation, revocation, temporal validity, risk ceiling, exclusions and capability checks mandatory. Environment matching alone is never authorization.
- Run negative integration tests proving rejected environment swaps have zero handler invocations, queue mutations, grant writes and target I/O.
- Require source-owner review and green exact-head hosted checks plus permanent self-hosted VPS CI before promotion.

## Ownership and safety
This contribution adds tests/docs only; production `ExecutionPolicy`, `ToolExecutor`, grant issuance, persistence, live authorization resolver and all source-owner branches remain untouched. The offline reference has no trusted provenance and cannot authorize a real target. No network requests, scanning, capabilities, attack execution, deployment or grant widening.
