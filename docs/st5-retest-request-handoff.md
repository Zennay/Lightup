# ST5 strict isolated retest-request persisted handoff

This package adds an exact persisted/transport boundary for the immutable
`FutureSecurityRetestRequest` produced by PR #52.

Structural parsing is not authorization. A parsed request must still match a
request rebuilt from the live remediation/retest plan, ST4 lineage and
`StateStore` before any follow-up consumer can trust it.

## Strict structure

The handoff requires:

- the exact top-level and item schemas;
- canonical non-empty identifiers and lowercase SHA-256 lineage;
- real integer twin versions rather than bool/int confusion;
- exact request lifecycle markers;
- every execution, target-interaction, deployment and attack-path authority
  flag to remain false;
- unresolved future semantics and no security verdict.

Item classification, graph-diff action, source next action, retest purpose and
`remediation_required` must agree:

- introduced -> add-path hypothesis -> author remediation then retest ->
  remediation validation;
- worsened -> risk-up modification -> author remediation then retest ->
  remediation validation;
- improved -> risk-down modification -> verify improvement with retest ->
  improvement verification;
- removed -> remove-path candidate -> verify improvement with retest ->
  improvement verification;
- insufficient evidence cannot become a retest request.

Identifiers follow the upstream ST4 canonical contract: non-empty, already
trimmed, at most 256 characters and free of ASCII control characters. Lineage
lists are unique and canonically sorted. Evidence, capability and effect
lineage is non-empty per item.

Change-node IDs and resolution IDs are each globally unique inside one request.
Introduced items cannot reference a current attack path; worsened, improved and
removed items must reference at least one current attack path.

## Aggregate lineage

Top-level requested capability and evidence identities must be:

- non-empty;
- unique;
- canonically sorted;
- exactly equal to the union of the corresponding item lineage.

Persisted metadata therefore cannot add, remove, duplicate or reorder aggregate
authority/evidence identity independently of the request items.

## Digest and JSON boundary

The parser recomputes the exact request digest from typed state before returning
an object. Non-canonical lineage hashes or stale request digests fail closed.

JSON decoding uses an object-pairs hook so duplicate object keys are rejected
instead of silently collapsing with last-value-wins semantics.

## Live validation

`validate_future_security_retest_request_handoff` rebuilds the request through
the canonical PR #52 producer from the supplied remediation/retest plan, report,
preview, proposal, resolutions, run contexts and live `StateStore`.

Only exact equality with that rebuilt request is accepted. Cross-lineage,
stale, tampered or cross-tenant persisted requests therefore fail closed even
after structural parsing succeeds.

## Safety boundary

This handoff adds no execution authority:

- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No evidence collection, tool invocation, target interaction, remediation/retest
execution, deployment, verdict creation or attack-path mutation is introduced.
