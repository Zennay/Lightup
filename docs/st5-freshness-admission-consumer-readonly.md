# ST5 freshness-admission live consumer read-only contract

Issue #767 isolates read-only behavior at PR #141's composed persisted
freshness-admission consumer.

The regression snapshots proposal, source context, transition resolution,
graph-diff preview, security-delta report, remediation/retest plan, evidence
collection request, freshness constraints and candidate context, together with
durable `runs`, `capability_leases` and `evidence` rows.

Canonical success and fail-closed candidate-evidence SHA drift are each repeated.
The typed lineage and durable state must remain unchanged. Fail-fast sentinels on
`StateStore.create_run`, `acquire_lease` and `add_evidence` prevent repair
or state creation as a validation side effect.

This branch is tests/docs-only and pinned to PR #141 exact head
`cfa22936bb2e3fc95665a0a032143d708a4568fe`. PR #141 retains source ownership;
#766/#765 own persisted-input atomicity, #764 fail-fast ordering and #763 outer
runtime-type exactness.

Freshness remains non-authoritative and this proof adds no classification,
transition or execution authority.
