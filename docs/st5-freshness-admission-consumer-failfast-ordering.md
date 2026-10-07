# ST5 freshness-admission consumer fail-fast ordering

Issue #764 isolates ordering at the persisted freshness-admission consumer from
PR #141.

Persisted-input validation must complete before live freshness-admission
validation can run. The regression replaces the live validator with a fail-fast
sentinel and covers malformed JSON, duplicate keys, non-object JSON, unsupported
persisted values, strict schema rejection and canonical-shape digest rejection.

The first four cases belong to the outer persisted boundary; schema/digest
rejection proves the strict #72 handoff also finishes before live validation is
reachable.

This branch is tests/docs-only and pinned to PR #141 exact head
`cfa22936bb2e3fc95665a0a032143d708a4568fe`. PR #141 retains source ownership;
#763 owns outer runtime-type exactness and #613 owns direct parser exactness.

Freshness remains non-authoritative: this proof adds no suitability/sufficiency,
classification, transition, collection, tool/target execution, remediation/
retest, deployment, verdict or attack-path authority.
