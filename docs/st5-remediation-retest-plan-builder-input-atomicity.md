# ST5 remediation/retest plan builder input atomicity

This tests/docs-only invariant proves that the existing
`build_future_security_remediation_retest_plan` boundary consumes live ST4
inputs without rewriting caller-owned state.

## Boundary

The proof is intentionally narrower than adjacent evidence-remediation work.

- Snapshot-isolation contracts prove returned/exported snapshots are detached.
- Direct-construction hardening validates typed plan objects created outside the
  canonical producer.
- Parser purity contracts cover caller-owned persisted dictionaries.
- This contract covers the **typed remediation/retest plan builder** itself.

No production source is changed.

## Successful planning invariant

For each canonical ST4 classification (`introduced`, `worsened`,
`improved`, `removed`, and `insufficient_evidence`), the regression builds
the real ST4 report and then snapshots:

- the report, graph preview, transition proposal, resolution tuple and
  `RunContext` tuple by value;
- every nested tuple/list/dict/set/frozenset container identity reachable from
  those caller-owned inputs;
- all persisted `runs`, `capability_leases` and `evidence` rows in the live
  `StateStore`.

Two consecutive remediation/retest plan builds must return equal plans while
all three snapshots remain unchanged.

This establishes that deterministic planning is a read-only derivation rather
than an implicit lineage/state update.

## Live-revalidation rejection invariant

The regression also supplies a canonical-shape report with a stale
`report_sha256`. The builder performs its normal live report rebuild and then
rejects the stale report.

Repeated rejection must leave:

- the tampered caller-owned report and every other typed input unchanged;
- nested caller-owned container identities unchanged;
- all live ledger rows unchanged.

So fail-closed live revalidation does not acquire a hidden write side effect.

## Safety boundary

The proof keeps the existing planning stop line unchanged:

- `execution_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

It performs no evidence collection, model invocation, target interaction, tool
execution, remediation/retest execution, deployment, verdict creation or
attack-path mutation.
