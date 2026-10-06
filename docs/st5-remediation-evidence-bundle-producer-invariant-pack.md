# ST5 remediation evidence bundle producer-invariant acceptance pack

This tests/docs-only branch composes the independently proven persisted-boundary
contracts from issues #398, #399, #400, #401 and #402 directly on exact active
#194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`.

It is the preferred single acceptance head for the #194 source owner after
absorbing the narrow parser fixes. It does not modify production source.

## Contracts

- #398: current and future twin versions remain positive exact integers.
- #399: nested evidence capability set exactly matches item capability lineage.
- #400: INTRODUCED has no current-path lineage; WORSENED retains current paths.
- #401: resolution IDs keep exact transition-resolution shape and effect lineage
  stays non-empty with canonical identifiers.
- #402: evidence kind remains exactly future-transition-verification.

All tampered cases recompute their applicable public manifest/bundle digest, so
the contracts prove structural producer invariants rather than stale-digest
rejection.

## Expected RED shape before owner fixes

The combined dedicated acceptance modules contain positive real-producer
controls plus 14 deliberately failing negative cases per Python version:

- #398: 2;
- #399: 2;
- #400: 2;
- #401: 7;
- #402: 1.

The parent #194 handoff suite and safety canaries must remain green.

## Promotion use

After #194 absorbs the fixes, run this exact combined pack against the updated
source. The desired transition is all dedicated tests green with no authority
widening. Keep live StateStore freshness/provenance enforcement at the immediate
live validator rather than duplicating it in the structural parser.

## Safety

Persistence-integrity acceptance only. No evidence collection, model
invocation, target interaction, tool/remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
