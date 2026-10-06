# ST5 remediation evidence bundle full integrity acceptance pack

This branch composes two ownership-separated tests/docs-only acceptance layers:

1. the preferred strict persisted-handoff producer-invariant pack for #194
   (#398/#399/#400/#401/#402);
2. the direct typed-object construction contract for #60 (#404).

It contains no production-source changes and is intended as a future integration
gate after the respective source owners absorb their narrow fixes.

## Pre-fix expected RED shape

- persisted parser producer invariants: 14 expected failures per Python version;
- typed direct construction: 39 expected failures per Python version;
- combined: 53 expected failures per Python version.

The canonical #60 producer, #194 handoff, compile checks, and safety canaries
must remain green throughout.

## Ownership

Do not use this aggregate branch to take over either source implementation.
#60 owns the producer dataclasses. #194 owns the strict persisted parser. The
aggregate only provides one post-fix verification surface spanning both.

Digest equality and live StateStore provenance remain at established strict/live
consumer boundaries; the direct-construction contract owns structural impossible
state only.

## Safety

Integrity testing/documentation only. No evidence collection, model invocation,
target interaction, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
