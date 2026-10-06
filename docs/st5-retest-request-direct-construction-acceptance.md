# ST5 isolated retest-request direct-construction acceptance

Issue: #394

This tests/docs-only acceptance slice starts from exact PR #52 head
`e44abdc141ea21e3298894238bd14c62e0c1227f`.

## Boundary

The canonical retest-request producer is live-lineage validated, but the frozen
`FutureSecurityRetestRequestItem` and `FutureSecurityRetestRequest` typed
objects currently have no constructor-level semantic invariants. Direct
construction or `dataclasses.replace()` can therefore manufacture typed state
that the producer cannot emit before any persisted handoff is reached.

The typed-object boundary should reject contradictory state immediately while
leaving exact live-lineage and persisted-digest validation at their existing
consumer boundaries.

## Acceptance contract

Canonical producer objects remain constructible. Direct replacement must fail
closed for:

- incomplete request lifecycle or loss of isolated-future-state requirement;
- positive execution, target-interaction, deployment, or attack-path authority;
- resolved future semantics or a claimed security verdict;
- zero current/future twin versions;
- item classification, graph-action, next-action, purpose, or remediation-state
  combinations that contradict the canonical classification semantics;
- missing required current-path, effect, evidence, or capability lineage;
- non-canonical resolution SHA-256 shape.

Digest equality is deliberately not asserted here. Existing strict/live
consumer tests may continue to construct a syntactically canonical stale digest
and prove that the later boundary rejects it.

## Expected RED on exact PR #52

The current frozen dataclasses have no `__post_init__` validation, so
`dataclasses.replace()` accepts every contradictory state above. The
regression therefore remains RED until the producer owner adds typed-object
invariants.

## Collision boundary

This branch adds only:

- `tests/test_future_security_retest_request_direct_construction_acceptance.py`;
- this document.

It does not modify PR #52 source/tests/docs, #356/#357/#359/#363, retest
authorization/tool-selection, scope authorization, or target-capable code.

## Safety

Integrity narrowing only. No evidence collection, model invocation, target
interaction, tool/remediation/retest execution, deployment, verdict creation or
attack-path mutation is introduced.
