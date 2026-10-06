# ST5 retest-request canonical item-order acceptance

Issue: #389

This is a tests/docs-only acceptance child of exact strict retest-request handoff
head `51ef9d8574e69c2f82c3f9635b508e835a822177`.

## Boundary

The canonical producer lineage orders transition items by
`(change_node_id, subject_node_id)`, and the later remediation/retest plan and
isolated retest-request builders preserve that sequence.

The strict persisted handoff must therefore reject a caller-owned item sequence
that is not already in canonical order. It must not sort or normalize persisted
input silently.

## Structural isolation

The regression creates a two-item WORSENED request shape from a real producer
fixture, then gives the two items:

- unique change IDs;
- unique subject IDs;
- unique resolution IDs and canonical SHA-256 values;
- distinct current attack-path IDs;
- otherwise unchanged valid classification/action/purpose/lineage semantics.

The canonical `change-a`, `change-z` sequence is accepted. Reversing only
the item sequence and recomputing a matching `request_sha256` must fail closed.

This keeps the contract independent from #387 positive versions and #388
cross-item current-path ownership.

## Collision boundary

This branch adds only:

- `tests/test_future_security_retest_request_item_order_acceptance.py`;
- this document.

It does not modify #359 source/tests/docs, #356/#357/#363 files, #387/#388
files, retest authorization/tool-selection, scope authorization, or
target-capable code.

## Safety

Persistence-integrity only. No evidence collection, target interaction, tool
execution, remediation/retest execution, deployment, security verdict creation,
or attack-path mutation is introduced.
