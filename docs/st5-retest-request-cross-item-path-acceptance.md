# ST5 retest-request cross-item current-path ownership acceptance

Issue: #388

This is a tests/docs-only acceptance child of exact strict retest-request handoff
head `51ef9d8574e69c2f82c3f9635b508e835a822177`.

## Boundary

The persisted retest request must preserve the upstream ST4 invariant that one
current attack-path identity is owned by at most one change in the same request.

The current strict handoff already requires unique change and resolution IDs and
checks whether current-path lineage is present or absent for each
classification. Those local checks do not prevent two distinct changes from
claiming the same current attack path.

## Expected RED on the current #359 handoff

The regression starts from a canonical WORSENED producer request, adds a second
otherwise-valid item with unique change/subject/resolution identities, preserves
the first item's current-path lineage, and recomputes a matching
`request_sha256`.

The persisted parser currently accepts that cross-item collision even though
the upstream ST4 graph-diff/security-delta construction rejects the same
ownership shape.

## Collision boundary

This branch adds only:

- `tests/test_future_security_retest_request_cross_item_path_acceptance.py`;
- this document.

It does not modify #359 source/tests/docs, #356/#357/#363 files, #387 files,
retest authorization/tool-selection, scope authorization, or target-capable
code.

## Safety

Persistence-integrity only. No evidence collection, target interaction, tool
execution, remediation/retest execution, deployment, security verdict creation,
or attack-path mutation is introduced.
