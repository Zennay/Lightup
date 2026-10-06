# ST5 remediation evidence bundle positive-version acceptance

Issue #398 preserves the upstream positive twin-version contract at the
persisted remediation-evidence-bundle boundary.

## Upstream contract

The transition proposal lineage requires `current_twin_version` and
`twin_version` to be positive exact integers. The remediation/retest plan is
built only from that live-validated lineage, and the remediation-evidence-bundle
producer copies those versions from the plan. A canonical bundle therefore
cannot contain version zero.

The strict #194 persisted handoff currently routes both version fields through a
non-negative-integer validator. That allows `0` even though it is not a
producer-reachable value.

## Acceptance

The dedicated regression uses a real WORSENED remediation-evidence bundle as
the positive control. For each twin-version field it then:

1. replaces only that version with `0`;
2. recomputes an exact matching public `bundle_sha256`;
3. requires strict persisted parsing to fail closed.

Recomputing the digest makes this independent of stale-digest rejection.
Canonical producer bundles must continue to round-trip unchanged.

## Collision boundary

This is a tests/docs-only child of the active #194 handoff branch. It does not
modify #194 source or existing tests/docs and does not take over its source
ownership.

The contract is downstream and distinct from #384 at the remediation/retest
plan handoff and #387 at the isolated retest-request handoff. It does not touch
#190/#382/#359/#393/#396 or scope-authorization work.

## Safety

Persistence-integrity acceptance only. No evidence collection, model
invocation, target interaction, tool execution, remediation/retest execution,
deployment, verdict creation, or attack-path mutation.
