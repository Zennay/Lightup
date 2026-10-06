# ST5 remediation authoring chain invariant

This regression package proves the independent remediation-authoring lane stays
non-executable across both persisted boundaries.

## Covered chain

1. Build the live ST5 remediation evidence bundle from the exact remediation
   plan and current evidence ledger.
2. Serialize, strictly parse, and immediately live-revalidate that bundle.
3. Build the bounded remediation authoring request from the live-valid bundle.
4. Serialize, strictly parse, and immediately live-revalidate that request.

The invariant runs with real producer fixtures for introduced and worsened
classifications.

## Safety assertions

The chain may set only `authoring_requested=true`. It must never create:

- a remediation proposal;
- code/config change authority;
- a tool call;
- target-interaction authority;
- execution authority;
- future-state retest authority;
- deployment authority;
- attack-path mutation authority;
- resolved future semantics or a security verdict.

Exports are also checked to remain bounded to lineage and evidence-reference
metadata; raw payload/source/metadata, credentials, target arguments, and
patches stay absent.

## Fail-closed regressions

The invariant proves that:

- improved, removed, and insufficient-evidence outcomes stop before authoring;
- duplicate JSON keys fail at both persisted boundaries;
- live evidence-ledger drift invalidates an already persisted authoring request.

## Ownership

This is a test/documentation-only child of PR #198 at exact head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`. It changes no production source.
It is intentionally separate from #157/#159, whose persisted-consumer contract
explicitly excludes the #60 remediation-authoring/evidence-bundle lane.

Refs #199.
