# Lab finding evidence-intake integrity pack

Issue: #852

This tests/docs-only composition is pinned above exact PR #184 head
`bc7242d5171856f69f2ec68d7b3cf06d64bbb938` and combines the two
non-overlapping lab finding evidence-intake contracts:

- #848 — canonical evidence-reference container/item/blank/duplicate integrity;
- #850 — mandatory evidence presence with legacy single-lane fallback.

## Preferred absorption target

A future `labsync.py` source-owner change should satisfy both suites together
before promotion. The combined contract requires:

- planner-driven finding-local evidence references remain accepted;
- the legacy top-level single-lane evidence fallback remains accepted;
- an explicitly empty local list may still use that valid fallback;
- malformed reference containers, item types, blanks and duplicates reject;
- a finding with no usable evidence source rejects;
- every rejected case fails before `DomainStore.record_finding()`;
- rejection leaves durable finding rows unchanged.

## Included files

From #848:

- `tests/test_labsync_finding_evidence_reference_integrity.py`;
- `docs/labsync-finding-evidence-reference-integrity.md`.

From #850:

- `tests/test_labsync_evidence_presence.py`;
- `docs/labsync-evidence-presence.md`.

This manifest is the only composition-specific file.

## Explicit exclusions

- no production source;
- no retest object-identity work (#849);
- no lower-level durable `DomainStore.record_finding()` contract (#851);
- no review-pipeline work (#840/#842/#845/#847);
- no scope authorization, target-capable workers, deployment, verdict or
  attack-path mutation.

## Safety

Offline temporary-SQLite acceptance only. No DNS/network access, target
interaction, evidence collection, capability execution, remediation/retest
execution, deployment, security verdict creation or attack-path mutation.
