# Remediation evidence-bundle snapshot isolation

Issue: #319

## Purpose

The ST5 remediation evidence bundle is a read-only manifest of the exact live evidence supporting remediation-required findings. It may indicate that remediation **text authoring** is ready, but it never authorizes code/config changes, tools, target interaction, execution, deployment, a security verdict, or attack-path mutation.

Because the bundle contains nested remediation items and nested evidence references, its public serialization surfaces must be deeply detached from canonical typed state.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic for remediation-ready and evidence-gap bundles;
- untouched JSON round-trips through the strict bundle parser to the exact typed artifact;
- mutating top-level or nested `as_dict()` snapshots cannot mutate the source bundle or later JSON;
- independently returned snapshots do not alias item dictionaries, evidence-reference dictionaries, or lineage tuples;
- JSON-decoded caller-owned item lists, evidence lists/dictionaries, current-path IDs, effect IDs and capability IDs are copied into immutable typed state during strict parsing;
- later mutation of any caller-owned nested container cannot mutate the parsed bundle;
- remediation-authoring readiness remains derived from actual remediation items plus the blocking evidence-gap count and cannot be forged;
- remediation-required and future-state-retest-required item markers remain exact true for remediation items;
- execution, code-change, target, deployment and attack-path authority remain false;
- future semantics remain unresolved and the security verdict remains not evaluated.

## Stop line

`remediation_authoring_ready=true` permits only a later bounded remediation-text authoring stage. It is not implementation, execution, deployment, retest or target authority.

## Collision boundary

This slice adds only:

- `tests/test_future_remediation_evidence_bundle_snapshot_isolation.py`;
- `docs/future-remediation-evidence-bundle-snapshot-isolation.md`.

It does not modify the remediation evidence-bundle producer/handoff source or existing tests/docs, and it does not modify remediation authoring/text/review or implementation-planning branches.

## Safety

All proof is in-memory persistence/integrity testing. There is no remediation authoring, code/config generation, target interaction, tool execution, retest, deployment, verdict creation or attack-path mutation.
