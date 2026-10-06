# Evidence-freshness constraint snapshot isolation

Issue: #317

## Purpose

ST5 evidence-freshness constraints bind each unresolved evidence gap to the exact prior evidence and run identities that are forbidden from satisfying the next collection attempt. They are planning-only constraints: they do not select a capability, tool, target or security outcome and they grant no execution authority.

The artifact has nested freshness items, prior-evidence fingerprints and several canonical ID collections, so its public serialization snapshots must be deeply detached from canonical typed state.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- untouched JSON round-trips through the strict parser to the exact typed constraints;
- mutating top-level or nested `as_dict()` snapshots cannot mutate the source constraints or later JSON;
- independently returned snapshots do not alias freshness-item dictionaries, prior-evidence fingerprint dictionaries, or forbidden-ID containers;
- JSON-decoded caller-owned item, effect/path/capability, prior-evidence, forbidden-evidence and forbidden-run containers are copied into immutable typed state during parsing;
- later mutation of any caller-owned container cannot mutate the parsed constraints;
- `fresh_evidence_required=true` and `fresh_run_required=true` remain exact;
- capability and outcome-classification selection remain false;
- forbidden evidence/run IDs remain derived from and exactly bound to prior evidence;
- all action-authority fields remain false;
- future semantics remain unresolved and the security verdict remains not evaluated.

## Stop line

Freshness constraints describe what cannot be reused. They do not authorize the next evidence collection attempt and do not select capabilities, tools, targets, arguments, credentials or outcomes.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_freshness_constraints_snapshot_isolation.py`;
- `docs/future-security-evidence-freshness-constraints-snapshot-isolation.md`.

It does not modify the current freshness-constraints producer/parser/consumer source or existing tests/docs, and it does not modify freshness admission/coverage or later metadata/sufficiency branches.

## Safety

All proof is in-memory persistence/integrity testing. There is no evidence collection, capability/tool/target selection, classification, remediation/retest execution, deployment, or attack-path mutation.
