# ST4 security-delta report snapshot isolation

Issue: #333  
Parent: #328 exact head `baa39ce561201c6f8be27f66c718581f5de7e78a`

This tests/docs-only child proves the hardened ST4 security-delta report's producer snapshots are detached and deterministic. It does not introduce a persisted parser contract.

## Proven producer boundary

- repeated `FutureAttackPathSecurityDeltaReport.to_json()` output is byte-for-byte deterministic for introduced, worsened, improved, removed and insufficient-evidence classifications;
- JSON output is canonical under sorted keys and compact separators;
- mutating top-level `as_dict()` identity, completion, mutation-authority, future-state, verdict or digest fields cannot alter the typed report;
- mutating nested item identity, classification/action text or evidence/capability lineage in a snapshot cannot alter the source item;
- independently returned `as_dict()` snapshots contain independently materialized nested item dictionaries;
- replacing snapshot lineage tuples is caller-local and cannot rewrite the immutable typed lineage or later JSON.

## Deliberate scope boundary

This slice does **not** claim that arbitrary persisted dictionaries can be safely reloaded. There is no strict ST4 security-delta persisted parser in this branch. Snapshot isolation proves only that the producer's exported Python/JSON views are detached from the source typed object.

The direct-construction stop line remains owned by #328. Stale-but-canonical `report_sha256` values remain a live-consumer validation concern exactly as documented there.

## Safety

Pure in-memory serialization/integrity proof only. No target interaction, evidence collection, tool execution, remediation/retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.

## Collision boundary

Only these files belong to #333:

- `tests/test_future_attack_path_security_delta_report_snapshot_isolation.py`;
- `docs/future-attack-path-security-delta-report-snapshot-isolation.md`.

No #328 source/test/doc file or any graph-diff, remediation/retest, evidence-bundle, authoring, implementation-planning, parser-purity or scope-authorization file is modified.
