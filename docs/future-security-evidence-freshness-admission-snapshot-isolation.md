# Evidence-freshness admission snapshot isolation

Issue: #315

## Purpose

The ST5 evidence-freshness admission proves only that candidate evidence is new relative to the explicit freshness constraints and comes from the bound candidate run. It does not decide evidence suitability, select a security classification, create a transition resolution, or grant action authority.

Because the persisted artifact contains nested candidate-evidence fingerprints plus parallel evidence/capability ID collections, its serialization snapshots must be deeply detached from canonical typed state.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- untouched JSON round-trips through the strict #70 parser to the exact typed admission;
- mutating top-level or nested `as_dict()` snapshots cannot mutate the source admission or later JSON;
- independently returned snapshots do not alias nested fingerprint dictionaries, evidence-ID tuples, or capability-ID tuples;
- JSON-decoded caller-owned fingerprint lists/dictionaries, evidence-ID lists, and capability-ID lists are copied into immutable typed state during parsing;
- later mutation of any of those caller-owned containers cannot mutate the parsed admission;
- fingerprint evidence/run/capability binding remains exact;
- `freshness_check_passed=true` remains the only positive admission outcome;
- suitability evaluation, classification selection, transition creation and every action-authority field remain false;
- future semantics remain unresolved and the security verdict remains not evaluated.

## Stop line

Freshness admission is not evidence sufficiency or security classification. It cannot authorize collection, tools, target interaction, remediation, retest, deployment, or attack-path mutation.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_freshness_admission_snapshot_isolation.py`;
- `docs/future-security-evidence-freshness-admission-snapshot-isolation.md`.

It does not modify freshness-admission producer/handoff/consumer source or existing tests/docs, and it does not modify freshness coverage or later metadata/sufficiency branches.

## Safety

All proof is in-memory persistence/integrity testing. There is no evidence collection, suitability/classification decision, target interaction, remediation/retest execution, deployment, or attack-path mutation.
