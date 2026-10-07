# Passive-discovery admission state atomicity

Issue: #936  
Base pack: coherent v8 at `d4b3491d94dc6230c0e0ed2c75187e5712a4961f`  
Production owner: draft PR #175

## Goal

The individual passive-discovery contracts must compose into one fail-closed state machine. Rejecting malformed evidence or a caller mutation must not partially change a profile that already contains a canonical admitted signal.

## Integrated proof

The composition-level regression starts with one canonical signal bound to one canonical prospect identity, then independently exercises:

- malformed category identity;
- blank summary provenance;
- blank source provenance;
- non-canonical confidence type;
- non-public provenance;
- target-interactive provenance;
- direct public collection mutation;
- whole-collection replacement;
- prospect ID rebinding;
- organization-name rebinding.

After every rejected operation, the exact tuple snapshot, prospect identity and aggregate confidence must remain unchanged. Caller-owned replacement objects are also left unchanged.

This proof does not add a new production rule; it proves the already-pinned v8 rules are atomic when composed. Production implementation remains owned by PR #175.

## Safety

Local in-memory validation only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
