# Passive-discovery admission integrity pack v9

Issue: #936  
Production owner: draft PR #175  
Base composition: coherent v8 at `d4b3491d94dc6230c0e0ed2c75187e5712a4961f`

v9 retains all nine v8 admission/provenance contracts and adds one composition-level state-atomicity proof.

## Retained contracts

- #915 canonical built-in float confidence;
- #916 exact outer `ProspectSignal`;
- #921 exact `SignalCategory`;
- #923 exact non-empty source provenance;
- #925 constructor/list admission gate;
- #927 collection replacement guard;
- #929 immutable profile identity;
- #931 canonical profile identity text;
- #933 canonical signal summary text.

## New v9 invariant

Any rejected signal, collection mutation or identity rebinding attempt must preserve the exact already-admitted tuple snapshot, original prospect identity and aggregate confidence. The integration regression in `tests/test_discovery_admission_atomicity.py` exercises these contracts together instead of only in isolation.

## Ownership and safety

- `src/lightup/discovery.py` remains solely owned by PR #175.
- v9 changes tests/docs only.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack remains intentionally expected RED until the production owner absorbs the underlying contracts.
