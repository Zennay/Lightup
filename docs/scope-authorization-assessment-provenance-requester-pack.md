# Assessment-request provenance pack — requester extension

Issue: #895

## Parent

This composition is pinned directly above the active #878 assessment-provenance head:

`43238e5cfc61e238461ba0e4fcafae617e360986`

That parent is itself based on exact PR #146 head `33c67f8e8b17bd9214c29d02fc52954cc42655da`.

## Added contract

This child carries #879 into the active assessment-request provenance pack without changing any existing #878 acceptance:

- persisted `requested_by` must reconstruct as an exact built-in non-blank `str`;
- BLOB, blank and whitespace-only requester provenance fail closed;
- rejection preserves corrupt SQLite state unchanged for forensic visibility.

## Combined unresolved read-side gaps

The pack now keeps these independent read-side authorization provenance contracts adjacent:

- #877 persisted assessment asset shape;
- #879 persisted requester provenance;
- #880 decision provenance coherence.

The existing risk/mode identity regressions remain source-green controls on #146.

## Collision and authority boundary

This branch contains tests/docs only and must not modify `src/lightup/domain.py`, PR #146, or any target-capable surface. It introduces no target interaction, scanning, capability execution, remediation/retest execution, deployment, security verdict or attack-path mutation.

## Runner posture

Known expected-RED composition stays branch-only while the shared permanent LightUp self-hosted lane is occupied. No duplicate canonical workflow should be dispatched solely for this acceptance pack.
