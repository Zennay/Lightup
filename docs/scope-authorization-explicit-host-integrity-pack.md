# Explicit-host identity acceptance pack

Pinned parent: `main` at `1abc16a66fc490b1ba7272890dfbf498482fca9c`.

This composition branch collects collision-free policy/target identity contracts
for `ScopePolicy.explicit_hosts` without modifying production source.

Included contracts:

- #286: explicit host membership is exact and never suffix/wildcard inheritance;
- #367: policy entries are literal host identities, not URL-like configuration;
- #368: policy-side surrounding whitespace is not silently normalized into authority;
- #723: terminal-dot normalization removes at most one DNS root dot, so malformed
  multi-dot target/policy text cannot inherit explicit-host or loopback authority.

## Validation posture

The #286/#367/#368 controls describe behavior already expected to remain green on
the pinned parent. #723 adds three expected-RED methods on current source:

1. target `example.test..` must not collapse to allowlisted `example.test`;
2. malformed policy entry `example.test..` must not authorize canonical/rooted target;
3. `localhost..` must not collapse into syntactic loopback trust.

The canonical one-root-dot explicit-host and localhost controls remain green.

## Ownership and stop line

This pack is tests/docs only and intentionally does not edit
`src/lightup/scope.py`. Active scope source owners retain production ownership.
Do not rewrite or merge over existing #286/#367/#368 branches; this successor
pack is the combined absorption/proof target.

No DNS/network I/O, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.
