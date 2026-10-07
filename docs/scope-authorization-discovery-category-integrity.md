# Passive-discovery category integrity

Issue: #921  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

Unauthorized prospect discovery is deliberately passive. A `ProspectSignal` may only carry one of LightUp's canonical `SignalCategory` values before it can be admitted into a `ProspectProfile`.

Value equality is not sufficient at this boundary. Raw strings such as `"configuration"`, subclasses of `str`, and unrelated caller-controlled objects must fail closed rather than being treated as typed taxonomy metadata.

## Acceptance contract

`ProspectSignal.validate_for_unauthorized_discovery()` must:

1. accept exact `SignalCategory` enum members;
2. reject every non-`SignalCategory` object with `ValueError("category must be an exact SignalCategory")`;
3. reject before `ProspectProfile.signals` is mutated;
4. never coerce, normalize, repair, or replace the caller-owned category object;
5. preserve all existing passive/public-source restrictions.

The regression is intentionally tests/docs only. Production implementation belongs to PR #175 so this child does not compete for `src/lightup/discovery.py`.

## Safety

This contract exercises local object validation only. It performs no DNS or network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, or authorization widening.
