# Passive-discovery profile admission integrity

Issue: #925  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

`ProspectProfile.add_signal()` is intended to be the passive-discovery admission gate. The profile must not expose another mutable path that lets caller code insert a signal without running the same fail-closed validation.

The current public list allows both constructor pre-seeding and direct `.append()` mutation, so an interactive or otherwise malformed signal can bypass `validate_for_unauthorized_discovery()`.

## Acceptance contract

- the public `signals` view is an exact immutable tuple;
- canonical valid signals remain addable through `add_signal()`;
- direct caller mutation of the returned signal collection is impossible;
- constructor pre-seeding cannot admit a signal without passive-discovery validation;
- rejected signals leave profile state unchanged;
- caller-owned signals are not repaired, coerced or silently normalized.

The production design remains owned by PR #175. This child contributes regression/contract evidence only and is intentionally expected RED until the owner closes the bypass.

## Safety

This contract is in-memory admission validation only. It performs no DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
