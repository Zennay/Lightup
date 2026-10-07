# Passive-discovery summary provenance integrity

Issue: #933  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

A passive-discovery signal must carry an explicit human-auditable summary of what the public observation represents. Valid category/source metadata is insufficient when the explanatory summary is absent, blank or caller-polymorphic.

## Acceptance contract

`ProspectSignal.validate_for_unauthorized_discovery()` must require `summary` to be an exact built-in `str` with non-whitespace content.

The boundary rejects:

- `None` and unrelated objects;
- string subclasses;
- empty strings;
- whitespace-only strings.

Canonical summary text is preserved exactly. Rejection happens before `ProspectProfile.signals` mutation, and no trimming, coercion, synthesis or repair occurs.

Production implementation remains owned by PR #175. This child is tests/docs-only and intentionally expected RED until the owner absorbs the contract.

## Safety

Local passive-discovery provenance validation only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
