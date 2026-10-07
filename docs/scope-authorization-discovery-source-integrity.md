# Passive-discovery source provenance integrity

Issue: #923  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

A passive-discovery signal may claim `public_source=True` only while carrying explicit, auditable source provenance. The provenance label is therefore part of admission integrity, not optional display metadata.

## Acceptance contract

`ProspectSignal.validate_for_unauthorized_discovery()` must reject unless `source` is:

- an exact built-in `str`;
- non-empty after checking for whitespace-only content;
- preserved exactly as supplied when valid.

The boundary must reject `None`, arbitrary objects, string subclasses, empty strings and whitespace-only strings before `ProspectProfile.signals` is mutated. It must not trim, coerce, synthesize or replace caller-owned source provenance.

Production implementation remains owned by PR #175. This child is tests/docs only and intentionally expected RED until that owner absorbs the contract.

## Safety

The contract is local validation only. It performs no DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
