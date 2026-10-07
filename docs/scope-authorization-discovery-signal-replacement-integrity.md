# Passive-discovery signal replacement integrity

Issue: #927  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

Making the public signal collection immutable is insufficient if callers can replace the entire `signals` attribute after construction. Whole-attribute replacement would still bypass `ProspectProfile.add_signal()` and its passive-discovery validation.

## Acceptance contract

- `add_signal()` remains the only public mutation path for admitted signals;
- assigning a new object to `profile.signals` after construction fails deterministically;
- an attempted replacement cannot alter an existing admitted snapshot;
- empty profiles remain empty after a rejected replacement;
- caller-owned replacement containers and signals are left unchanged.

Production implementation remains owned by PR #175. This child is tests/docs-only and intentionally expected RED until the owner absorbs the boundary.

## Safety

Local in-memory admission validation only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
