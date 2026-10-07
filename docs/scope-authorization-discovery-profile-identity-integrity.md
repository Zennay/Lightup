# Passive-discovery profile identity immutability

Issue: #929  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

Once passive-discovery signals have been admitted to a prospect profile, the identity that owns that signal snapshot must not be silently rebound by caller mutation.

Allowing `prospect_id` or `organization_name` reassignment after admission breaks provenance: the same validated signals can be made to appear as evidence for another prospect without another validation boundary.

## Acceptance contract

- canonical profile construction remains available;
- canonical `add_signal()` remains available;
- `prospect_id` cannot be reassigned after construction;
- `organization_name` cannot be reassigned after construction;
- rejected identity replacement leaves both identity and admitted signals unchanged;
- replacement values are not coerced, normalized or copied into the profile.

Production implementation remains owned by PR #175. This child is tests/docs-only and intentionally expected RED until the owner absorbs the boundary.

## Safety

Local in-memory provenance integrity only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
