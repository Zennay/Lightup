# LightUp incubation semantic field diagnostics — #1360

LightUp is **INCUBATE M3/M7 · PLAN/LAB ONLY**, with no real active target
interaction. The preexisting closed-world catalog checker (#1355/#1357)
properly returns `HOLD` when a capability name or description changes.
For a metadata-only change, however, it cannot identify which source field
changed, forcing manual inspection of all 31 capabilities.

## New opt-in human review tool

`src/lightup/capability_registry_incubation_field_review.py` contains
a separately reviewed **static 31-entry semantic reference** of both
human-readable metadata fields. It first invokes the existing validated
closed-world posture check and bounded canonical manifest parser. A
state/activation/membership/invalid-manifest mismatch returns **atomic
HOLD with no misleading partial field diagnostics**. Only a valid catalog
whose reviewed semantic fingerprint differs can produce specific
field-level diagnostics.

For such safe-to-explain semantic drift, the output reports **only
canonical capability IDs and fixed field names** `name`/`description`,
sorted deterministically. It never prints old/new user-supplied free text,
targets, customer information or untrusted detail. Multiple field changes
are reported together, and a reversed-record order remains equivalent.

Optional CLI (no file or target arguments):

```bash
python3 scripts/review_scope_incubation_fields_offline.py
python3 -m unittest discover -s tests -p 'test_scope_incubation_field_diagnostics_20261014.py' -v
```

**REVIEW_ONLY exits 3** for an identical reviewed catalog;
**HOLD exits 2** for changed or invalid metadata. Both exit nonzero, so
`review && execute` never authorizes anything. All five
`authorization_verified`, `permit_issued`, `execution_enabled`,
`merge_approved` and `release_approved` flags are always false.

The reference map is **plain reviewed source code**, not an out-of-band
signature, trusted Git provenance or independent release history; a
developer could alter both it and production metadata. The tool does
not authorize grants, operator approval, client/tenant consent, targets,
risk changes, real scans or deployment. Existing runtime security owners
remain responsible for actual authorization gates and reviews.

14 real-source and synthetic regression methods cover both individual
fields, simultaneous changes, multiple IDs, invalid/legacy/malformed
manifest, source changes, stable ordering, privacy, immutable receipt,
no-success CLI semantics and argument refusal. All new paths are isolated
from other workers and original source/runner/workflow changes.
