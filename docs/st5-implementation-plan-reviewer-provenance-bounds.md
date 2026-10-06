# ST5 implementation-plan reviewer provenance bounds

Issue #304 closes a producer-to-persistence mismatch in the independent remediation implementation-plan review path.

The #281 producer previously required reviewer provider/model identifiers to be merely non-empty, while the strict #283 handoff already rejected provenance longer than 256 characters or containing NUL. That allowed the canonical reviewer path to create an artifact that could not pass its own persisted boundary.

## Contract

Reviewer provenance now uses the same bounded identity contract before the review digest or artifact is constructed:

- provider ID is a non-empty string;
- model ID is a non-empty string;
- neither value may contain NUL;
- each value is at most 256 characters;
- values are never truncated or rewritten.

The review dataclass enforces the same contract independently in `__post_init__`, so direct construction and `dataclasses.replace()` cannot bypass it. The strict #283 handoff remains independently strict.

## Regression proof

The dedicated regression proves:

- exactly 256-character provider and model IDs are preserved byte-for-byte;
- that canonical artifact serializes and passes the complete strict/live #283 reload;
- 257-character provider/model IDs fail before a review artifact is returned;
- NUL-bearing provider/model IDs fail closed;
- direct reconstruction/replacement is subject to the same bounds.

## Safety

This is provenance-integrity narrowing only. It does not expand model capabilities, invoke external targets, create executable remediation, run tools, retest, deploy, resolve future state, create a security verdict, or mutate attack paths.
