# LightUp manifest mutation matrix — scope-authorization #1370

## Purpose and immutable boundaries

`snapshot_manifest(get_capabilities())` is the current source-local,
**not-authorizing** capability manifest. The offline dossier's three
independent reviewers must reject invalid metadata consistently. The
parser already imposes size, depth, canonical Unicode, identifier,
boolean, state and duplicate-key constraints. This test-only matrix
makes those controls executable and regression-resistant on Python
3.11 and Python 3.14.

```bash
python3 -m unittest discover -s tests -p 'test_scope_incubation_manifest_adversarial_matrix_20261014.py' -v
```

**33 deterministic test methods** (including bounded subcases) work on
the real 31-entry registry and mutate one property at a time.

- **Malformed, must reject in the strict parser and atomic dossier:**
  duplicate root/record keys; invalid bytes and envelopes; unknown
  root/record fields; empty, wrong-type and too-many records; duplicate
  capability ID; excessive byte size; deep nested name structures;
  nonfinite JSON; noncanonical, overlong or empty IDs; invalid state
  and activation types; blank/control/oversize name and description;
  Unicode normalization and surrogate input.
- **Semantically unchanged:** reordered records and record fields,
  or different JSON whitespace remain `REVIEW_ONLY` but never confer
  grants, permits, release or scanning rights.
- **Semantically changed but still canonical:** name, state, lab
  membership, activation or added capability generate a privacy-safe
  `HOLD` with only fixed violation labels, not source text. A valid
  legacy three-field manifest is accepted by the historical comparator
  but **not** by this incarnation's five-field incubation dossier.
- **Combination proof:** an explicit-activation violation alongside a
  secret description/name change cannot accidentally leak that text or
  turn the review into an execution permit.

Malformed manifests produce a generic atomic `HOLD` with **no
fingerprint, partial violations or field details**. The five authority
fields in receipts remain literally false for every output.

The checked-in capability reference is a developer-owned source
snapshot, **not signed provenance**. These tests do not verify
customer ownership, scope, live grant/revocation or runtime executor
authorization. They perform no network, targets, attacks, customer
data, database writes, production deployment or VPS mutation.

Only new regression/docs files, never concurrently owned production
source, workflow/CI, workers or runner settings. Promotion to main
requires hosted exact-head tests and independent source-only review.
