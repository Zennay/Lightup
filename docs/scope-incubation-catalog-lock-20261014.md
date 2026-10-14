# LightUp scope #1354 — closed-world incubation capability catalog

LightUp remains **INCUBATE M3/M7, PLAN/LAB ONLY**. This opt-in, offline,
non-authorizing source-local review catches a gap in the existing incubation
posture checker: even with every tool requiring explicit activation, an
ordinary capability can be silently added, removed, or reclassified from
`planning` to `lab_only` or `disabled`. The prior single-snapshot
posture checker only pins five designated sensitive lab IDs. Full historical
drift checks need an independently selected baseline, which may be absent.

## Implemented boundary

`src/lightup/capability_registry_incubation_catalog_review.py` has a
**deliberately explicit reviewed M3/M7 catalog**: the 26 known ordinary IDs
must each retain the `planning` state, the five isolated lab IDs must stay
`lab_only`, every record must require explicit activation and *no other IDs*
may appear. A missing known ID, unreviewed new ID, any reclassification,
or explicit activation turned off produces an atomic `HOLD`.

Input reuses the existing 32-KiB, 128-record, full five-field parser and
canonical metadata fingerprint, rejecting legacy/partial metadata,
invalid Unicode, duplicate names/keys, non-builtin booleans and malformed
envelopes. Receipts include only canonical capability IDs and fixed violation
codes, never capability names, descriptions or other source text.
The reference intentionally requires **code review whenever product coverage
changes**. It is a *developer-controlled assumption*, not a cryptographically
trusted policy, provenance proof or signed customer grant.

## Use

```sh
python3 scripts/review_scope_incubation_catalog_offline.py
python3 -m unittest discover -s tests -p 'test_scope_incubation_catalog_lock_20261014.py' -v
```

The CLI reads only local in-process registry metadata and takes **no args**.
It never accepts file paths, target addresses or tenant credentials, calls
network/DNS, scans targets, writes grants or installs an executor gate.
Both statuses are deliberately nonzero: `REVIEW_ONLY` exits **3** for an
unchanged assumed catalog, `HOLD` exits **2** otherwise. Even
`REVIEW_ONLY` includes five permanently **false** flags:
`authorization_verified`, `permit_issued`, `execution_enabled`,
`merge_approved`, `release_approved`. Neither status can authorize
`review && scan`. Tested against real `get_capabilities()` exporter data,
synthetic unexpected/removed/reclassified entries, metadata malformations,
stable order, bounded privacy-safe receipts and actual CLI exit behavior.

## Remaining boundaries

This is a second, complementary check, **not a replacement** for the
preexisting field-level drift, historical sequence, checkout comparison,
incubation posture or runtime authorization policy. It cannot authenticate
the checkout, customer/tenant consent, asset ownership, operator approval,
current revocation state, exact CI runner identity or any real target.
A developer could edit both the registry and this reference; independent
source/security review and trusted provenance remain necessary. Review
source-only PRs under the current Notion developer-merge policy with
exact-head hosted tests; deployment, registered VPS release evidence, grants
and actual security assessments are entirely separate decisions.
