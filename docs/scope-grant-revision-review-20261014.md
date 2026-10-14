# Grant revision narrowing review (offline, opt-in)

## Problem and ownership

A later grant snapshot can accidentally widen an existing customer's declared
asset scope, capabilities, risk ceiling, validity window, or recurring-retest
authority. LightUp needs a way for an operator to compare two **self-declared**
grant objects *before* a human reviews the change. This implementation is a
new isolated module; it does **not** alter the original `AuthorizationGrant`,
`ExecutionPolicy`, state store, active executor, web app, target adapters,
other workers, or CI configuration.

## What is implemented

`lightup.grant_revision_review.review_grant_revision(current, proposed)`
accepts the project's real frozen `AuthorizationGrant`/
`ScopeDefinition` classes and returns a small, privacy-safe receipt.
It enforces:

- Exact canonical grant, tenant, engagement, operator and reference identity.
- Non-increasing asset membership; no new assets.
- No removal of an excluded asset **while that asset remains in scope**.
  Removing an excluded asset entirely is safe and supported.
- Capability subset checks. **An empty `allowed_capabilities` means wildcard
  in the existing application**, not an empty allowlist. A proposed wildcard
  always yields `HOLD`, even when the original also had one.
- Exact `RiskLevel` identity, non-increasing maximum and refusal to present
  destructive risk 5 as a normal real-target grant.
- Strict timezone-aware UTC windows, preserved or shortened only, with
  well-ordered endpoints.
- `recurring_retest_allowed` must be a real `bool`: true-to-false is safe;
  false-to-true is rejected.
- Canonical bounded ASCII token sets. Duplicate, confusable, noncanonical
  and oversized inputs fail closed rather than being normalized by DNS.\n  Numeric IP literals and CIDR entries must also use strict canonical\n  `ipaddress` spelling: decimal/hex/short IPv4 aliases, noncanonical IPv6,\n  host-bit CIDR and noncanonical prefix widths return `HOLD`.

`REVIEW_ONLY` means only *syntactically non-widening relative to supplied
objects*. Even equality and old expired grants can return `REVIEW_ONLY`.
The caller's snapshots are untrusted; this checks neither their authenticity,
freshness nor authorization. It must **not** grant permission to scan.

Every receipt fixes `authorization_verified`, `permit_issued`,
`execution_enabled`, `merge_approved`, and `release_approved` to
`False`. `HOLD` is returned on invalid input. Neither result may be used
as a permit, execution signal, green CI attestation, verified client consent,
or human sign-off.

## Minimal offline usage

```python
from lightup.grant_revision_review import review_grant_revision

# current and proposed are locally constructed AuthorizationGrant objects.
receipt = review_grant_revision(current, proposed)
assert not receipt.execution_enabled
print(receipt.verdict, receipt.reason_code, receipt.narrowed_fields)
```

Local tests (with repository `PYTHONPATH=src`):

```bash
PYTHONPATH=src python -m unittest discover -s tests -p "test_grant_revision*review.py" -v
```

No database/customer state, internet target, socket, DNS, credentials, grant
issuer, release workflow, or scanner is accessed or modified. The test suite
uses real in-repository authorization data classes and synthetic `.test`
assets, and checks privacy and no-socket/no-database properties.

## Non-goals and mandatory gates

- **No integration into `ExecutionPolicy`, active admission, existing owner
  branches or production.** The module is not wired into any executor.
- Does not verify tenant, owner identity, reference signatures, clock trust,
  revocation, approval/release, mutable data-store version, policy version,
  full grant history, or original authorization provenance.
- A self-declared narrowed revision must never be treated as a trustworthy
  new grant or used to bypass active checks. Live/revocation validation is
  separately owned by other workers.
- Identity equality is not cryptographic authenticity. Exact string membership
  is intentionally conservative; adding IDNA, trailing-dot, DNS, IP aliases,
  or CIDR canonicalization requires a separate reviewed contract.

Next source-owner step (not automatic): integrate any desired human-facing
read-only preview with a **trusted persisted original grant**, version fencing
and explicit operator authorization. Independently review privacy and scope,
verify Python 3.11/3.14 exact-head hosted and registered permanent VPS test
logs, and obtain human merge/release approval.

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO
DEPLOY · NO REAL SCANS.**

## Atomic multi-client batch extension

`lightup.grant_revision_batch_review.review_grant_revision_batch(pairs)`
reviews a tuple of 1–32 `(old, proposed)` real grants, without I/O. It
rejects any malformed or widened pair and duplicate original grant IDs. It
also conservatively HOLDs when the **self-declared active asset strings** of
two distinct tenants overlap, avoiding a green-looking operator batch with
ambiguous assignments. Excluded assets are not counted as active for this
comparison. Overlap within one tenant remains reviewable, but still grants
no rights. Even if the first 31 pairs pass and the 32nd fails, the return is
an atomic `HOLD` with **zero** reviewed/narrowed counts. A positive return
only says that the self-declared batch met these syntactic constraints; no
customer entitlement, asset ownership, reviewer approval, revocation,
release or execution permission is proven. The batch function is also
uninstalled and non-authorizing. Nine genuine synthetic tests check these
boundaries, including privacy and the absence of database/network I/O.

## Usable local JSON CLI (W4, still non-authorizing)

`scripts/review_grant_revision_offline.py` is an opt-in read-only command-line
entrypoint for a **local** untrusted snapshot; it is not part of the app's
CLI, web endpoints, authorization ledger or active executor. Input is an exact
UTF-8 JSON object with a single `revisions` key containing 1–32 objects;
each object has exactly `current` and `proposed` grant snapshots.

Every grant must contain exactly `grant_id`, `client_id`,
`engagement_id`, `approved_by`, `reference`, `scope`,
`valid_from`, `valid_until`, and `recurring_retest_allowed`.
Each `scope` contains exactly `assets`, `excluded_assets`,
`allowed_capabilities`, and `max_risk`. Asset/capability/exclusion
collections are JSON string arrays (maximum 128 each); risk is a genuine
integer 0–5; retest is a literal JSON boolean; timestamps are exact
calendar-valid ASCII UTC seconds, such as `2026-10-01T09:00:00Z`.
Unrecognized authority-looking keys are **denied**, not ignored.

```bash
PYTHONPATH=src python scripts/review_grant_revision_offline.py lab/fixtures/grant_revision_narrowing_synthetic.json
```

The checked-in fixture uses invented `.test` assets and reduces both risk and scope; it is **not a real grant or real customer**. Expected output is a `REVIEW_ONLY` receipt with all five flags `false` and exit code `3`. Do not chain exit 3 into a scan.\n\nThe CLI accepts **only a regular local input file** (<=64 KiB) and rejects
symlinks, directories, pipes, oversize input, invalid UTF-8/JSON, duplicate
JSON keys, nonfinite constants, ambiguous types, unknown keys, and entire
malformed batches. Errors print an opaque `HOLD` JSON receipt, not a path,
exception, customer identifier or input contents.

**Crucially, exit code is always NONZERO:** `3` for `REVIEW_ONLY`,
`2` for `HOLD`. Do not treat a subprocess exit 3 as successful consent
or chain it to an active command. Every output repeats all five false
authority flags. This is local human-review preparation, not a real-target
admission or execution decision.

## W5: full-history monotonic narrowing (offline, opt-in)

`lightup.grant_revision_history_review.review_grant_history` accepts an
exact tuple of **2–8 self-declared original-model AuthorizationGrant versions**
and checks every *adjacent* change, not merely the oldest and newest.
This catches temporary expansions of assets, capabilities, risk, validity
windows, retest rights, excluded-asset access or tenant identity followed
by a later reversion. Consecutive duplicate/no-op versions are refused.
There is no partial REVIEW_ONLY on a later bad version: HOLD returns zero
versions, zero reviewed transitions and no narrowed fields. The same five
authority flags remain false under both verdicts.

The existing strict local JSON CLI also now accepts the separate top-level
shape `{"history":[grant_version_1,grant_version_2,...]}` (exactly 2–8).
The original `{"revisions":[{"current":...,"proposed":...}]}` mode
remains unchanged. Mixing both modes, unknown fields, invalid order,
noncanonical types or excessive versions yields opaque HOLD.

Reproducible fictional offline sample:

```bash
PYTHONPATH=src python scripts/review_grant_revision_offline.py lab/fixtures/grant_revision_history_narrowing_synthetic.json
```

The sample contains three `.test`-only synthetic snapshots, with two strictly
narrowing transitions. A valid-looking receipt has `verdict=REVIEW_ONLY`,
`version_count=3`, `reviewed_transitions=2`, four listed narrowing
dimensions and **all five false authorization flags**. CLI exit code is still
**3, never 0** (HOLD remains 2). Passing history shape proves **nothing**
about the authenticity, completeness, actual chronological order, consent or
revocation of the submitted snapshots. It is easy for a malicious source
to omit the bad middle version. Production would additionally need a trusted,
immutable, tenant-bound revision ledger, signature/version fencing, a trusted
clock and independent security/operator approval. None is implemented or
authorized by this optional offline checker.

Synthetic regression suite: `test_grant_revision_history_review.py` and
`test_grant_revision_history_cli.py`. Both are read-only and do not touch
customer records, production dispatcher, network targets or worker files.

## W6: cross-tenant IP/CIDR truthfulness

The simple local grant **batch** reviewer intentionally does not implement
CIDR membership, DNS, authority normalization or ownership proof. A claim
that two cross-tenant IP/CIDR *strings* differ would be misleading:
`192.0.2.0/24` and `192.0.2.12` name overlapping space. For any
multi-tenant batch containing a canonical live IP, IPv6, CIDR or ambiguous
colon host:port authority, the whole review now returns
`HOLD/network_identity_requires_separate_review` and zero counts, even
when declared networks happen to be disjoint. Ordinary syntactically
canonical, disjoint DNS name declarations remain reviewable without target
interaction. Single-tenant IP-shaped snapshots can still receive
`REVIEW_ONLY` for their local syntactic *narrowing* only, with all five
authority flags false.

Proper network isolation is separately owned by its independent scope
lane; this change deliberately does **not** take over that work or confer
a certificate of non-overlap. It introduces no DNS calls or active target I/O.

## W7: atomic multi-tenant full-history dossier

`lightup.grant_revision_history_batch_review.review_grant_history_batch`
composes **1–16 declared histories**, each with **2–8 grant snapshots**.
Every transition within each history is checked for monotonic narrowing
before applying the already-isolated multi-tenant grant batch reviewer
to each declared oldest/newest pair. A late invalid history, duplicate
grant ID, same-active-asset cross-tenant conflict, or ambiguous IP/CIDR
collapses the **entire** packet to HOLD with zero accepted histories and
zero transitions. The result is non-authorizing, cannot validate omitted
history or trustworthy consent, and deliberately does not perform IP/CIDR
network disjointness (that capability belongs to its separate owner).

The same local nonzero-exit CLI supports one more mutually exclusive
top-level schema: `{"histories":[[grant_snapshot_1,grant_snapshot_2],...]}`.
A packet must have exactly one of `revisions`, `history`, or
`histories`. Unrecognized keys, oversized input and authority spoofing
remain HOLD. The genuine synthetic two-tenant fixture runs with:

```bash
PYTHONPATH=src python scripts/review_grant_revision_offline.py lab/fixtures/grant_revision_histories_batch_synthetic.json
```

It returns a `REVIEW_ONLY` *shape receipt only* with 2 reviewed histories,
2 reviewed transitions, 2 narrowing dimensions, all authority flags
`false`, and shell exit `3` (never zero). Tests cover cross-tenant
collisions, later unsafe versions, duplicate grant IDs, network aliases,
maximal bounded packet size, synthetic user privacy and no target I/O.
The historical versions are UNTRUSTED self-declared text and **cannot**
be used to launch assessments, renew grants or skip revocation checks.
