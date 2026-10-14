# LightUp atomic incubation dossier: status/evidence coherence (#1366)

## Gap repaired

The opt-in human metadata dossier (#1365) originally checked that each of
three reviewer status labels said only `HOLD` or `REVIEW_ONLY`, and
sanitized the format of any reported violation tuples. It did **not**
require the status and its own evidence to be logically compatible. A
compromised, patched or accidentally changed component could report
`REVIEW_ONLY` *while returning violations*. The aggregate could then
appear entirely review-only, despite retaining explicit error evidence.
This is a local status-invariant bug, not a grant/scan authorization bypass.

## Fail-closed contract

New `_coherent_components` verifies the exact fixed reason and evidence
relations for each kind of legitimate result:

- Whole catalog `REVIEW_ONLY` only with its empty violation set, the
  independently clean incubation posture and unchanged field review.
- Metadata-only drift `HOLD` only with a clean posture, **actual**
  changed name/description field labels, and the same fingerprint.
- Catalog membership/state/activation `HOLD` only with at least one
  canonical violation, an atomic field-review boundary HOLD and no field
  details; every posture violation must map to the corresponding
  catalog violation for the identical capability ID.
- A posture `REVIEW_ONLY` cannot contain any violation; a posture
  `HOLD` requires nonempty violations and the expected fixed reason.
- Unknown/malformed/contradictory tuples, statuses, explanations and
  fingerprints become a **single privacy-safe atomic HOLD** without
  a partial positive fingerprint, field detail or violation list.

The existing conservative 31-ID closed-world catalog, bounded input
decoding and five explicit false authority flags remain intact.

## Verification

```bash
python3 -m unittest discover -s tests -p 'test_scope_incubation_dossier_coherence_20261014.py' -v
```

20 unit/integration-style tests exercise actual 31-capability source,
semantic changes, ordinary/lab state changes, activation, added/removed
capabilities, 12 deliberately forged sub-reviewer outcomes, sensitive
customer-text privacy and invalid byte/type payloads. Each forgery uses
an isolated monkeypatch and never touches grant or production state.

This is **not an external signed attestation**, a trusted approval,
merge/release authority, or enforcement inside the runtime executor.
It neither opens sockets nor reads customer data, modifies SQLite, emits
permits, scans targets or deploys. The existing active production
authorization owners retain their work. Tests still require exact-head
hosted Python 3.11 and 3.14 plus genuine producer integrations before
source-only merge; independent permanently queued VPS CI remains a
separate proof requirement for any release.
