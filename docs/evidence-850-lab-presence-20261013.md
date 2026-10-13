# #850 — lab → durable finding evidence PRESENCE boundary

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/NO DEPLOY**

## Scope and ownership

Pinned immutable base: original lab-provenance source owner [PR #184](https://github.com/Zennay/Lightup/pull/184) exact `bc7242d5171856f69f2ec68d7b3cf06d64bbb938`. This child adds only `tests/test_lab_evidence_presence_850.py` and this document; does **not** modify `src/lightup/labsync.py` (owner #184 / source successor #853), DomainStore, scope authorization, target-capable workers, retests, deployment or sibling PRs.

## Why this matters

The existing bridge `persist_lab_findings()` can call `DomainStore.record_finding()` even when a lab finding has neither a local `evidence_ids` list nor a top-level legacy `evidence_id`. The durable finding then has `[]` evidence while still carrying remediation/retest metadata, undermining evidence-first reports.

## Offline acceptance

All tests create a disposable **real on-disk SQLite** domain and internal lab engagement, without making any baseline observations or network requests:

- Ordinary PASS: nonempty local references take precedence over top-level legacy evidence and persist with the same values.
- Ordinary PASS: omitted local refs inherit valid legacy `evidence_id` and persist.
- Ordinary PASS: explicit empty local list does not suppress legitimate legacy fallback.
- **Two deliberately unresolved expected RED**: no local nor legacy ref; empty local ref list with no fallback. Both must fail with an evidence-specific `ValueError` **before** `DomainStore.record_finding()` is called and with zero durable SQLite row changes.

These tests enforce **presence**, not canonical reference contents or polymorphic shape (owned separately by #848 / #853). Test and document must not be mistaken for an installed source fix.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_lab_evidence_presence_850.py' -v
```

Pre-fix expected outcome is 5 executed cases, **3 ordinary PASS / 2 intentionally expected RED**, not a security approval. Source owner should install missing-presence fail-before-write admission, remove the two decorators, and prove five ordinary green on hosted Python 3.11/3.14 and on a separately registered permanent VPS runner. Independently review privacy/security, current-main integration, source ownership and explicit human release before any merge or deployment.

No customer data, targets, DNS, scans, grants, external AI, remediation execution, retest, verdict or attack-path mutations.
