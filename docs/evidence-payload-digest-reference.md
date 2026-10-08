# Evidence remediation — content digest reference (offline)

This draft isolates a **reference-only** content-integrity check for evidence
artifacts. It is deliberately not wired into LightUp production readers,
writers, exports, authorization policy, or remediation status transitions.

## Proposed invariants

- Verify the exact stored **bytes** against lowercase 64-character SHA-256,
  without text decoding, whitespace normalization, filename inference or
  representation conversion.
- Reject malformed digests, payloads that are not exact `bytes`, and payloads
  exceeding a configured positive exact-integer byte budget. The illustrative
  1 MiB limit here is **not** a production policy recommendation.
- Content integrity is necessary but insufficient: even a matching digest
  does **not** prove source authenticity, tenant ownership, consent, freshness,
  approval, event order, remediation completion or retest success.
- Production integration must bind the digest to an issuer-trusted,
  tenant-scoped evidence record and enforce checks before displaying or using
  artifacts as remediation/retest proof. On mismatch, fail closed without
  inventing success or silently repairing the record.

## Boundaries / handoff

This reference has no I/O, external dependencies, network calls, target
interaction, runtime grant changes or production source edits. Related
attachment-name, export-gate, plan-digest and transition-seal branches retain
their own ownership. The existing evidence/remediation source owner should
select the integration boundary and actual byte limits, and validate
exact-head hosted and permanent VPS CI before promotion.

Offline exercise: `python -m unittest discover -s tests -p 'test_evidence_payload_digest_reference.py'`.
