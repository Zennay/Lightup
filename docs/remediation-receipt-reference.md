# Offline remediation receipt reference (non-authoritative)

This isolated evidence-remediation lane adds a **reference-only** consistency validator for a small in-memory receipt. It does not read a ledger, prove a finding, grant scope, run a retest, authorize a target, or generate a release verdict.

The receipt has exactly five fields: `finding_id`, `evidence_sha256`, `remediation_sha256`, `retest_status`, and `retest_evidence_sha256`. Evidence and remediation references use exact lowercase 64-character SHA-256 hex strings. Pending/not-tested states must have no retest evidence; passed/failed states require separate canonical retest evidence, different from the original evidence hash. The validator rejects missing/unknown fields, ambiguous types and noncanonical status text, and returns an isolated snapshot.

**Limitations:** Different hashes do not prove different underlying assessments, correct timestamps, tenant ownership, trusted issuance, valid authorization, human review, actual remediation or retest success. A caller must establish trusted evidence provenance, finding/tenant identity, current scope and the real retest procedure separately. This offline helper must never be wired to execution approval or used as production attestation without source-owner design and review.

Run isolated tests via `PYTHONPATH=src python -m unittest discover -s tests -p test_remediation_receipt_reference.py`. No network, target, DNS, subprocess, or VPS success is implied by this contribution.
