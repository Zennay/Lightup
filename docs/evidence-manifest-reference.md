# Remediation artifact manifest — offline reference contract

This additive, pure-Python reference accepts a **self-contained synthetic** remediation evidence artifact manifest. Every declared artifact must bind an exact identifier, byte length, media type and lowercase SHA-256 digest to an in-memory byte payload. It rejects duplicate identifiers, unlisted payloads, missing payloads, tampering, malformed identity, ambiguous types, and unsupported media types. It does not mutate inputs.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_evidence_manifest_reference.py' -v`.

**Not an authority boundary:** a matching hash proves consistency with caller-supplied bytes, *not* collection integrity, independent provenance, trusted timestamps, approval, tenant ownership, remedial effectiveness, or successful retesting. IDs are syntactic labels, not authenticated identities. The allowlisted media types are only reference defaults; no artifact rendering or untrusted content interpretation is performed. The one-MiB per artifact limit and 32-artifact limit are conservative reference bounds, not production storage controls.

Promotion requires source-owner integration with trusted persisted evidence, tenant-scoped access checks, independent reviewer approval, exact-head hosted and permanent VPS tests, and explicit human release decisions. This module cannot authorize an assessment, network access, active scanning, or real-target execution. Existing evidence ledger, remediation, retest and release owners retain their code paths.

## Explicit tenant substitution negative assurance
A manifest whose tenant label is replaced by another syntactically valid tenant still passes this **byte-integrity-only** check. This is intentional and regression-tested: the verifier does **not** possess a trusted authenticated tenant context and therefore must never be used as a tenant authorization guard. A production consumer must bind the authenticated tenant, finding and remediation record to trusted persisted records before interpreting evidence.

## Explicit expected-context binding reference

Call `verify_artifact_manifest_for_context(manifest, blobs, tenant_id=..., finding_id=..., remediation_id=...)` when trusted expected identifiers are available. It rejects mismatch of any of the three identity dimensions before evaluating integrity and keeps exact-type/lexical checks for the expected IDs. Six synthetic tests exercise matching context, tenant/finding/remediation substitution, invalid expected identity type and tampered payloads.

**Security limitation:** parameters passed to this helper are caller claims. The helper does not authenticate sessions, resolve tenant ownership, verify issuer signatures, or fetch/revalidate current authoritative records. Never derive expected identifiers from the untrusted manifest itself. Production adoption must obtain expected IDs from a separately authenticated tenant-scoped source and revalidate state according to the owner's policy.
