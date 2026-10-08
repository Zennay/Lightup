# Remediation artifact manifest — offline reference contract

This additive, pure-Python reference accepts a **self-contained synthetic** remediation evidence artifact manifest. Every declared artifact must bind an exact identifier, byte length, media type and lowercase SHA-256 digest to an in-memory byte payload. It rejects duplicate identifiers, unlisted payloads, missing payloads, tampering, malformed identity, ambiguous types, and unsupported media types. It does not mutate inputs.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_evidence_manifest_reference.py' -v`.

**Not an authority boundary:** a matching hash proves consistency with caller-supplied bytes, *not* collection integrity, independent provenance, trusted timestamps, approval, tenant ownership, remedial effectiveness, or successful retesting. IDs are syntactic labels, not authenticated identities. The allowlisted media types are only reference defaults; no artifact rendering or untrusted content interpretation is performed. The one-MiB per artifact limit and 32-artifact limit are conservative reference bounds, not production storage controls.

Promotion requires source-owner integration with trusted persisted evidence, tenant-scoped access checks, independent reviewer approval, exact-head hosted and permanent VPS tests, and explicit human release decisions. This module cannot authorize an assessment, network access, active scanning, or real-target execution. Existing evidence ledger, remediation, retest and release owners retain their code paths.
