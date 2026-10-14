# Scope authorization: evidence-downgrade reference (offline)

This narrow companion to `tests/test_scope_evidence_downgrade_reference.py` specifies a **conditional, in-memory reference predicate** only. It is not a production authorization grant or a trustworthy issuer registry.

## Invariant

An asserted scope identity cannot acquire execution authority from a lower-trust provenance source. A report, attached file, scanner output, lab fixture, or cache is not issuer-owned authorization evidence. Changes to tenant, request, revision or issuer always require fresh, independently validated authorization; they must not be silently accepted as equivalent.

The reference denies: unrecognized evidence origins; false or truthy-but-not-boolean verification; revoked or truthy-but-not-boolean revocation; changed bound identities or revisions; malformed control/Unicode identity; duck-typed, dict and dataclass-subclass envelopes. It makes no network or capability calls.

## Production integration is not provided

The production scope/activation owner must authenticate issuer provenance, retrieve current grants, check revocation and validity against current authoritative state, revalidate at admission and dispatch, and correlate permission with the exact tenant/request/revision/capability/target. A literal trusted source string **does not establish authenticity**. Conditional positive test cases must never be interpreted as permission to interact with real targets.

## Collision / validation boundaries

Only this document and its corresponding new stdlib offline test module are in scope. The active executor production owner (#107) and all existing authorization/activation/evidence files remain untouched. Run `python -m unittest tests.test_scope_evidence_downgrade_reference -v` under Python 3.11 and 3.14, then require exact-head canonical self-hosted CI before promotion. Keep PR draft until production owner review. No targets, DNS, sockets, scanning, deployment or permission activation.
