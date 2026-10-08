# Remediation evidence attachment labels — offline reference

This independent M7/ST5 contract proposes a **display-name-only** guard at the boundary where remediation and retest evidence metadata is presented to a human reviewer or exported. It does not resolve, read, write, upload, or open a filesystem path.

## Proposed rejection conditions

Reject untrusted non-string and overlong labels; path separators or drive markers; percent-encoded path aliases; control and bidirectional format characters; non-NFC Unicode and nonportable characters; Windows device names; leading dot/hyphen/space and trailing dot/space. Keep the raw evidence identifier separate from the display label. Do not silently sanitize two different names into the same authoritative identity.

This deliberately restrictive ASCII reference is not a final product naming policy. Production owners must decide how legitimate international filenames are displayed without treating a label as a storage key or a trusted URI.

## Ownership and gates

- Isolated tests/docs only; no production source, existing evidence manifest/receipt/export code, queue, authorization, or other worker branch changed.
- The positive cases show only a reference parser result, **not** evidence provenance, tenant authorization, integrity, or permission to perform remediation.
- No target contact, DNS, network, scanner, active remediation, file I/O or deployment.
- Run `python -m unittest discover -s tests -p 'test_evidence_attachment_label_reference.py' -v`.
- Draft pending source-owner integration, exact-head hosted CI, permanent VPS proof and independent review. Never count a reference test as production safety evidence.
