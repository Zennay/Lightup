# Evidence identifier canonicalization — offline reference only

This proposal defines an **isolated test reference**, not a production parser or
an authorization decision. Its illustrative content-addressed identifier grammar
is `ev-` followed by exactly 64 lowercase ASCII hexadecimal characters. It is
**not** a claim that existing LightUp evidence IDs already use this grammar.

## Risk boundary
Case folding, Unicode lookalikes, implicit string conversion, invisible controls,
truncation and overlong values can cause two nonidentical evidence references to
be treated as interchangeable. A verifier must never repair a hostile reference
into a trusted one by coercion or normalization.

## Proposed owner acceptance gate
1. Determine the actual issued evidence-ID format and establish a documented,
   versioned issuer-owned canonical grammar; do not deploy this reference grammar
   without compatibility review.
2. Require exact built-in string types; reject aliases, controls, Unicode
   confusables, case variations, truncation, and overlong strings before lookup.
3. Bind IDs to tenant, run, provenance, hash and immutable stored evidence. A
   syntactically valid reference alone is **never** proof that an artifact exists,
   belongs to the requester or was independently verified.
4. Revalidate at read, export, remediation and retest admission boundaries, and
   preserve audit-appropriate denial evidence without exposing sensitive data.
5. Verify integration against the exact candidate commit in hosted CI **and**
   the permanent self-hosted VPS lane before declaring a production gate green.

## Scope / non-overlap
This change adds only this document and a stdlib offline reference module.
Existing evidence-content-hash, reference-order, tombstone, export, transition,
source ownership, and scope-authorization PRs remain untouched. No DNS, sockets,
target probing, real evidence ingestion, permissions, deployment or active
capability execution. Positive reference tests prove lexical shape only.
