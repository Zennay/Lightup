# Optional evidence identifier admission — issue #1075

A new pure helper accepts only exact built-in lowercase hyphenated RFC 4122 UUID version 4 text. It rejects aliases without normalizing them. This is lexical admission only, not a tenant authorization, ownership, source-provenance or evidence-integrity check. Existing StateStore.get_evidence is unchanged and can still accept noncanonical aliases until its source owner integrates an appropriate pre-lookup check.

The parent PR #1074 contains the historical issuer/reader compatibility characterization. Do not merge this child without source-owner review, full exact-head CI, permanent VPS evidence, and a safe authenticated tenant/engagement boundary. No targets or network checks were performed.
