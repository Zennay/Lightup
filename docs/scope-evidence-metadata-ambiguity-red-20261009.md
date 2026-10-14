# Evidence metadata admission: duplicate and reserved fields (offline RED)

Handler-controlled `ToolOutput.metadata` is an ordered tuple of key/value pairs. Today the executor projects this into a dictionary before writing evidence. Duplicate pairs therefore collapse, and reserved provenance keys (`asset`, `client_id`, `engagement_id`, `mode`, `is_lab`) are overwritten by context rather than being explicitly rejected.

## Acceptance for evidence/executor owners
- Validate exact tuple of exact two-string pairs before constructing a dictionary.
- Reject repeated keys and reserved provenance keys before handler output is persisted.
- Reject malformed pair entries, non-string keys/values and polymorphic containers.
- Preserve the existing successful canonical unique-metadata path, with trusted provenance from context only.
- Denied outputs must not create evidence rows.
- Recheck on exact final SHA with hosted + canonical VPS runner and independent review.

## Status
The accompanying file supplies pure offline reference tests and two intentionally `expectedFailure` production-projection canaries. The canaries are *not* evidence that production enforces the boundary. No source owner files, network, DNS, scanning, approval issuance or real targets modified. DRAFT/HOLD.
