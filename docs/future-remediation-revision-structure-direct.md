# Revised-remediation direct-construction structural integrity

The ST5 revised-remediation loop remains planning-only. In addition to the
existing direct authority guards, each in-memory artifact now enforces the
same structural and canonical-digest rules as its strict persisted handoff.

Covered artifacts:

1. **Revision request** — exact schema and SHA-256 lineage, fixed
   `revision_required` decision, non-empty unique review checks in canonical
   rubric order, and canonical request digest.
2. **Revised proposal** — exact lineage/provenance, canonical trimmed bounded
   content, content SHA-256, and canonical revision-proposal digest.
3. **Revised review request** — exact lineage/provenance, the fixed review
   rubric, and canonical review-request digest.
4. **Final revised review** — exact lineage/reviewer provenance, fixed ordered
   typed checks with bounded results, decision/check coherence, canonical
   trimmed bounded summary, and canonical review digest.

Duplicate-key-safe JSON decoding and complete live upstream-lineage revalidation
remain responsibilities of the strict persisted handoff functions. This slice
only ensures direct in-memory construction cannot manufacture an artifact that
would be structurally rejected after persistence.

No constructor grants code/config, tool, target, execution, retest, deployment,
future-state resolution, security-verdict, or attack-path authority.
