# ST5 freshness-admission consumer rejection input atomicity

Issue #765 isolates rejection-path caller-input atomicity at PR #141's composed
persisted freshness-admission consumer.

A caller-owned JSON-decoded admission must remain unchanged when strict parsing
rejects a digest mismatch and when immediate live validation rejects deliberate
candidate-evidence SHA drift. The regression preserves complete value, recursive
dict/list identities and key/list ordering across repeated rejection.

This branch is tests/docs-only and pinned to PR #141 exact head
`cfa22936bb2e3fc95665a0a032143d708a4568fe`. #764 owns fail-fast ordering;
#763 owns outer runtime-type exactness; #613 owns direct parser exactness. PR
#141 retains all source ownership.

Freshness remains non-authoritative and this proof adds no execution or
classification authority.
