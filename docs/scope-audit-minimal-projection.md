# Scope audit index: privacy-minimal offline projection

This add-only, independent script is an **offline index format validator**, not a trusted audit ledger, approval proof, authorization decision, or runtime dispatch gate.

It accepts exactly six printable-ASCII string fields: `decision_id`, `tenant_id`, `run_id`, `grant_id`, `outcome` (`allow` or `deny`), and `reason_code`. Every field must be nonempty and at most 128 characters. Identifiers must begin with an ASCII letter/digit, then use only ASCII letters/digits/dot/underscore/colon/hyphen (no whitespace, URL slash, query strings or email-like text). Reason codes must begin with an ASCII letter and contain only ASCII letters/digits/underscores. These syntax constraints reduce accidental inclusion of URLs, credential-like assignments and other unbounded free text; they do not prove identifiers are non-sensitive. It rejects any extra fields rather than silently copying personal data, credentials, target URLs, unredacted evidence or payloads. Canonical JSON output uses sorted keys.

Example offline verification:

```sh
python -m unittest discover -s tests -p 'test_scope_audit_minimal_projection.py' -v
```

The caller is responsible for ensuring source identifiers are non-secret, for access control, tenant visibility, retention/deletion policy, immutable trusted audit persistence and trustworthy authorisation provenance. This isolated projection **must not** be wired into an active capability path or used to assert approval. It neither contacts targets nor performs any network I/O. Production executor ownership remains with PR #107; release receipt work remains with #982 and approval lineage with #992. No production code is modified in this branch.
