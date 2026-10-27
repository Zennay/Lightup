# Ambiguous approval receipt selection — offline reference

The caller may never manufacture effective permission by selecting the first, last, freshest-looking, or most permissive receipt from an ambiguous collection. This synthetic reference accepts only exactly one structurally matching, positive, non-revoked receipt. Zero, duplicated, contradictory or malformed receipts must deny before any capability request.

## Production integration caveats

This is not a durable uniqueness constraint, trustworthy signature, grant validator, issuance record, revocation fence, time validity decision, or proof that production authorization is secure. Production owners must define authoritative receipt identity, deduplication and replacement semantics; if multiple identical records are legitimate persistence artifacts, resolve those transactionally into one issuer-verified current grant **before** invoking the authorization decision, never by first-match selection. A trusted store and exact tenant/asset/capability/request/revision binding remain mandatory. No code in this PR allows execution.

Regression command: `python -m unittest discover -s tests -p 'test_scope_unique_approval_reference_20261008.py' -v`.

Scope remains two newly added files, both tests/docs only, on existing PR #1005; no overlapping production ownership and no targets/network/scans/workers invoked.
