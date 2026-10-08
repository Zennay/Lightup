# Scope policy decision purity: offline regression boundary

This isolated suite protects deterministic **decision purity** on the existing
`ScopePolicy` path. Repeated, unauthorized decisions must not cache admission,
mutate policy configuration, or require DNS. Frozen configuration is checked
without interacting with public targets.

Run with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_policy_purity.py' -v`.

These are local component regressions, not a signed-grant audit, production
executor test, permission to access a target, or evidence of hosted/permanent
VPS validation. Policy source and the active executor/revocation/approval PRs
are intentionally untouched. No network request or scan is performed.

Additional regression cases assert isolation between separate policies and between
matching and unknown hosts under a single policy. Those cases remain denied
without a grant and do not depend on previous decisions. Six offline test methods
are included; they deliberately do not exercise an authorized target.
