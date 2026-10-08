# Offline scope-authorization decision matrix

This additive contract complements the existing `tests/test_scope.py` without changing production scope logic or active owner branches.

Run on the CI/self-hosted runner:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_decision_matrix_offline.py' -v
```

Boundary checks:
- An authorization attached to a different public host cannot authorize an unlisted host or suffix-confusable hostname.
- A canonicalized, explicitly listed public host still requires a present, currently valid grant. Expired and not-yet-active grants are denied.
- Disabling private-lab admission excludes private and link-local address examples.
- Loopback admission remains distinct from public scope; unknown public IPs remain denied.

These tests only instantiate in-memory policy/model values. They must not resolve DNS, open sockets, contact real targets, trigger tools, create grants, alter deployment, or broaden permissions.

This matrix is a focused regression proof, **not** a substitute for digital authorization, tenant-scoped grant verification, and the approval boundary at execution time. Test and documentation additions are intentionally disjoint from production owner PRs.
