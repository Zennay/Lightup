# IPv4-mapped IPv6 scope-gate boundary (M7/ST5)

This isolated regression pack pins **representation-sensitive network authorization** in the existing `ScopePolicy` API. A host encoded as `[::ffff:a.b.c.d]` must not inherit authority from an unrelated IPv4 CIDR, and opt-out from private lab must remain effective. A deliberately configured IPv6 mapped CIDR is separate authority and still requires an explicit current authorization for public targets.

Run offline with `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_mapped_ipv4_boundary_20261008.py' -v`.

No real targets are accessed. Documentation IP addresses are in-memory string fixtures only. This pack does not change production policy, grant semantics, executor paths, or network behavior, and it is **not evidence of complete authorization enforcement**. Keep promotion contingent on exact-head CI/self-hosted proof and source-owner review. Production ownership remains with the existing policy/executor PRs.
