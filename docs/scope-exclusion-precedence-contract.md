# Scope exclusion precedence — offline regression contract

This add-only contract protects the pure `ScopeDefinition.allows_asset()` boundary.

- A normalized exact-match allowlist entry is required.
- A matching exclusion always overrides an allowlist entry, including differences in ASCII case or surrounding whitespace.
- No implicit parent, subdomain, or lookalike hostname authorization is inferred.
- Excluding one asset does not exclude an unrelated allowed sibling.
- Empty allowlists deny every candidate, including empty identity; repeated allow entries cannot override exclusions.
- Exact allowlist matching must not implicitly admit lookalike suffixes/prefixes or a trailing-dot hostname variant.
- Repeated evaluations are deterministic and do not rewrite the declared allow/exclude tuples.

The contract intentionally documents the current exact-string matching semantics; it does **not** assert hostname canonicalization, wildcard expansion, IP-range containment, IDNA treatment, or DNS resolution. Those concerns require separate security review and authorization gates.

Run locally: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_exclusion_precedence_contract.py' -v`.

## Ownership / safety

Only this document and `tests/test_scope_exclusion_precedence_contract.py` are added. This does not modify `src/lightup/engagements.py` or any scope, policy, grant, activation, executor, registry, UI, or target-worker implementation. Pure in-memory unit tests; no network I/O, DNS, target interaction, scanning, exploitation, capability execution, or authorization widening.
