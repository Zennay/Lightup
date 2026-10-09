# Public-host authorization provenance: offline RED contract

Branch-local regression suite: `tests/test_scope_authorization_reference_integrity_20261009.py`.

## Current contract and expected behavior

A public host listed in `ScopePolicy.explicit_hosts` must not be
considered authorized merely because `Target.authorization` is non-null.
Before any external adapter or evidence writer is invoked, the production
authorization issuer should verify a **trusted, persisted** consent grant
and deny an owner or consent reference that is empty or whitespace-only.

| Fixture | Required decision | Current offline coverage |
| --- | --- | --- |
| No authorization | deny / authorization_missing | passing |
| Unlisted public hostname | deny / out_of_scope | passing |
| Empty owner | deny before I/O | RED / expectedFailure |
| Whitespace-only owner | deny before I/O | RED / expectedFailure |
| Empty consent reference | deny before I/O | RED / expectedFailure |
| Whitespace-only consent reference | deny before I/O | RED / expectedFailure |
| Expired grant | deny / authorization_expired | passing |

These RED cases deliberately document missing guards. An
`expectedFailure` result is **not** proof of safe authorization.
Converting them to passing assertions requires production-source owner
review, trusted grant provenance, live consent/revocation checks, and
integration tests proving zero handler calls and zero evidence writes.
A structurally nonblank string is likewise not proof that consent exists.

## Execution

```sh
PYTHONPATH=src python -m unittest -v tests.test_scope_authorization_reference_integrity_20261009
```

Offline only: `.invalid` fixture addresses, no DNS, sockets, scans,
real grants, or deployment. Retain draft/hold until full-source security
gate and exact-head hosted and canonical VPS CI are verified.
