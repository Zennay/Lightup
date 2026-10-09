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
| Zero-width owner or reference | deny before I/O | RED / expectedFailure (2) |
| Embedded newline/carriage return in owner or reference | deny before I/O | RED / expectedFailure (2) |
| Expired grant | deny / authorization_expired | passing |

There are now 11 offline methods: 3 passing controls and 8 RED requirements.\n\nThese RED cases deliberately document missing guards. An
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

## Isolated shape reference (not production authorization)

`tests/test_scope_provenance_shape_offline_reference_20261009.py`
adds fifteen **normal** offline unit contracts for a fail-closed,
strictly typed provenance-shape reference. It rejects empty/whitespace,
Unicode format and control characters, surrogate code points, Unicode line/paragraph separators and embedded invisible markers, hostile str subclasses, wrong-typed
fields, and forged containers without invoking hostile `__str__` or
`__bool__`. The positive case proves **syntax only**. A real grant must
still be verified by the trusted source-owner path immediately before I/O.
The mock no-call assertion concerns the *reference helper only*, not the
production handler integration.

```sh
PYTHONPATH=src python -m unittest -v tests.test_scope_provenance_shape_offline_reference_20261009
```

## Regression-fixture integrity

Dedicated assertions verify that Unicode test fixtures are genuine single-codepoint characters in the intended Unicode category, rather than misleading literal backslash-u sequences. A separate invariant checks that syntax validation does not mutate the frozen Authorization object. These checks are offline and do not constitute authorization to contact a target.

## Forged object boundaries

Two additional offline tests reject a subclass of the Authorization model and a hostile mapping object without introspecting its keys or invoking user-provided methods. These explicitly test the strict-type boundary of the reference helper, not the production grant issuer.
