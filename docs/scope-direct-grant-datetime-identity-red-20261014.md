# LightUp #738 — direct-grant datetime identity acceptance (offline)

## Purpose and ownership

Scope-authorization issue [#738](https://github.com/Zennay/Lightup/issues/738) requires
`AuthorizationGrant.is_current()` to **fail closed** for a subclass of
`datetime` stored directly in either grant validity field. Such a subclass
may override comparison operators and make future or expired grants look current.

The **production implementation belongs to source owner
[#100](https://github.com/Zennay/Lightup/pull/100)**. This isolated change
adds no production implementation and does not touch live dispatch, network,
state stores, CI workflows, runners or other workers' files.

## What the tests really establish

`tests/test_scope_direct_grant_datetime_identity_red_20261014.py` uses
only synthetic immutable grants, fixed UTC fixture times and the in-process
policy function. It tests:

- Ordinary builtin `datetime` before/after and inclusive endpoints.
- A timezone-naive evaluation instant raises before any authority is granted.
- A true built-in future grant is denied by the pure `ExecutionPolicy`.
- Five **expected failures**: polymorphic future lower bound, expired upper
  bound, both fields, and each kind flowing into the real in-process policy
  decision. These are deliberately **RED** security acceptance canaries.
- Input immutability and absence of network/target/database calls.

`expectedFailure` is not success of the safety requirement. The genuine
implementation must first require `type(value) is datetime` for **both**
stored bounds, validate timezone awareness, retain canonical inclusive
boundaries (issue #295), and deny malformed state *before* policy or handler
effects. After source owner repairs production, **remove**
`@unittest.expectedFailure` on each test and require normal PASS; an
unexpected success under that decorator is an **XPASS** and must not be
silently called release-safe.

## Offline command

```bash
python -m unittest discover -s tests -p 'test_scope_direct_grant_datetime_identity_red_20261014.py' -v
```

Passing offline tests with expected failures only prove that the fixture and
canaries run; they do **not** establish enforcement. Do not enable active
targets, issue consent, scan, merge unsafe source or deploy based on this
document. Real target activation remains disabled until trusted ownership,
scope, live revocation, independent source/security review and appropriate
release gates are satisfied.

## Isolation

Branch files are strictly newly added acceptance test + this document;
no existing source-owner path is modified. This test pack makes no claims
about active assets. It uses `fixture.example.test` as a synthetic string
only; no DNS or network I/O is present.
