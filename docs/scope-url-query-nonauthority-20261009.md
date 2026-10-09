# URL query parameters are not scope or consent authority

This is a narrow offline acceptance contract for the legacy `ScopePolicy.decide` host
boundary. Query strings such as `?host=`, `?target=`, `?redirect_uri=`,
`?scope=`, `?authorization=`, and `?approved=` must not change the host identity
parsed from the actual URL authority, or replace a current authorization object.

The positive control confirms that a real explicitly approved host and valid
`Target.authorization` remain accepted even when the query contains another host.
This does **not** approve a redirected request or any secondary URL embedded in
query parameters. A target-capable executor must separately authorize every
network destination, redirect and effective request origin before dispatch.

Tests use synthetic `.test` names only. No target interaction, DNS, socket,
scan, exploit, deployment, dispatch or permission widening occurs.

Offline command:
`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_url_query_nonauthority_20261009.py' -v`

Collision boundary: two newly named test/documentation files. No modification
of scope production code or active parallel workers' files. Promotion requires
exact-head permanent self-hosted CI in addition to any hosted preflight.
