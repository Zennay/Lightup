# Scope URL userinfo authority-confusion regression (offline, RED)

The legacy `ScopePolicy.normalize_host` uses `urlparse(...).hostname`.
A URL such as `http://outside.invalid@localhost/` resolves its parsed
hostname to `localhost`, despite a misleading authority string containing an
untrusted userinfo component. Under default private/loopback exceptions this
can become an apparently authorized target.

**Required fail-closed contract:** any URL containing a nonempty userinfo
component in its authority must be rejected before matching localhost,
private-lab IPs or explicitly approved hosts. Reject rather than silently
strip credentials. This is a *proposal to the owning implementation worker*;
the test is intentionally red against main and must not be interpreted as
an existing production guard.

Run offline: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_url_userinfo_authority_red_20261008.py' -v`.

No target contact, DNS, sockets, scans, credentials, execution grants or
production-source modifications. Coordinate with #107 and existing host-input
owners before integrating any production fix. Distinct new test/docs files only.
