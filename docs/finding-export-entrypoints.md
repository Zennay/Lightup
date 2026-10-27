# CSV downloads in normal web entry points

The package factory `lightup.webapp.create_app`, development launcher
`python -m lightup.webapp` and configured Gunicorn production factory now
construct the secured CSV extension added in #962. The existing
`lightup.webapp.app.LightUpWebApp` base class remains available unchanged.

Signed-in client portal users see Download CSV beside Findings. Operators
can view a selected client portal and download only that client's summary.
The extension uses normal session and portal access checks followed by the
independent tenant/finding lineage service.

The development launcher still binds only to loopback. Production still
requires an explicit HTTPS public origin and absolute database path, trusted
loopback proxy, HTTPS forwarding and correct Host/Origin checks. Switching
the factory does not deploy or start the application, authorize active tests,
add network workers or evaluate security outcomes.

The standalone terminal exporter remains separately available via
`python -m lightup.finding_export_cli` after #960.

Five entrypoint regressions prove default package wiring, production trust
requirements, dev wiring and rejection of public development binds. Full
web/session/security tests must pass on both Python versions and permanent
VPS before promotion.
