# Authenticated finding CSV command

Run this command from an interactive terminal with access to the existing
LightUp domain database:

```sh
python -m lightup.finding_export_cli --db lightup.db --email operator@example.test --client-id CLIENT_ID > findings.csv
```

The password is prompted with getpass; there is no password or role override
argument. Noninteractive input is refused to avoid fallback password echo.
An optional `--engagement-id ENGAGEMENT_ID` limits the export further.

Successful sign-in uses existing DomainStore credential verification and
lockout policy, then resolves the current persisted user role/tenant. Operators
must name one client; client members/admins can export only their own client.
Tenant/engagement/finding lineage is checked by the #959 service.

On denial stdout is empty, errors contain no findings or supplied passwords,
and the process returns 2. Missing database paths are refused rather than
bootstrapping a new empty database. Successful output is quoted guarded CSV
on stdout. Shell redirection creates a file under normal shell permissions;
choose a private destination and review free text before external sharing.

Authentication updates the existing login-failure counters. The domain schema
initialization follows normal DomainStore behavior; finding data is not
modified, sessions are not created, and no active assessment is run.

This entry point is separate from existing `lightup.cli` so parallel CLI policy
tests and webapp source ownership remain unchanged. No target/network/model
calls, execution authority or security verdict is added.
