# ScopePolicy CIDR versus durable-grant authorization

This offline contract tests the `ScopePolicy` decision as implemented. CIDR membership
and currentness are independent gates, but **the policy does not bind the
`Authorization.owner` or `reference` to a specific host, tenant or grant record**.
The executable characterization in `test_scope_network_boundary_offline.py`
intentionally records that limitation (an unrelated current Authorization can pass
the network-only policy); it must not be mistaken for acceptable end-to-end
authorization.

**Required execution-layer contract (production owner follow-up):**
Before any real-target work, independently resolve an approved, revocable digital
grant tied to the exact tenant/engagement, target asset and permitted capabilities.
Deny on missing, stale, mismatched or expired grant; preserve an audit record.
Do not rely on an attached `Target.authorization` value alone.

The network tests also prove an unrelated public IP stays out of scope despite a
current grant; missing, expired and future grants are rejected for an explicitly
listed public CIDR. Neither the tests nor this document contacts targets, opens
sockets, grants permission, changes the runner, or modifies production logic.

Focused CI command:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_*offline.py' -v
```

This is a nonproduction regression/characterization addition for PR #969;
execution authorization remains owned by the existing domain/executor workers.
