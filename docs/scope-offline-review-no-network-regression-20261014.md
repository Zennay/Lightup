# Offline LightUp scope review — no-network acceptance proof

LightUp's standalone registry/authorization-metadata review tools are intended to inspect **local files or the local checkout only**, not to discover targets, make DNS queries or open network connections. This independent regression suite executes six *real CLI entrypoints* in isolated child Python interpreters after replacing common Python socket/DNS primitives with hooks that print `__LIGHTUP_NETWORK_ATTEMPT_BLOCKED__` and reject attempted calls.

Run:

```bash
python3 -m unittest discover -s tests -p test_scope_offline_cli_no_network.py -v
```

## Covered entrypoints

- `export_scope_capability_registry_offline.py`: actual current local registry export, not network discovery.
- `review_scope_capability_registry_offline.py`: two distinct manifest files, both equal and changed.
- `review_scope_registry_history_offline.py`: two to three distinct historical snapshot files, unchanged and reversible-drift HOLD.
- `render_scope_registry_history_offline.py`: readable Markdown for unchanged and changed/invalid input; always explicitly **Authority: NONE**.
- `review_scope_history_against_checkout_offline.py`: real checkout match and stale-manifest HOLD.
- `review_scope_incubation_registry_offline.py`: actual checkout posture and invalid argument rejection.

The harness also proves regular local file error paths do not accidentally trigger DNS/socket helpers. For every non-exporter JSON receipt, **authorization_verified, permit_issued, execution_enabled, merge_approved and release_approved remain false**. `REVIEW_ONLY` exits 3, `HOLD` exits 2; no CLI treats these metadata hints as exit-zero execution approvals. Tests use synthetic local temporary files or actual local registry metadata, **never a real target**.

## Important limitations

These are **Python-level regression probes**, not an OS sandbox, kernel firewall, external-process interception, binary-level egress control, signed checkout attestation, or an audited production network deny policy. They intercept common Python socket/DNS APIs inside the **tested process** and explicitly fail if an attempted call is observed even when application exception handling swallows it. A new native library or subprocess could bypass this test instrumentation and would require separate containment; actual LightUp target-capable runtimes still need strong production scope, egress controls, signed consent, review and permanent registered VPS evidence. They **do not** repair active source-owner authorization/executor/CI issues.

The test slice modifies only its own **new** test and documentation files, not any production or runtime worker path. Project remains **INCUBATE M3/M7 · PLAN/LAB ONLY**.
