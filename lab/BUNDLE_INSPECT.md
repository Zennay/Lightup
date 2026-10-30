# Read-only lab bundle inspection

Inspect an existing content-addressed replay bundle without rerunning the fixture or changing its files:

```bash
PYTHONPATH=src python -m lightup.lab_bundle_inspect \
  --bundle-dir ~/.local/state/lightup/lab-fixture-replays/<receipt-sha256>
```

The inspector admits only an existing owner-private bundle directory and owner-private, regular, single-link receipt, checksum, and SQLite files. It rejects symlinked path components, group/other-writable ancestors (except root-owned sticky `/tmp`, `/var/tmp`, and `/dev/shm`), non-canonical or duplicate-key JSON, a mismatched content-addressed directory/checksum, corrupt SQLite databases, altered physical SQLite table sets, views, triggers and virtual tables, unreferenced lifecycle/evidence rows, and broken StateStore-to-DomainStore evidence/retest links, exact loopback finding assets, and source-defined severity/impact/remediation copy. Open file descriptors remain pinned through verification, and the bundle directory fingerprint plus exact entry set are rechecked at the end; an entry mutation during inspection (including an add/remove cycle) fails closed. Existing SQLite sidecars are admitted only when private and bounded; any non-empty WAL is rejected as uncheckpointed data. SQLite is opened read-only and immutable with SQLite trusted schemas disabled; the command creates no files, runs no fixture server, and makes no network calls.

Output contains only receipt/catalog hashes and aggregate profile, evidence, event, and retest counts; private paths and evidence payloads are omitted. `integrity: PASS` means the stored synthetic bundle is internally consistent. `lab_outcome` separately preserves the recorded fixture result, so a valid bundle may report `lab_outcome: FAIL`. Neither value proves a real-world fix, trusted origin, authorization, or permission to contact a target.

Exit status `0` means bundle integrity was verified; `2` means admission or verification failed.
